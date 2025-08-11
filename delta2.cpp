#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <unistd.h>
#include <boost/program_options.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

namespace po = boost::program_options;

//
constexpr size_t FILE_MAX_QUEUE_SIZE = 10000000;
constexpr size_t FILE_WRITER_BATCH_SIZE = 100000;
constexpr size_t FILE_WORKER_BUFFER_SIZE = 100000;

// 
constexpr size_t PIPE_MAX_QUEUE_SIZE = 4000000;
constexpr size_t PIPE_WRITER_BATCH_SIZE = 400000;
constexpr size_t PIPE_WORKER_BUFFER_SIZE = 400000;

struct Config {
    BIGNUM* q1;
    BIGNUM* start_r;
    BIGNUM* end_r;
    BIGNUM* neg_delta;
    int iterations;
    int q1_increments;
    int threads;
    std::string output;
    bool use_stdout;
    EC_GROUP* group;
    BIGNUM* order;
    bool is_pipe;
};

std::mutex queue_mutex;
std::condition_variable queue_cv;
std::queue<std::string> key_queue;
std::atomic<bool> writer_done(false);
std::atomic<int> next_increment(0);

void writer_thread(const Config& config) {
    const size_t batch_size = config.is_pipe ? PIPE_WRITER_BATCH_SIZE : FILE_WRITER_BATCH_SIZE;
    std::vector<std::string> batch;
    batch.reserve(batch_size);

    if (!config.use_stdout) {
        //
        std::ofstream outfile(config.output, std::ios::app | std::ios::binary);
        outfile.sync_with_stdio(false);

        while (!writer_done || !key_queue.empty()) {
            batch.clear();

            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                if (key_queue.empty() && !writer_done) {
                    queue_cv.wait(lock);
                }

                while (!key_queue.empty() && batch.size() < batch_size) {
                    batch.push_back(std::move(key_queue.front()));
                    key_queue.pop();
                }
            }

            if (!batch.empty()) {
                std::string buffer;
                buffer.reserve(batch.size() * 65);
                for (const auto& key : batch) {
                    buffer.append(key).append("\n");
                }
                outfile << buffer;
            }
        }
        outfile.close();
    }
    else {
        // 
        setvbuf(stdout, nullptr, _IONBF, 0);
        std::ios::sync_with_stdio(false);

        while (!writer_done || !key_queue.empty()) {
            batch.clear();

            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                queue_cv.wait(lock, [&] {
                    return writer_done || !key_queue.empty();
                    });

                while (!key_queue.empty() && batch.size() < batch_size) {
                    batch.push_back(std::move(key_queue.front()));
                    key_queue.pop();
                }
            }

            if (!batch.empty()) {
                for (const auto& key : batch) {
                    std::cout << key << '\n';
                }
                std::cout.flush();
            }

            queue_cv.notify_all();
        }
    }
}

void worker_task(const Config& config, BIGNUM* base_q1) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* r_target = BN_new();
    BIGNUM* q_r = BN_new();
    BIGNUM* tmp = BN_new();
    BIGNUM* range = BN_new();
    BIGNUM* current_q1 = BN_new();
    BIGNUM* increment = BN_new();
    BIGNUM* one = BN_new();

    BN_one(one);
    BN_sub(range, config.end_r, config.start_r);

    const size_t buffer_size = config.is_pipe ? PIPE_WORKER_BUFFER_SIZE : FILE_WORKER_BUFFER_SIZE;
    const size_t max_queue_size = config.is_pipe ? PIPE_MAX_QUEUE_SIZE : FILE_MAX_QUEUE_SIZE;
    std::vector<std::string> key_buffer;
    key_buffer.reserve(buffer_size);

    while (true) {
        int inc = next_increment.fetch_add(1, std::memory_order_relaxed);
        if (inc >= config.q1_increments) break;

        BN_set_word(increment, inc);
        BN_add(current_q1, base_q1, increment);

        for (int i = 0; i < config.iterations; ++i) {
            BN_rand_range(r_target, range);
            BN_add(r_target, r_target, config.start_r);

            if (BN_is_one(r_target)) {
                BN_copy(q_r, current_q1);
            }
            else {
                BN_sub(tmp, r_target, one);
                BN_mul(tmp, tmp, config.neg_delta, ctx);
                BN_add(tmp, tmp, current_q1);
                BN_mod(q_r, tmp, config.order, ctx);
            }

            char* hex_str = BN_bn2hex(q_r);
            key_buffer.emplace_back(hex_str);
            OPENSSL_free(hex_str);

            if (key_buffer.size() >= buffer_size ||
                (inc == config.q1_increments - 1 && i == config.iterations - 1 && !key_buffer.empty())) {

                std::unique_lock<std::mutex> lock(queue_mutex);

                if (config.is_pipe) {
                    queue_cv.wait(lock, [&] {
                        return key_queue.size() < max_queue_size;
                        });
                }
                else {
                    if (key_queue.size() > max_queue_size * 0.9) {
                        queue_cv.wait(lock, [&] {
                            return key_queue.size() < max_queue_size * 0.7;
                            });
                    }
                }

                for (auto& key : key_buffer) {
                    key_queue.push(std::move(key));
                }
                key_buffer.clear();

                lock.unlock();
                queue_cv.notify_one();
            }
        }
    }

    BN_free(r_target);
    BN_free(q_r);
    BN_free(tmp);
    BN_free(range);
    BN_free(current_q1);
    BN_free(increment);
    BN_free(one);
    BN_CTX_free(ctx);
}

int main(int argc, char* argv[]) {
    po::options_description desc("Options");
    desc.add_options()
        ("help,h", "Show help")
        ("q1", po::value<std::string>()->required(), "Initial q1 value (hex)")
        ("s", po::value<std::string>()->required(), "Start R value (decimal)")
        ("e", po::value<std::string>()->required(), "End R value (decimal)")
        ("delta", po::value<std::string>()->default_value("2820A9F42E5ECE72F5F16F09D5CB5569904A09DE43ECD2A4ECF0130FFBF5D0C8"),
            "Negative delta value (hex)")
        ("i", po::value<int>()->required(), "Iterations per q1 increment")
        ("qi", po::value<int>()->required(), "Number of q1 increments")
        ("t", po::value<int>()->required(), "Number of threads")
        ("o", po::value<std::string>(), "Output file (optional)");

    po::variables_map vm;
    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    }
    catch (const po::error& e) {
        std::cerr << "Error: " << e.what() << "\n";
        std::cout << desc << "\n";
        return 1;
    }

    BN_CTX* ctx = BN_CTX_new();
    Config config;

    config.group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    config.order = BN_new();
    EC_GROUP_get_order(config.group, config.order, ctx);

    config.q1 = BN_new();
    BN_hex2bn(&config.q1, vm["q1"].as<std::string>().c_str());

    config.start_r = BN_new();
    BN_dec2bn(&config.start_r, vm["s"].as<std::string>().c_str());

    config.end_r = BN_new();
    BN_dec2bn(&config.end_r, vm["e"].as<std::string>().c_str());

    config.neg_delta = BN_new();
    BN_hex2bn(&config.neg_delta, vm["delta"].as<std::string>().c_str());

    config.iterations = vm["i"].as<int>();
    config.q1_increments = vm["qi"].as<int>();
    config.threads = vm["t"].as<int>();
    config.use_stdout = !vm.count("o");

    // 
    if (config.use_stdout) {
        config.is_pipe = (isatty(fileno(stdout)) == 0);
    }
    else {
        config.is_pipe = false;
    }

    if (!config.use_stdout) {
        config.output = vm["o"].as<std::string>();
        std::ofstream ofs(config.output, std::ios::trunc);
        ofs.close();
    }

    next_increment = 0;
    writer_done = false;

    std::thread writer(writer_thread, std::cref(config));
    std::vector<std::thread> workers;

    for (int i = 0; i < config.threads; ++i) {
        workers.emplace_back(worker_task, std::cref(config), config.q1);
    }

    for (auto& t : workers) {
        t.join();
    }

    writer_done = true;
    queue_cv.notify_all();
    writer.join();

    BN_free(config.q1);
    BN_free(config.start_r);
    BN_free(config.end_r);
    BN_free(config.neg_delta);
    BN_free(config.order);
    EC_GROUP_free(config.group);
    BN_CTX_free(ctx);

    return 0;

}
