#include <windows.h>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <string>
#include <iostream>
#include <chrono>
#include <queue>
#include <condition_variable>
#include <fstream>
#include <memory>
#include <algorithm>

extern "C" {
#include "openssl/ec.h"
#include "openssl/bn.h"
#include "openssl/obj_mac.h"
#include "openssl/rand.h"
}

constexpr size_t BATCH_SIZE = 1000;
constexpr size_t WRITE_BUFFER_SIZE = 4096;
constexpr size_t MAX_QUEUE_SIZE = 10;

struct ThreadContext {
    BN_CTX* ctx;
    EC_POINT* R_times_G;
    EC_POINT* numerator;
    EC_POINT* P_diff;
    EC_POINT* P_target;
    BIGNUM* current_r;
    BIGNUM* one;
    BIGNUM* range_size;
    BIGNUM* start_r;

    ThreadContext(const EC_GROUP* group, const BIGNUM* start_r, const BIGNUM* range_size) {
        ctx = BN_CTX_new();
        R_times_G = EC_POINT_new(group);
        numerator = EC_POINT_new(group);
        P_diff = EC_POINT_new(group);
        P_target = EC_POINT_new(group);
        current_r = BN_new();
        one = BN_new();
        this->range_size = BN_dup(range_size);
        this->start_r = BN_dup(start_r);
        BN_one(one);
    }

    ~ThreadContext() {
        BN_free(current_r);
        BN_free(one);
        BN_free(range_size);
        BN_free(start_r);
        EC_POINT_free(R_times_G);
        EC_POINT_free(numerator);
        EC_POINT_free(P_diff);
        EC_POINT_free(P_target);
        BN_CTX_free(ctx);
    }

    void generate_random_r_batch(BIGNUM** out, int count) {
        for (int i = 0; i < count; ++i) {
            BN_rand_range(out[i], range_size);
            BN_add(out[i], start_r, out[i]);
        }
    }
};

class InstantFileWriter {
private:
    std::ofstream output_file;
    std::ofstream pubkeys_file;
    std::mutex file_mutex;
    std::atomic<uint64_t> total_written{ 0 };
    bool use_stdout;
    std::atomic<uint64_t> batches_processed{ 0 };

    struct WriteBatch {
        std::vector<std::string> full_data;
        std::vector<std::string> pubkeys;
    };

    std::queue<WriteBatch> write_queue;
    std::condition_variable queue_cv;
    std::condition_variable queue_not_full_cv;
    std::atomic<bool> writer_active{ true };
    std::thread writer_thread;

    void writer_function() {
        while (writer_active || !write_queue.empty()) {
            WriteBatch batch;

            {
                std::unique_lock<std::mutex> lock(file_mutex);
                queue_cv.wait(lock, [&] { return !write_queue.empty() || !writer_active; });

                if (!write_queue.empty()) {
                    batch = std::move(write_queue.front());
                    write_queue.pop();
                    queue_not_full_cv.notify_one();
                }
            }

            if (!batch.full_data.empty()) {
                if (!use_stdout) {
                    for (const auto& line : batch.full_data) {
                        output_file << line;
                    }

                    for (const auto& key : batch.pubkeys) {
                        pubkeys_file << key << "\n";
                    }
                }
                else {
                    for (const auto& line : batch.full_data) {
                        std::cout << line;
                    }
                }

                batches_processed++;
                if (batches_processed % 100 == 0) {
                    std::cerr << "Processed " << batches_processed << " batches\n";
                }
            }
        }
    }

public:
    InstantFileWriter(const std::string& filename, const std::string& pubkeys_filename)
        : use_stdout(filename.empty()) {

        if (!use_stdout) {
            output_file.open(filename, std::ios::out | std::ios::binary);
            if (!output_file.is_open()) {
                throw std::runtime_error("Failed to create output file: " + filename);
            }

            pubkeys_file.open(pubkeys_filename, std::ios::out | std::ios::binary);
            if (!pubkeys_file.is_open()) {
                output_file.close();
                throw std::runtime_error("Failed to create pubkeys file: " + pubkeys_filename);
            }

            output_file << "R | PubKey\n";
        }
        else {
            std::ios::sync_with_stdio(false);
        }

        writer_thread = std::thread(&InstantFileWriter::writer_function, this);
    }

    void write_batch(std::vector<std::string>&& full_data, std::vector<std::string>&& pubkeys) {
        if (full_data.empty()) return;

        {
            std::unique_lock<std::mutex> lock(file_mutex);
            queue_not_full_cv.wait(lock, [&] { return write_queue.size() < MAX_QUEUE_SIZE; });

            write_queue.push({ std::move(full_data), std::move(pubkeys) });
        }
        queue_cv.notify_one();
    }

    ~InstantFileWriter() {
        writer_active = false;
        queue_cv.notify_one();

        if (writer_thread.joinable()) {
            writer_thread.join();
        }

        if (!use_stdout) {
            output_file.close();
            pubkeys_file.close();

            if (output_file.fail() || pubkeys_file.fail()) {
                std::cerr << "Failed to flush files\n";
            }
            else {
                std::cerr << "Files successfully closed\n";
            }
        }
        else {
            std::cout.flush();
        }
    }
};

void process_range(
    const EC_GROUP* group,
    const EC_POINT* P1,
    const BIGNUM* D,
    const BIGNUM* inv_D,
    const BIGNUM* start_r,
    const BIGNUM* range_size,
    InstantFileWriter& writer,
    std::atomic<bool>& stop_flag,
    uint64_t max_iterations
) {
    ThreadContext ctx(group, start_r, range_size);
    const EC_POINT* G = EC_GROUP_get0_generator(group);

    std::vector<std::string> full_data_batch;
    std::vector<std::string> pubkeys_batch;
    full_data_batch.reserve(BATCH_SIZE);
    pubkeys_batch.reserve(BATCH_SIZE);

    // Используем raw pointers для совместимости с OpenSSL API
    std::vector<BIGNUM*> r_batch(BATCH_SIZE);
    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        r_batch[i] = BN_new();
    }

    uint64_t iterations = 0;
    while (iterations < max_iterations && !stop_flag) {
        int current_batch_size = std::min<int>(BATCH_SIZE, static_cast<int>(max_iterations - iterations));

        // Генерация случайных значений
        ctx.generate_random_r_batch(r_batch.data(), current_batch_size);

        // Обработка батча
        for (int i = 0; i < current_batch_size && !stop_flag; ++i, ++iterations) {
            // Вычисления эллиптической кривой
            EC_POINT_mul(group, ctx.R_times_G, r_batch[i], nullptr, nullptr, ctx.ctx);
            EC_POINT_copy(ctx.numerator, G);
            EC_POINT_invert(group, ctx.R_times_G, ctx.ctx);
            EC_POINT_add(group, ctx.numerator, ctx.numerator, ctx.R_times_G, ctx.ctx);
            EC_POINT_mul(group, ctx.P_diff, nullptr, ctx.numerator, inv_D, ctx.ctx);
            EC_POINT_copy(ctx.P_target, P1);
            EC_POINT_add(group, ctx.P_target, ctx.P_target, ctx.P_diff, ctx.ctx);

            // Форматирование результатов
            char* r_str = BN_bn2dec(r_batch[i]);
            char* pubkey = EC_POINT_point2hex(group, ctx.P_target, POINT_CONVERSION_COMPRESSED, ctx.ctx);

            full_data_batch.emplace_back(std::string(r_str) + " | " + pubkey + "\n");
            pubkeys_batch.emplace_back(pubkey);

            OPENSSL_free(r_str);
            OPENSSL_free(pubkey);

            // Отправка на запись при заполнении буфера
            if (full_data_batch.size() >= WRITE_BUFFER_SIZE) {
                writer.write_batch(std::move(full_data_batch), std::move(pubkeys_batch));
                full_data_batch.clear();
                pubkeys_batch.clear();
            }
        }
    }

    // Запись оставшихся данных
    if (!full_data_batch.empty()) {
        writer.write_batch(std::move(full_data_batch), std::move(pubkeys_batch));
    }

    // Освобождение памяти
    for (auto& r : r_batch) {
        BN_free(r);
    }
}

void print_usage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " -p1 <P1> -rs <R_start> -re <R_end> -d <D> -t <threads> -o <output> [-i <iterations>]\n"
        << "Options:\n"
        << "  -p1 <P1>         Initial P1 point (hex)\n"
        << "  -rs <R_start>    Start of R range (decimal)\n"
        << "  -re <R_end>      End of R range (decimal)\n"
        << "  -d <D>           D value (decimal)\n"
        << "  -t <threads>     Number of threads (0 for auto)\n"
        << "  -o <output>      Output file (stdout if empty)\n"
        << "  -i <iterations>  Iterations per thread (default unlimited)\n";
}

int main(int argc, char* argv[]) {
    if (argc < 6) {
        print_usage(argv[0]);
        return 1;
    }

    std::string p1_hex, output_file;
    std::string R_start_str, R_end_str, D_str;
    unsigned threads = 1;
    uint64_t iterations_per_thread = UINT64_MAX;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-p1" && i + 1 < argc) {
            p1_hex = argv[++i];
        }
        else if (arg == "-rs" && i + 1 < argc) {
            R_start_str = argv[++i];
        }
        else if (arg == "-re" && i + 1 < argc) {
            R_end_str = argv[++i];
        }
        else if (arg == "-d" && i + 1 < argc) {
            D_str = argv[++i];
        }
        else if (arg == "-t" && i + 1 < argc) {
            threads = std::stoul(argv[++i]);
        }
        else if (arg == "-o" && i + 1 < argc) {
            output_file = argv[++i];
        }
        else if (arg == "-i" && i + 1 < argc) {
            iterations_per_thread = std::stoull(argv[++i]);
        }
        else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    try {
        OpenSSL_add_all_algorithms();
        EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (!group) {
            throw std::runtime_error("Failed to create EC group");
        }

        BN_CTX* ctx = BN_CTX_new();
        if (!ctx) {
            EC_GROUP_free(group);
            throw std::runtime_error("Failed to create BN context");
        }

        EC_POINT* P1 = EC_POINT_new(group);
        if (!EC_POINT_hex2point(group, p1_hex.c_str(), P1, ctx)) {
            EC_POINT_free(P1);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            throw std::runtime_error("Invalid P1 format");
        }

        BIGNUM* D = BN_new();
        if (!BN_dec2bn(&D, D_str.c_str())) {
            EC_POINT_free(P1);
            BN_free(D);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            throw std::runtime_error("Invalid D value");
        }

        BIGNUM* inv_D = BN_new();
        if (!BN_mod_inverse(inv_D, D, EC_GROUP_get0_order(group), ctx)) {
            EC_POINT_free(P1);
            BN_free(D);
            BN_free(inv_D);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            throw std::runtime_error("Failed to calculate inverse D");
        }

        BIGNUM* start_r = BN_new();
        BIGNUM* end_r = BN_new();
        if (!BN_dec2bn(&start_r, R_start_str.c_str()) || !BN_dec2bn(&end_r, R_end_str.c_str())) {
            EC_POINT_free(P1);
            BN_free(D);
            BN_free(inv_D);
            BN_free(start_r);
            BN_free(end_r);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            throw std::runtime_error("Invalid R range values");
        }

        BIGNUM* range_size = BN_new();
        BN_sub(range_size, end_r, start_r);
        BN_add(range_size, range_size, BN_value_one());

        unsigned num_threads = threads;
        if (num_threads == 0) {
            num_threads = std::thread::hardware_concurrency();
            if (num_threads == 0) num_threads = 4;
        }

        std::string pubkeys_file = output_file.empty() ? "" : output_file + "_pubkeys.txt";
        InstantFileWriter writer(output_file, pubkeys_file);

        std::vector<std::thread> workers;
        std::atomic<bool> stop_flag(false);
        auto start_time = std::chrono::high_resolution_clock::now();

        // Запуск рабочих потоков
        workers.reserve(num_threads);
        for (unsigned i = 0; i < num_threads; ++i) {
            workers.emplace_back(process_range, group, P1, D, inv_D,
                start_r, range_size,
                std::ref(writer), std::ref(stop_flag),
                iterations_per_thread);
        }

        // Ожидание завершения работы
        for (auto& t : workers) {
            if (t.joinable()) {
                t.join();
            }
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        double elapsed_sec = std::chrono::duration<double>(end_time - start_time).count();

        std::cout << "Processing complete in " << elapsed_sec << " seconds\n";
        std::cout << "Results saved to:\n";
        std::cout << " - Full format: " << (output_file.empty() ? "stdout" : output_file) << "\n";
        if (!output_file.empty()) {
            std::cout << " - Pubkeys only: " << pubkeys_file << "\n";
        }

        // Освобождение ресурсов
        BN_free(range_size);
        BN_free(start_r);
        BN_free(end_r);
        BN_free(inv_D);
        BN_free(D);
        EC_POINT_free(P1);
        EC_GROUP_free(group);
        BN_CTX_free(ctx);
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}