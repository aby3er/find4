# find4.cpp и delta2.cpp
Генератор публичных ключей (остатков R) - find4.cpp и дельта-генератор для поиска (любого из сгенерированных остатков R) - delta2.cpp для работы со сторнныим приложением или записи в файл
для компиляции find4.cpp в minGW64 : g++ find4.cpp -o find4.exe -std=c++17 -IC:\boost -lcrypto -lssl -march=native -pthread  ,или статической линковкой ,чтобы вшить из библитек что нужно
для delta2.cpp ,напимер статической линковкой : g++ -o delta2.exe delta2.cpp -static -IC:\boost -lboost_program_options-mt -lssl -lcrypto -lcrypt32 -lws2_32 -lwsock32 -lpthread 

О
