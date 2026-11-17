#include "serial_port.hpp"
#include "radio_packet.hpp"
#include "crypto_engine.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <thread>
#include <iomanip>
#include <numeric>
#include <algorithm>

#ifdef __linux__
#include <sys/resource.h>
#endif

using namespace radio;

struct TelemetryResult {
    std::string algo_name;
    size_t payload_bytes;
    double crypto_tx_us;
    double rtt_ms;
    bool ack_received;
    size_t frame_bytes;
    double overhead_pct;
    double throughput_bps;
    int retries;
};

struct KemResult {
    std::string kem_name;
    double encaps_us;
    double rtt_ms;
    bool ack_received;
    size_t ciphertext_bytes;
    size_t shared_secret_bytes;
    size_t frame_bytes;
    int retries;
};

static int adaptive_timeout_ms(size_t frame_bytes, int base_timeout_ms = 1500) {
    double tx_time_ms = (static_cast<double>(frame_bytes) * 8.0 / 12500.0) * 1000.0;
    int estimated_ms = static_cast<int>(tx_time_ms * 2.5) + 500;
    return std::max(base_timeout_ms, estimated_ms);
}

static bool wait_for_ack(SerialPort& serial, uint32_t expected_seq, int timeout_ms, double& out_rtt_ms,
                         const std::chrono::steady_clock::time_point& t_tx, bool check_seq = true) {
    uint8_t in_magic = 0;
    auto ack_start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - ack_start).count() < timeout_ms) {
        if (serial.read_byte(in_magic, 100) && in_magic == MAGIC_ACK) {
            AckPacket ack;
            ack.magic = in_magic;
            if (serial.read_exact(reinterpret_cast<uint8_t*>(&ack) + 1, sizeof(AckPacket) - 1, 300)) {
                if (ack.status_code == 0 && (!check_seq || ack.seq_num == expected_seq)) {
                    out_rtt_ms = std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - t_tx).count();
                    return true;
                }
            }
        }
    }
    return false;
}

static double get_cpu_time_ms() {
#ifdef __linux__
    struct rusage ru;
    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        return (ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1000.0 +
               (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1000.0;
    }
#endif
    return 0.0;
}

void run_telemetry_burst(SerialPort& serial,
                         CryptoEngine& crypto,
                         CryptoAlgorithm algo,
                         const std::string& algo_name,
                         size_t payload_size,
                         int num_packets,
                         std::vector<TelemetryResult>& results,
                         uint32_t& seq_counter,
                         int max_retries = 2) {

    std::cout << "  > Test " << algo_name << " | Payload: " << payload_size << " B | " << num_packets << " pacchetti...\n";
    std::vector<uint8_t> dummy_payload(payload_size);
    for (size_t i = 0; i < payload_size; ++i) {
        dummy_payload[i] = static_cast<uint8_t>((i + 1) & 0xFF);
    }

    double cpu_start = get_cpu_time_ms();
    auto wall_start = std::chrono::steady_clock::now();

    for (int p = 0; p < num_packets; ++p) {
        uint32_t current_seq = ++seq_counter;

        auto t_start_crypto = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> ciphertext;
        uint8_t tag[AEAD_TAG_LEN];
        bool ok = crypto.encrypt(algo, current_seq, dummy_payload.data(), dummy_payload.size(), ciphertext, tag);
        auto t_end_crypto = std::chrono::high_resolution_clock::now();

        if (!ok) {
            std::cerr << "    [ERR] Cifratura fallita per seq " << current_seq << "\n";
            continue;
        }

        double crypto_time_us = std::chrono::duration<double, std::micro>(t_end_crypto - t_start_crypto).count();

        TelemetryHeader header{MAGIC_TELEMETRY, static_cast<uint8_t>(algo), current_seq, static_cast<uint16_t>(ciphertext.size())};
        size_t tag_len = (algo == CryptoAlgorithm::BASELINE_CLEAR) ? 0 : AEAD_TAG_LEN;

        std::vector<uint8_t> frame(sizeof(header) + ciphertext.size() + tag_len);
        std::memcpy(frame.data(), &header, sizeof(header));
        std::memcpy(frame.data() + sizeof(header), ciphertext.data(), ciphertext.size());
        if (tag_len > 0) {
            std::memcpy(frame.data() + sizeof(header) + ciphertext.size(), tag, tag_len);
        }

        double overhead_pct = (static_cast<double>(frame.size() - payload_size)) / frame.size() * 100.0;

        bool ack_ok = false;
        double rtt_ms = -1.0;
        int retries_used = 0;
        int timeout_ms = adaptive_timeout_ms(frame.size());

        for (int r = 0; r <= max_retries; ++r) {
            auto t_tx = std::chrono::steady_clock::now();
            serial.write_exact(frame.data(), frame.size());
            ack_ok = wait_for_ack(serial, current_seq, timeout_ms, rtt_ms, t_tx, true);
            if (ack_ok) {
                break;
            }
            retries_used++;
            serial.flush();
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        double throughput_bps = (ack_ok && rtt_ms > 0) ? ((payload_size * 8.0) / (rtt_ms / 1000.0)) : 0.0;

        results.push_back({algo_name, payload_size, crypto_time_us, rtt_ms, ack_ok,
                           frame.size(), overhead_pct, throughput_bps, retries_used});

        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }

    double cpu_end = get_cpu_time_ms();
    auto wall_end = std::chrono::steady_clock::now();
    double wall_ms = std::chrono::duration<double, std::milli>(wall_end - wall_start).count();
    double cpu_pct = (wall_ms > 0) ? ((cpu_end - cpu_start) / wall_ms * 100.0) : 0.0;
    std::cout << "    [CPU Usage] " << std::fixed << std::setprecision(2) << cpu_pct << " %\n";
}

void run_kem_handshake_test(SerialPort& serial,
                            CryptoEngine& crypto,
                            KemAlgorithm kem_algo,
                            const std::string& kem_name,
                            int num_handshakes,
                            std::vector<KemResult>& kem_results,
                            bool derive_aead_key = false,
                            int max_retries = 1) {

    std::cout << "\n--- AVVIO TEST KEM: " << kem_name << " (" << num_handshakes << " handshake) ---\n";

    for (int h = 0; h < num_handshakes; ++h) {
        auto t_encaps_start = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> kem_ct;
        std::vector<uint8_t> shared_secret;
        bool encaps_ok = crypto.kem_encapsulate(kem_algo, kem_ct, shared_secret);
        auto t_encaps_end = std::chrono::high_resolution_clock::now();

        if (!encaps_ok) {
            std::cerr << "    [ERR] KEM encapsulate fallito per " << kem_name << " #" << (h+1) << "\n";
            kem_results.push_back({kem_name, 0.0, -1.0, false, 0, 0, 0, 0});
            continue;
        }

        double encaps_us = std::chrono::duration<double, std::micro>(t_encaps_end - t_encaps_start).count();

        KemHeader kh{MAGIC_KEM, static_cast<uint8_t>(kem_algo), static_cast<uint16_t>(kem_ct.size())};
        std::vector<uint8_t> frame(sizeof(KemHeader) + kem_ct.size());
        std::memcpy(frame.data(), &kh, sizeof(KemHeader));
        std::memcpy(frame.data() + sizeof(KemHeader), kem_ct.data(), kem_ct.size());

        double rtt_ms = -1.0;
        int timeout_ms = adaptive_timeout_ms(frame.size(), 3000);
        bool ack_ok = false;
        int retries_used = 0;

        for (int r = 0; r <= max_retries; ++r) {
            auto t_tx = std::chrono::steady_clock::now();
            serial.write_exact(frame.data(), frame.size());
            ack_ok = wait_for_ack(serial, 0, timeout_ms, rtt_ms, t_tx, false);
            if (ack_ok) {
                break;
            }
            retries_used++;
            serial.flush();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        kem_results.push_back({kem_name, encaps_us, rtt_ms, ack_ok,
                               kem_ct.size(), shared_secret.size(), frame.size(), retries_used});

        if (ack_ok && derive_aead_key) {
            if (crypto.set_session_key_from_kem(shared_secret.data(), shared_secret.size())) {
                std::cout << "    [KEM->AEAD] Session key derivata da " << kem_name << " shared secret\n";
            }
        }

        if (ack_ok) {
            std::cout << "    [OK] KEM #" << (h+1) << " | Encaps: " << std::fixed << std::setprecision(1)
                      << encaps_us << " us | RTT: " << std::setprecision(1) << rtt_ms
                      << " ms | CT: " << kem_ct.size() << " B | Retries: " << retries_used << "\n";
        } else {
            std::cout << "    [TIMEOUT] KEM #" << (h+1) << " | Encaps: " << std::fixed << std::setprecision(1)
                      << encaps_us << " us | Fallito dopo " << retries_used << " tentativi\n";
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void print_aggregate_stats(const std::vector<TelemetryResult>& results) {
    std::cout << "\n=== STATISTICHE AGGREGATE ===\n";

    std::string last_key;
    std::vector<double> rtts;
    size_t successes = 0, total = 0, total_retries = 0;

    for (size_t i = 0; i <= results.size(); ++i) {
        std::string key = (i < results.size())
            ? results[i].algo_name + "|" + std::to_string(results[i].payload_bytes)
            : "";

        if (key != last_key && !last_key.empty()) {
            double pdr = (total > 0) ? (static_cast<double>(successes) / total * 100.0) : 0.0;
            std::sort(rtts.begin(), rtts.end());
            double avg_rtt = rtts.empty() ? 0 : (std::accumulate(rtts.begin(), rtts.end(), 0.0) / rtts.size());
            double med_rtt = rtts.empty() ? 0 : rtts[rtts.size() / 2];
            double p95_rtt = rtts.empty() ? 0 : rtts[static_cast<size_t>(rtts.size() * 0.95)];

            std::cout << "  " << last_key << " -> PDR: " << std::fixed << std::setprecision(1) << pdr
                      << "% | RTT avg: " << std::setprecision(1) << avg_rtt
                      << " ms, med: " << med_rtt << " ms, p95: " << p95_rtt
                      << " ms | Retries: " << total_retries << "\n";

            rtts.clear();
            successes = 0;
            total = 0;
            total_retries = 0;
        }

        if (i < results.size()) {
            last_key = key;
            total++;
            total_retries += results[i].retries;
            if (results[i].ack_received) {
                successes++;
                rtts.push_back(results[i].rtt_ms);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    std::string device = "/dev/ttyUSB0";
    int baudrate = 57600;
    std::string csv_out = "radio_telemetry_results.csv";
    std::string kem_csv_out = "radio_kem_results.csv";
    bool run_kem_tests = true;
    bool derive_key_after_kem = false;

    if (argc > 1) device = argv[1];
    if (argc > 2) baudrate = std::stoi(argv[2]);
    if (argc > 3) csv_out = argv[3];
    if (argc > 4) kem_csv_out = argv[4];
    if (argc > 5) derive_key_after_kem = (std::string(argv[5]) == "--derive-key");

    std::cout << "========================================================\n";
    std::cout << "  ZENO ATLAS - BOA TELEMETRY NODE (Raspberry Pi)\n";
    std::cout << "  Device: " << device << " (" << baudrate << " baud)\n";
    std::cout << "========================================================\n\n";

    SerialPort serial;
    if (!serial.open_device(device, baudrate)) {
        std::cerr << "Impossibile aprire il dispositivo " << device << "\n";
        return 1;
    }
    std::cout << "[OK] Porta seriale aperta e configurata.\n";

    CryptoEngine crypto;
    uint32_t seq_counter = 1000;
    std::vector<TelemetryResult> results;
    std::vector<KemResult> kem_results;

    const std::vector<size_t> payloads = {8, 16, 32, 64, 128, 256};
    const int PACKETS_PER_RUN = 50;

    const std::vector<std::pair<CryptoAlgorithm, std::string>> algos = {
        {CryptoAlgorithm::BASELINE_CLEAR,   "Baseline (In Chiaro)"},
        {CryptoAlgorithm::ASCON_128,        "Ascon-AEAD128 (ascon-c)"},
        {CryptoAlgorithm::AES_256_GCM,      "AES-256-GCM (OpenSSL)"},
        {CryptoAlgorithm::CHACHA20_SODIUM,  "ChaCha20-Poly1305 (Libsodium)"},
        {CryptoAlgorithm::CHACHA20_OPENSSL, "ChaCha20-Poly1305 (OpenSSL)"}
    };

    for (const auto& alg : algos) {
        std::cout << "\n--- AVVIO TEST: " << alg.second << " ---\n";
        for (size_t sz : payloads) {
            run_telemetry_burst(serial, crypto, alg.first, alg.second, sz, PACKETS_PER_RUN, results, seq_counter);
        }
    }

    if (run_kem_tests) {
        const std::vector<std::pair<KemAlgorithm, std::string>> kem_algos = {
            {KemAlgorithm::X25519,      "X25519 (Libsodium)"},
            {KemAlgorithm::ML_KEM_512,  "ML-KEM-512 (liboqs)"},
            {KemAlgorithm::ML_KEM_768,  "ML-KEM-768 (liboqs)"},
            {KemAlgorithm::ML_KEM_1024, "ML-KEM-1024 (liboqs)"}
        };

        for (const auto& ka : kem_algos) {
            run_kem_handshake_test(serial, crypto, ka.first, ka.second, 20, kem_results, derive_key_after_kem);
        }
    }

    {
        std::ofstream out(csv_out);
        out << "Algorithm,Payload_B,Crypto_Time_us,RTT_ms,Success,Frame_B,Overhead_pct,Throughput_bps,Retries\n";
        for (const auto& r : results) {
            out << r.algo_name << "," << r.payload_bytes << ","
                << std::fixed << std::setprecision(3) << r.crypto_tx_us << ","
                << (r.ack_received ? std::to_string(r.rtt_ms) : "TIMEOUT") << ","
                << (r.ack_received ? 1 : 0) << ","
                << r.frame_bytes << ","
                << std::setprecision(2) << r.overhead_pct << ","
                << std::setprecision(1) << r.throughput_bps << ","
                << r.retries << "\n";
        }
    }

    if (!kem_results.empty()) {
        std::ofstream out(kem_csv_out);
        out << "KEM_Algorithm,Encaps_Time_us,RTT_ms,Success,Ciphertext_B,SharedSecret_B,Frame_B,Retries\n";
        for (const auto& r : kem_results) {
            out << r.kem_name << ","
                << std::fixed << std::setprecision(3) << r.encaps_us << ","
                << (r.ack_received ? std::to_string(r.rtt_ms) : "TIMEOUT") << ","
                << (r.ack_received ? 1 : 0) << ","
                << r.ciphertext_bytes << ","
                << r.shared_secret_bytes << ","
                << r.frame_bytes << ","
                << r.retries << "\n";
        }
    }

    print_aggregate_stats(results);

    size_t success_count = 0;
    for (const auto& r : results) {
        if (r.ack_received) success_count++;
    }
    double overall_pdr = results.empty() ? 0.0 : (static_cast<double>(success_count) / results.size() * 100.0);

    std::cout << "\n=== SESSIONE COMPLESSIVA ===\n"
              << "  Pacchetti totali: " << results.size() << "\n"
              << "  Successi:         " << success_count << "\n"
              << "  PDR complessivo:  " << std::fixed << std::setprecision(1) << overall_pdr << " %\n";

    return 0;
}
