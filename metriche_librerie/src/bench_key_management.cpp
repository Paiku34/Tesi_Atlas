#include "benchmark_core.hpp"
#include <sodium.h>
#include <sodium/crypto_kdf_hkdf_sha256.h>
#include <fstream>
#include <iomanip>
#include <cstring>
#include <array>

struct KeyMgmtResult {
    std::string scheme_name;
    std::string paradigm;
    size_t exchanged_bytes = 0;
    
    double total_us = 0.0;
    unsigned long long total_cycles = 0;
    
    double energy_uj = -1.0;
    long ram_kb = 0;
    
    // Per analisi statistica e confidenza
    std::vector<double> sample_times_us;
};

// -----------------------------------------------------------------------------
// 1. PSK + KDF (Libsodium BLAKE2b)
// -----------------------------------------------------------------------------
void benchmark_psk_kdf_libsodium(KeyMgmtResult& res, int iterations) {
    res.scheme_name = "PSK + KDF (Libsodium)";
    res.paradigm = "Symmetric Pre-Shared";
    res.exchanged_bytes = 0; // 0 B (chiave pre-condivisa, derivazione locale su contatore di pacchetto)

    uint8_t psk[crypto_kdf_KEYBYTES]; // 32 B
    randombytes_buf(psk, sizeof(psk));
    uint8_t session_key[32];

    // Warm-up
    for (int i = 0; i < 50; i++) {
        crypto_kdf_derive_from_key(session_key, sizeof(session_key), (uint64_t)i, "ATLAS_KM", psk);
        do_not_optimize_away(session_key);
    }

    res.sample_times_us.clear();
    res.sample_times_us.reserve(iterations);

    long long energy_start = read_intel_rapl_uj();

    unsigned long long c0 = read_cpu_cycles();

    for (int i = 0; i < iterations; i++) {
        uint64_t subkey_id = (uint64_t)i;
        
        auto t0 = std::chrono::high_resolution_clock::now();
        crypto_kdf_derive_from_key(session_key, sizeof(session_key), subkey_id, "ATLAS_KM", psk);
        do_not_optimize_away(session_key);
        auto t1 = std::chrono::high_resolution_clock::now();

        double s_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        res.sample_times_us.push_back(s_us);
    }

    unsigned long long c1 = read_cpu_cycles();
    res.total_cycles = (c1 >= c0) ? ((c1 - c0) / iterations) : 0;

    long long energy_end = read_intel_rapl_uj();
    if (energy_start != -1 && energy_end >= energy_start) {
        res.energy_uj = (double)(energy_end - energy_start) / iterations;
    }

    double sum = 0.0;
    for (double v : res.sample_times_us) sum += v;
    res.total_us = sum / iterations;
    res.ram_kb = get_current_ram_usage_kb();
}

// -----------------------------------------------------------------------------
// 2. Symmetric handshake (buoy-side challenge response)
// -----------------------------------------------------------------------------
void benchmark_symmetric_handshake(KeyMgmtResult& res, int iterations) {
    res.scheme_name = "Symmetric Handshake";
    res.paradigm = "Symmetric Auth, Buoy Only";
    res.exchanged_bytes = 80;

    uint8_t psk[32];
    randombytes_buf(psk, sizeof(psk));
    uint8_t nc[32], ns[32], tag[crypto_auth_BYTES], session_key[32];
    uint8_t handshake_data[64];
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];

    // The Ground Station nonce is received before the measured buoy operation.
    randombytes_buf(nc, sizeof(nc));

    // Warm-up
    for (int i = 0; i < 50; i++) {
        randombytes_buf(ns, sizeof(ns));
        memcpy(handshake_data, nc, 32);
        memcpy(handshake_data + 32, ns, 32);
        crypto_auth(tag, handshake_data, sizeof(handshake_data), psk);
        crypto_kdf_hkdf_sha256_extract(prk, handshake_data, sizeof(handshake_data), psk, sizeof(psk));
        crypto_kdf_hkdf_sha256_expand(session_key, sizeof(session_key), "ATLAS_SH", 8, prk);
        do_not_optimize_away(session_key);
    }

    res.sample_times_us.clear();
    res.sample_times_us.reserve(iterations);

    long long energy_start = read_intel_rapl_uj();

    unsigned long long c0 = read_cpu_cycles();

    for (int i = 0; i < iterations; i++) {
        auto t0 = std::chrono::high_resolution_clock::now();
        // The GS nonce is already available; only the buoy-side response is measured.
        randombytes_buf(ns, sizeof(ns));
        memcpy(handshake_data, nc, 32);
        memcpy(handshake_data + 32, ns, 32);

        // The buoy authenticates its response with the PSK.
        crypto_auth(tag, handshake_data, sizeof(handshake_data), psk);
        crypto_kdf_hkdf_sha256_extract(prk, handshake_data, sizeof(handshake_data), psk, sizeof(psk));
        crypto_kdf_hkdf_sha256_expand(session_key, sizeof(session_key), "ATLAS_SH", 8, prk);
        do_not_optimize_away(session_key);
        auto t1 = std::chrono::high_resolution_clock::now();

        double s_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        res.sample_times_us.push_back(s_us);
    }

    unsigned long long c1 = read_cpu_cycles();
    res.total_cycles = (c1 >= c0) ? ((c1 - c0) / iterations) : 0;

    long long energy_end = read_intel_rapl_uj();
    if (energy_start != -1 && energy_end >= energy_start) {
        res.energy_uj = (double)(energy_end - energy_start) / iterations;
    }

    double sum = 0.0;
    for (double v : res.sample_times_us) sum += v;
    res.total_us = sum / iterations;
    res.ram_kb = get_current_ram_usage_kb();
}

// -----------------------------------------------------------------------------
// 3. One-way authenticated X25519 (buoy side only)
// -----------------------------------------------------------------------------
void benchmark_x25519_libsodium(KeyMgmtResult& res, int iterations) {
    constexpr size_t PSK_TAG_BYTES = 16;
    res.scheme_name = "ECDH X25519 One-Way (PSK Auth)";
    res.paradigm = "Classical ECC, Buoy Only";
    // GS challenge (32 B nonce + 16 B tag) + buoy response
    // (32 B nonce + 32 B ephemeral public key + 16 B tag).
    res.exchanged_bytes = 32 + PSK_TAG_BYTES + 32 + 32 + PSK_TAG_BYTES;

    uint8_t psk[crypto_auth_KEYBYTES];
    uint8_t gs_pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t buoy_pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t buoy_sk[crypto_kx_SECRETKEYBYTES];
    uint8_t session_key[crypto_kx_SESSIONKEYBYTES];
    uint8_t response_data[32 + 32 + crypto_kx_PUBLICKEYBYTES];
    uint8_t response_tag[crypto_auth_BYTES];

    randombytes_buf(psk, sizeof(psk));
    // In deployment this public key is provisioned in the buoy. Key generation
    // is deliberately outside the measured operation because it belongs to GS setup.
    uint8_t gs_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(gs_pk, gs_sk);

    std::vector<std::array<uint8_t, 32>> gs_nonces(iterations);
    for (int i = 0; i < iterations; i++) {
        randombytes_buf(gs_nonces[i].data(), gs_nonces[i].size());
    }

    auto run_one_way_operation = [&](int i) {
        uint8_t buoy_nonce[32];
        randombytes_buf(buoy_nonce, sizeof(buoy_nonce));
        crypto_kx_keypair(buoy_pk, buoy_sk);
        if (crypto_kx_client_session_keys(
                session_key, nullptr, buoy_pk, buoy_sk, gs_pk) != 0) {
            return;
        }

        memcpy(response_data, gs_nonces[i].data(), 32);
        memcpy(response_data + 32, buoy_nonce, 32);
        memcpy(response_data + 64, buoy_pk, sizeof(buoy_pk));
        crypto_auth(response_tag, response_data, sizeof(response_data), psk);

        do_not_optimize_away(response_tag);
        do_not_optimize_away(session_key);
    };

    // Warm-up: only the buoy-side operation is included.
    for (int i = 0; i < 20; i++) {
        run_one_way_operation(i % iterations);
    }

    res.sample_times_us.clear();
    res.sample_times_us.reserve(iterations);

    long long energy_start = read_intel_rapl_uj();

    unsigned long long c0 = read_cpu_cycles();

    for (int i = 0; i < iterations; i++) {
        auto t0 = std::chrono::high_resolution_clock::now();
        run_one_way_operation(i);
        auto t1 = std::chrono::high_resolution_clock::now();

        double s_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        res.sample_times_us.push_back(s_us);
    }

    unsigned long long c1 = read_cpu_cycles();
    res.total_cycles = (c1 >= c0) ? ((c1 - c0) / iterations) : 0;

    long long energy_end = read_intel_rapl_uj();
    if (energy_start != -1 && energy_end >= energy_start) {
        res.energy_uj = (double)(energy_end - energy_start) / iterations;
    }

    double sum = 0.0;
    for (double v : res.sample_times_us) sum += v;
    res.total_us = sum / iterations;
    res.ram_kb = get_current_ram_usage_kb();
}

// -----------------------------------------------------------------------------
// Salva i campioni su file CSV per l'elaborazione con Python
// -----------------------------------------------------------------------------
void append_samples_to_csv(const std::string& filename, const KeyMgmtResult& res) {
    std::ofstream file(filename, std::ios::app);
    if (!file.is_open()) return;
    
    for (size_t i = 0; i < res.sample_times_us.size(); i++) {
        file << "key_management,"
             << "\"" << res.scheme_name << "\","
             << "\"" << res.paradigm << "\","
             << res.exchanged_bytes << ","
             << i + 1 << ","
             << std::fixed << std::setprecision(4) << res.sample_times_us[i] << ","
             << res.total_cycles << ","
             << std::fixed << std::setprecision(3) << res.energy_uj << ","
             << res.ram_kb << "\n";
    }
}

int main() {
    // Warm-up contatori cicli hardware (Linux PMU / x86)
    (void)read_cpu_cycles();

    if (sodium_init() < 0) {
        std::cerr << "Errore inizializzazione sodium!\n";
        return 1;
    }

    std::cout << "\n======================================================================================================\n";
    std::cout << " BENCHMARK: KEY MANAGEMENT ROADMAP (PSK -> Symmetric Handshake -> ONE-WAY ECC)\n";
    std::cout << " Tesi: Secure Sonobuoy Telemetry (Edge Pre-Quantum Baseline)\n";
    std::cout << "======================================================================================================\n";

    std::string csv_file = get_data_dir() + "key_management_raw.csv";
    {
        // Sovrascrivi/Inizializza CSV con intestazione
        std::ofstream file(csv_file);
        file << "category,scheme,paradigm,exchanged_bytes,sample_id,latency_us,cycles,energy_uj,ram_kb\n";
    }

    std::cout << std::left 
              << "| " << std::setw(26) << "Schema"
              << "| " << std::setw(22) << "Paradigma"
              << "| " << std::setw(12) << "Scambiati"
              << "| " << std::setw(14) << "Tempo Medio(us)"
              << "| " << std::setw(12) << "Cicli/Op"
              << "| " << std::setw(12) << "Energia(uJ)"
              << "| " << std::setw(8)  << "RSS(KB)"
              << "|\n";
    std::cout << "|" << std::string(27, '-')
              << "|" << std::string(23, '-')
              << "|" << std::string(13, '-')
              << "|" << std::string(16, '-')
              << "|" << std::string(13, '-')
              << "|" << std::string(14, '-')
              << "|" << std::string(10, '-')
              << "|\n";

    const int ITERATIONS = 1000; // 1000 campioni singoli 1-a-1 senza batching

    auto run_and_print = [&](auto bench_func) {
        pid_t pid = fork();
        if (pid == 0) {
            KeyMgmtResult res;
            bench_func(res, ITERATIONS);
            
            append_samples_to_csv(csv_file, res);

            std::string e_str = (res.energy_uj >= 0) ? std::to_string(res.energy_uj) : "N/A";

            std::cout << std::left 
                      << "| " << std::setw(26) << res.scheme_name
                      << "| " << std::setw(22) << res.paradigm
                      << "| " << std::setw(12) << (std::to_string(res.exchanged_bytes) + " B")
                      << "| " << std::fixed << std::setprecision(2)
                      << std::setw(14) << res.total_us
                      << "| " << std::setw(12) << res.total_cycles
                      << "| " << std::setw(12) << e_str
                      << "| " << std::setw(8)  << res.ram_kb
                      << "|\n";
            std::cout.flush();
            _exit(0);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        }
    };

    run_and_print(benchmark_psk_kdf_libsodium);
    run_and_print(benchmark_symmetric_handshake);
    run_and_print(benchmark_x25519_libsodium);

    std::cout << "  Dati grezzi esportati con successo in: " << csv_file << "\n\n";

    return 0;
}
