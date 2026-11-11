#include "benchmark_core.hpp"
#include <sodium.h>
#include <sodium/crypto_kdf_hkdf_sha256.h>
#include <fstream>
#include <iomanip>
#include <cstring>

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

    uint64_t operation_counter = 0;
    KeyMgmtMeasurement measurement = measure_key_management([&]() {
        uint64_t subkey_id = operation_counter++;
        crypto_kdf_derive_from_key(session_key, sizeof(session_key), subkey_id, "ATLAS_KM", psk);
        do_not_optimize_away(session_key);
    }, iterations);
    res.sample_times_us = std::move(measurement.sample_times_us);
    res.total_us = measurement.mean_us;
    res.total_cycles = measurement.cycles_per_op;
    res.energy_uj = measurement.energy_uj;
    res.ram_kb = get_current_ram_usage_kb();
}

// -----------------------------------------------------------------------------
// 2. Symmetric handshake (buoy-side challenge response)
// -----------------------------------------------------------------------------
void benchmark_symmetric_handshake(KeyMgmtResult& res, int iterations) {
    res.scheme_name = "Symmetric Handshake";
    res.paradigm = "Symmetric Auth, Buoy Only";
    res.exchanged_bytes = 96;

    uint8_t psk[32];
    randombytes_buf(psk, sizeof(psk));
    constexpr size_t PSK_TAG_BYTES = 16;
    uint8_t nc[32], ns[32], tag[crypto_auth_BYTES], session_key[32];
    uint8_t handshake_data[64];
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];

    // The Ground Station nonce and authentication tag are received before the
    // measured buoy operation. Their generation is not part of this benchmark.
    randombytes_buf(nc, sizeof(nc));
    memcpy(handshake_data, nc, sizeof(nc));
    memset(handshake_data + sizeof(nc), 0, sizeof(ns));
    crypto_auth(tag, handshake_data, sizeof(handshake_data), psk);
    uint8_t gs_tag[crypto_auth_BYTES];
    memcpy(gs_tag, tag, sizeof(gs_tag));

    KeyMgmtMeasurement measurement = measure_key_management([&]() {
        memcpy(handshake_data, nc, sizeof(nc));
        memset(handshake_data + sizeof(nc), 0, sizeof(ns));
        uint8_t expected_gs_tag[crypto_auth_BYTES];
        crypto_auth(expected_gs_tag, handshake_data, sizeof(handshake_data), psk);
        if (sodium_memcmp(gs_tag, expected_gs_tag, PSK_TAG_BYTES) == 0) {
            randombytes_buf(ns, sizeof(ns));
            memcpy(handshake_data + 32, ns, 32);
            crypto_auth(tag, handshake_data, sizeof(handshake_data), psk);
            crypto_kdf_hkdf_sha256_extract(prk, handshake_data, sizeof(handshake_data), psk, sizeof(psk));
            crypto_kdf_hkdf_sha256_expand(session_key, sizeof(session_key), "ATLAS_SH", 8, prk);
            do_not_optimize_away(session_key);
        }
    }, iterations);
    res.sample_times_us = std::move(measurement.sample_times_us);
    res.total_us = measurement.mean_us;
    res.total_cycles = measurement.cycles_per_op;
    res.energy_uj = measurement.energy_uj;
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
    uint8_t shared_secret[crypto_scalarmult_BYTES];
    uint8_t session_key[32];
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    uint8_t response_data[32 + 32 + crypto_kx_PUBLICKEYBYTES];
    uint8_t response_tag[crypto_auth_BYTES];

    randombytes_buf(psk, sizeof(psk));
    // In deployment this public key is provisioned in the buoy. Key generation
    // is deliberately outside the measured operation because it belongs to GS setup.
    uint8_t gs_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(gs_pk, gs_sk);

    uint8_t gs_nonce[32];
    uint8_t gs_auth_data[32 + crypto_kx_PUBLICKEYBYTES];
    uint8_t gs_tag[crypto_auth_BYTES];
    randombytes_buf(gs_nonce, sizeof(gs_nonce));
    memcpy(gs_auth_data, gs_nonce, sizeof(gs_nonce));
    memcpy(gs_auth_data + sizeof(gs_nonce), gs_pk, sizeof(gs_pk));
    crypto_auth(gs_tag, gs_auth_data, sizeof(gs_auth_data), psk);

    auto run_one_way_operation = [&]() {
        uint8_t expected_tag[crypto_auth_BYTES];
        crypto_auth(expected_tag, gs_auth_data, sizeof(gs_auth_data), psk);
        if (sodium_memcmp(gs_tag, expected_tag, PSK_TAG_BYTES) != 0) {
            return;
        }

        uint8_t buoy_nonce[32];
        randombytes_buf(buoy_nonce, sizeof(buoy_nonce));
        crypto_kx_keypair(buoy_pk, buoy_sk);
        if (crypto_scalarmult_curve25519(shared_secret, buoy_sk, gs_pk) != 0) {
            return;
        }

        memcpy(response_data, gs_nonce, sizeof(gs_nonce));
        memcpy(response_data + 32, buoy_nonce, 32);
        memcpy(response_data + 64, buoy_pk, sizeof(buoy_pk));
        crypto_auth(response_tag, response_data, sizeof(response_data), psk);

        crypto_kdf_hkdf_sha256_extract(
            prk, psk, sizeof(psk), shared_secret, sizeof(shared_secret));
        crypto_kdf_hkdf_sha256_expand(
            session_key, sizeof(session_key), "ATLAS_ECDH", 11, prk);

        do_not_optimize_away(response_tag);
        do_not_optimize_away(session_key);
    };

    KeyMgmtMeasurement measurement = measure_key_management(run_one_way_operation, iterations);
    res.sample_times_us = std::move(measurement.sample_times_us);
    res.total_us = measurement.mean_us;
    res.total_cycles = measurement.cycles_per_op;
    res.energy_uj = measurement.energy_uj;
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

    const int ITERATIONS = KEY_MGMT_MEASUREMENT_ITERATIONS;

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
