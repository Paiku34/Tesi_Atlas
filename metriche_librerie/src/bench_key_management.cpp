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
    
    double keygen_us = 0.0;
    unsigned long long keygen_cycles = 0;
    
    double derive_us = 0.0;
    unsigned long long derive_cycles = 0;
    
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

    #ifdef COMPILER_IS_X86
    unsigned int aux;
    unsigned long long c0 = __rdtscp(&aux);
    #endif

    for (int i = 0; i < iterations; i++) {
        uint64_t subkey_id = (uint64_t)i;
        
        auto t0 = std::chrono::high_resolution_clock::now();
        crypto_kdf_derive_from_key(session_key, sizeof(session_key), subkey_id, "ATLAS_KM", psk);
        do_not_optimize_away(session_key);
        auto t1 = std::chrono::high_resolution_clock::now();

        double s_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        res.sample_times_us.push_back(s_us);
    }

    #ifdef COMPILER_IS_X86
    unsigned long long c1 = __rdtscp(&aux);
    res.derive_cycles = (c1 - c0) / iterations;
    res.total_cycles = res.derive_cycles;
    #endif

    long long energy_end = read_intel_rapl_uj();
    if (energy_start != -1 && energy_end >= energy_start) {
        res.energy_uj = (double)(energy_end - energy_start) / iterations;
    }

    double sum = 0.0;
    for (double v : res.sample_times_us) sum += v;
    res.derive_us = sum / iterations;
    res.total_us = res.derive_us;
    res.ram_kb = get_current_ram_usage_kb();
}

// -----------------------------------------------------------------------------
// 2. Symmetric 2-Way Handshake (Challenge-Response + Key Confirmation)
// -----------------------------------------------------------------------------
void benchmark_symmetric_handshake(KeyMgmtResult& res, int iterations) {
    res.scheme_name = "Symmetric Handshake";
    res.paradigm = "Symmetric 2-Way Auth";
    res.exchanged_bytes = 80;

    uint8_t psk[32];
    randombytes_buf(psk, sizeof(psk));
    uint8_t nc[32], ns[32], tag[16], session_key[32];
    uint8_t handshake_data[64];
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];

    // Warm-up
    for (int i = 0; i < 50; i++) {
        randombytes_buf(nc, sizeof(nc));
        randombytes_buf(ns, sizeof(ns));
        memcpy(handshake_data, nc, 32);
        memcpy(handshake_data + 32, ns, 32);
        crypto_auth(tag, handshake_data, sizeof(handshake_data), psk);
        if (crypto_auth_verify(tag, handshake_data, sizeof(handshake_data), psk) == 0) {
            crypto_kdf_hkdf_sha256_extract(prk, handshake_data, sizeof(handshake_data), psk, sizeof(psk));
            crypto_kdf_hkdf_sha256_expand(session_key, sizeof(session_key), "ATLAS_SH", 8, prk);
        }
        do_not_optimize_away(session_key);
    }

    res.sample_times_us.clear();
    res.sample_times_us.reserve(iterations);

    long long energy_start = read_intel_rapl_uj();

    #ifdef COMPILER_IS_X86
    unsigned int aux;
    unsigned long long c0 = __rdtscp(&aux);
    #endif

    for (int i = 0; i < iterations; i++) {
        auto t0 = std::chrono::high_resolution_clock::now();
        // 1. Client genera Nonce client (32 B)
        randombytes_buf(nc, sizeof(nc));
        
        // 2. Server genera Nonce server (32 B) e concatena i due nonce
        randombytes_buf(ns, sizeof(ns));
        memcpy(handshake_data, nc, 32);
        memcpy(handshake_data + 32, ns, 32);

        // 3. Server calcola Tag MAC su (nc || ns) con la Master Key
        crypto_auth(tag, handshake_data, sizeof(handshake_data), psk);
        
        // 4. Client verifica Tag su (nc || ns)
        if (crypto_auth_verify(tag, handshake_data, sizeof(handshake_data), psk) == 0) {
            // 5. Entrambi derivano la chiave di sessione a 256 bit tramite HKDF (RFC 5869 - HMAC-SHA256)
            crypto_kdf_hkdf_sha256_extract(prk, handshake_data, sizeof(handshake_data), psk, sizeof(psk));
            crypto_kdf_hkdf_sha256_expand(session_key, sizeof(session_key), "ATLAS_SH", 8, prk);
        }
        do_not_optimize_away(session_key);
        auto t1 = std::chrono::high_resolution_clock::now();

        double s_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        res.sample_times_us.push_back(s_us);
    }

    #ifdef COMPILER_IS_X86
    unsigned long long c1 = __rdtscp(&aux);
    res.total_cycles = (c1 - c0) / iterations;
    res.derive_cycles = res.total_cycles;
    #endif

    long long energy_end = read_intel_rapl_uj();
    if (energy_start != -1 && energy_end >= energy_start) {
        res.energy_uj = (double)(energy_end - energy_start) / iterations;
    }

    double sum = 0.0;
    for (double v : res.sample_times_us) sum += v;
    res.total_us = sum / iterations;
    res.derive_us = res.total_us;
    res.ram_kb = get_current_ram_usage_kb();
}

// -----------------------------------------------------------------------------
// 3. ECC X25519 (ECDH - Libsodium)
// -----------------------------------------------------------------------------
void benchmark_x25519_libsodium(KeyMgmtResult& res, int iterations) {
    res.scheme_name = "ECDH X25519 (Libsodium)";
    res.paradigm = "Classical (ECC)";
    res.exchanged_bytes = 64;

    uint8_t client_sk[crypto_scalarmult_SCALARBYTES];
    uint8_t client_pk[crypto_scalarmult_BYTES];
    uint8_t server_sk[crypto_scalarmult_SCALARBYTES];
    uint8_t server_pk[crypto_scalarmult_BYTES];
    uint8_t shared_secret[crypto_scalarmult_BYTES];

    // Warm-up
    for (int i = 0; i < 20; i++) {
        randombytes_buf(client_sk, sizeof(client_sk));
        crypto_scalarmult_base(client_pk, client_sk);
    }

    res.sample_times_us.clear();
    res.sample_times_us.reserve(iterations);

    long long energy_start = read_intel_rapl_uj();

    #ifdef COMPILER_IS_X86
    unsigned int aux;
    unsigned long long c0 = __rdtscp(&aux);
    #endif

    for (int i = 0; i < iterations; i++) {
        auto t0 = std::chrono::high_resolution_clock::now();
        // Client KeyGen
        randombytes_buf(client_sk, sizeof(client_sk));
        crypto_scalarmult_base(client_pk, client_sk);

        // Server KeyGen
        randombytes_buf(server_sk, sizeof(server_sk));
        crypto_scalarmult_base(server_pk, server_sk);

        // Derivazione segreto condiviso (lato Client)
        if (crypto_scalarmult(shared_secret, client_sk, server_pk) == 0) {
            do_not_optimize_away(shared_secret);
        }
        auto t1 = std::chrono::high_resolution_clock::now();

        double s_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        res.sample_times_us.push_back(s_us);
    }

    #ifdef COMPILER_IS_X86
    unsigned long long c1 = __rdtscp(&aux);
    res.total_cycles = (c1 - c0) / iterations;
    #endif

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
    if (sodium_init() < 0) {
        std::cerr << "Errore inizializzazione sodium!\n";
        return 1;
    }

    std::cout << "\n======================================================================================================\n";
    std::cout << " BENCHMARK: KEY MANAGEMENT ROADMAP (PSK -> Symmetric Handshake -> ECC X25519)\n";
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

    const int ITERATIONS = 500; // 500 campioni singoli 1-a-1 senza batching

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
