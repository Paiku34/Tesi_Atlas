#include "benchmark_core.hpp"
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>
#include <fstream>

struct KeyMgmtResult {
    std::string scheme_name;
    std::string paradigm;
    size_t exchanged_bytes;
    
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
    res.exchanged_bytes = 32; // 32 B salt/nonce

    uint8_t psk[crypto_kdf_KEYBYTES];
    randombytes_buf(psk, sizeof(psk));
    uint8_t session_key[32];
    uint8_t salt[32];

    // Warm-up
    for (int i = 0; i < 50; i++) {
        randombytes_buf(salt, sizeof(salt));
        crypto_kdf_derive_from_key(session_key, sizeof(session_key), (uint64_t)i, "ATLAS_KM", psk);
        asm volatile("" : : "r"(session_key) : "memory");
    }

    res.sample_times_us.clear();
    res.sample_times_us.reserve(iterations);

    long long energy_start = read_intel_rapl_uj();

    #ifdef COMPILER_IS_X86
    unsigned int aux;
    unsigned long long c0 = __rdtscp(&aux);
    #endif

    for (int i = 0; i < iterations; i++) {
        randombytes_buf(salt, sizeof(salt));
        uint64_t subkey_id = (uint64_t)i;
        
        auto t0 = std::chrono::high_resolution_clock::now();
        crypto_kdf_derive_from_key(session_key, sizeof(session_key), subkey_id, "ATLAS_KM", psk);
        asm volatile("" : : "r"(session_key) : "memory");
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
// 2. PSK + HKDF-SHA256 (OpenSSL)
// -----------------------------------------------------------------------------
void benchmark_psk_hkdf_openssl(KeyMgmtResult& res, int iterations) {
    res.scheme_name = "PSK + HKDF (OpenSSL)";
    res.paradigm = "Symmetric Pre-Shared";
    res.exchanged_bytes = 32; // 32 B salt/nonce

    uint8_t psk[32];
    RAND_bytes(psk, sizeof(psk));
    uint8_t salt[32];
    uint8_t session_key[32];
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);

    // Warm-up
    for (int i = 0; i < 50; i++) {
        RAND_bytes(salt, sizeof(salt));
        EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
        OSSL_PARAM params[5];
        char digest[] = "SHA256";
        char info[] = "ATLAS_SONOBUOY_V1";
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, sizeof(digest));
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, psk, sizeof(psk));
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof(salt));
        params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, sizeof(info));
        params[4] = OSSL_PARAM_construct_end();
        EVP_KDF_derive(kctx, session_key, sizeof(session_key), params);
        EVP_KDF_CTX_free(kctx);
        asm volatile("" : : "r"(session_key) : "memory");
    }

    res.sample_times_us.clear();
    res.sample_times_us.reserve(iterations);

    long long energy_start = read_intel_rapl_uj();

    #ifdef COMPILER_IS_X86
    unsigned int aux;
    unsigned long long c0 = __rdtscp(&aux);
    #endif

    for (int i = 0; i < iterations; i++) {
        RAND_bytes(salt, sizeof(salt));
        
        auto t0 = std::chrono::high_resolution_clock::now();
        EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
        
        OSSL_PARAM params[5];
        char digest[] = "SHA256";
        char info[] = "ATLAS_SONOBUOY_V1";
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, sizeof(digest));
        params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, psk, sizeof(psk));
        params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, sizeof(salt));
        params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, sizeof(info));
        params[4] = OSSL_PARAM_construct_end();

        EVP_KDF_derive(kctx, session_key, sizeof(session_key), params);
        EVP_KDF_CTX_free(kctx);
        asm volatile("" : : "r"(session_key) : "memory");
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
    if (kdf) EVP_KDF_free(kdf);
}

// -----------------------------------------------------------------------------
// 3. Symmetric 2-Way Handshake (Challenge-Response + Key Confirmation)
// -----------------------------------------------------------------------------
void benchmark_symmetric_handshake(KeyMgmtResult& res, int iterations) {
    res.scheme_name = "Symmetric Handshake";
    res.paradigm = "Symmetric 2-Way Auth";
    res.exchanged_bytes = 80;

    uint8_t psk[32];
    randombytes_buf(psk, sizeof(psk));
    uint8_t nc[32], ns[32], tag[16], session_key[32];

    // Warm-up
    for (int i = 0; i < 50; i++) {
        randombytes_buf(nc, sizeof(nc));
        randombytes_buf(ns, sizeof(ns));
        crypto_auth(tag, nc, sizeof(nc), psk);
        if (crypto_auth_verify(tag, nc, sizeof(nc), psk) == 0) {
            crypto_kdf_derive_from_key(session_key, sizeof(session_key), 1, "ATLAS_SH", psk);
        }
        asm volatile("" : : "r"(session_key) : "memory");
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
        // 1. Client genera Nonce client
        randombytes_buf(nc, sizeof(nc));
        
        // 2. Server genera Nonce server e calcola Tag su nc
        randombytes_buf(ns, sizeof(ns));
        crypto_auth(tag, nc, sizeof(nc), psk);
        
        // 3. Client verifica Tag
        if (crypto_auth_verify(tag, nc, sizeof(nc), psk) == 0) {
            // 4. Entrambi derivano chiave di sessione
            crypto_kdf_derive_from_key(session_key, sizeof(session_key), 1, "ATLAS_SH", psk);
        }
        asm volatile("" : : "r"(session_key) : "memory");
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
// 4. ECC X25519 (ECDH - Libsodium)
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
            asm volatile("" : : "r"(shared_secret) : "memory");
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
// 5. ECC X25519 (ECDH - OpenSSL)
// -----------------------------------------------------------------------------
void benchmark_x25519_openssl(KeyMgmtResult& res, int iterations) {
    res.scheme_name = "ECDH X25519 (OpenSSL)";
    res.paradigm = "Classical (ECC)";
    res.exchanged_bytes = 64; // 32B + 32B

    // Warm-up
    for (int i = 0; i < 20; i++) {
        EVP_PKEY *client_key = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
        EVP_PKEY *server_key = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_key, NULL);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, server_key);
        size_t secret_len = 32;
        uint8_t secret[32];
        EVP_PKEY_derive(ctx, secret, &secret_len);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(client_key);
        EVP_PKEY_free(server_key);
        asm volatile("" : : "r"(secret) : "memory");
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
        EVP_PKEY *client_key = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
        EVP_PKEY *server_key = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(client_key, NULL);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, server_key);

        size_t secret_len = 32;
        uint8_t secret[32];
        EVP_PKEY_derive(ctx, secret, &secret_len);

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(client_key);
        EVP_PKEY_free(server_key);

        asm volatile("" : : "r"(secret) : "memory");
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
    std::cout << " BENCHMARK: KEY MANAGEMENT ROADMAP (PSK -> Symmetric -> ECC X25519)\n";
    std::cout << " Tesi: Secure Sonobuoy Telemetry (NATO ANEP-96 Radio Constrained)\n";
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
    run_and_print(benchmark_psk_hkdf_openssl);
    run_and_print(benchmark_symmetric_handshake);
    run_and_print(benchmark_x25519_libsodium);
    run_and_print(benchmark_x25519_openssl);

    std::cout << "\n  Frames ANEP = ceil(Scambiati / 255 B) a 9600 bps\n";
    std::cout << "  Dati grezzi esportati con successo in: " << csv_file << "\n\n";

    return 0;
}
