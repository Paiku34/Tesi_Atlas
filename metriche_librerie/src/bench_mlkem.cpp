#include "benchmark_core.hpp"
#include <oqs/oqs.h>
#include <sodium.h>
#include <fstream>
#include <iomanip>
#include <sstream>

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

void benchmark_kem(const char* alg_name, KeyMgmtResult& res) {
    res.scheme_name = alg_name;
    res.paradigm = "Lattice (PQC)";
    
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (!kem) {
        std::cerr << "Errore: algoritmo non supportato: " << alg_name << "\n";
        return;
    }

    constexpr size_t PSK_TAG_BYTES = 16;
    // GS challenge: nonce + tag. Buoy response: nonce + KEM ciphertext + tag.
    // The Ground Station public key is provisioned before deployment and is not
    // part of the one-way runtime exchange.
    res.exchanged_bytes = 32 + PSK_TAG_BYTES + 32 + kem->length_ciphertext + PSK_TAG_BYTES;

    std::vector<uint8_t> public_key(kem->length_public_key);
    std::vector<uint8_t> secret_key(kem->length_secret_key);
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret_sender(kem->length_shared_secret);
    uint8_t psk[crypto_auth_KEYBYTES];
    randombytes_buf(psk, sizeof(psk));

    // Provision the Ground Station key pair outside the measured operation.
    OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
    do_not_optimize_away(public_key);
    do_not_optimize_away(secret_key);

    uint8_t gs_nonce[32];
    uint8_t gs_tag[crypto_auth_BYTES];
    std::vector<uint8_t> response_data(32 + 32 + kem->length_ciphertext);
    std::vector<uint8_t> gs_auth_data(32 + kem->length_public_key);
    randombytes_buf(gs_nonce, sizeof(gs_nonce));
    memcpy(gs_auth_data.data(), gs_nonce, sizeof(gs_nonce));
    memcpy(gs_auth_data.data() + sizeof(gs_nonce), public_key.data(), kem->length_public_key);
    crypto_auth(gs_tag, gs_auth_data.data(), gs_auth_data.size(), psk);

    const int ITERATIONS = KEY_MGMT_MEASUREMENT_ITERATIONS;

    // One-way operation measured on the buoy only:
    // verify GS PSK challenge, encapsulate, authenticate response, derive key.
    KeyMgmtMeasurement measurement = measure_key_management([&]() {
        uint8_t buoy_nonce[32];
        uint8_t response_tag[crypto_auth_BYTES];
        uint8_t expected_tag[crypto_auth_BYTES];
        uint8_t session_key[32];
        uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];

        crypto_auth(expected_tag, gs_auth_data.data(), gs_auth_data.size(), psk);
        if (sodium_memcmp(gs_tag, expected_tag, PSK_TAG_BYTES) != 0) {
            return;
        }

        randombytes_buf(buoy_nonce, sizeof(buoy_nonce));
        OQS_KEM_encaps(kem, ciphertext.data(), shared_secret_sender.data(), public_key.data());
        memcpy(response_data.data(), gs_nonce, sizeof(gs_nonce));
        memcpy(response_data.data() + 32, buoy_nonce, 32);
        memcpy(response_data.data() + 64, ciphertext.data(), ciphertext.size());
        crypto_auth(response_tag, response_data.data(), response_data.size(), psk);

        crypto_kdf_hkdf_sha256_extract(
            prk, psk, sizeof(psk), shared_secret_sender.data(), shared_secret_sender.size());
        crypto_kdf_hkdf_sha256_expand(
            session_key, sizeof(session_key), "ATLAS_MLKEM", 12, prk);
        do_not_optimize_away(response_tag);
        do_not_optimize_away(session_key);
    }, ITERATIONS);

    res.sample_times_us = std::move(measurement.sample_times_us);
    res.total_us = measurement.mean_us;
    res.total_cycles = measurement.cycles_per_op;
    res.energy_uj = measurement.energy_uj;
    res.ram_kb = get_current_ram_usage_kb();

    OQS_KEM_free(kem);
}

void append_mlkem_to_csv(const std::string& general_csv,
                         const KeyMgmtResult& res) {
    std::ofstream gf(general_csv, std::ios::app);
    if (gf.is_open()) {
        gf.seekp(0, std::ios::end);
        if (gf.tellp() == 0) {
            gf << "category,scheme,paradigm,exchanged_bytes,sample_id,latency_us,cycles,energy_uj,ram_kb\n";
        }
        for (size_t i = 0; i < res.sample_times_us.size(); i++) {
            gf << "key_management,"
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
}

int main() {
    // Warm-up contatori cicli hardware (Linux PMU / x86)
    (void)read_cpu_cycles();

    if (sodium_init() < 0) {
        std::cerr << "Errore inizializzazione sodium!\n";
        return 1;
    }

    std::cout << "\n=======================================================================================================\n";
    std::cout << " BENCHMARK: ML-KEM POST-QUANTUM (liboqs) — ONE-WAY BUOY OPERATION\n";
    std::cout << "=======================================================================================================\n";

    std::vector<const char*> algorithms = {
        OQS_KEM_alg_ml_kem_512,
        OQS_KEM_alg_ml_kem_768,
        OQS_KEM_alg_ml_kem_1024
    };

    std::cout << std::left 
              << "| " << std::setw(14) << "Schema"
              << "| " << std::setw(18) << "Paradigma"
              << "| " << std::setw(14) << "Payload (B)"
              << "| " << std::setw(14) << "Tempo (us)"
              << "| " << std::setw(14) << "Cicli/Op"
              << "| " << std::setw(14) << "Energia (uJ)"
              << "|\n";
    std::cout << "|" << std::string(15, '-')
              << "|" << std::string(19, '-')
              << "|" << std::string(15, '-')
              << "|" << std::string(15, '-')
              << "|" << std::string(15, '-')
              << "|" << std::string(15, '-')
              << "|\n";

    std::string general_csv = get_data_dir() + "key_management_raw.csv";
    for (const char* alg : algorithms) {
        std::cout.flush();
        pid_t pid = fork();
        if (pid == 0) {
            KeyMgmtResult res;
            benchmark_kem(alg, res);

            std::string energy_str = (res.energy_uj > 0) ? std::to_string(res.energy_uj) : "N/A";
            std::cout << std::left 
                      << "| " << std::setw(14) << res.scheme_name
                      << "| " << std::setw(18) << res.paradigm
                      << "| " << std::setw(14) << res.exchanged_bytes
                      << "| " << std::fixed << std::setprecision(2) << std::setw(14) << res.total_us
                      << "| " << std::setw(14) << res.total_cycles
                      << "| " << std::setw(14) << energy_str
                      << "|\n";
            std::cout << "| " << std::setw(14) << res.scheme_name 
                      << "  [Memoria di Processo Peak RSS: " << res.ram_kb << " KB]\n";
            std::cout << "|" << std::string(15, '-')
              << "|" << std::string(19, '-')
              << "|" << std::string(15, '-')
              << "|" << std::string(15, '-')
              << "|" << std::string(15, '-')
              << "|" << std::string(15, '-')
              << "|\n";
            std::cout.flush();

            append_mlkem_to_csv(general_csv, res);
            _exit(0);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        } else {
            std::cerr << "Errore fork() per " << alg << "\n";
        }
    }

    std::cout << "\n  Dati one-way ML-KEM salvati in: " << general_csv << "\n\n";

    return 0;
}
