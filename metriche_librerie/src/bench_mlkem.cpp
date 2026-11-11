#include "benchmark_core.hpp"
#include <oqs/oqs.h>
#include <sodium.h>
#include <fstream>
#include <iomanip>
#include <sstream>

struct KemMeasurement {
    std::string phase_name;
    size_t payload_bytes = 0;
    std::string payload_desc;

    double mean_us = 0.0;
    unsigned long long cycles = 0;
    double energy_uj = -1.0;
    std::string energy_uj_str = "N/A";
    std::vector<double> sample_times_us;
};

struct KemBenchmarkResult {
    std::string alg_name;
    size_t pk_bytes = 0;
    size_t ct_bytes = 0;
    size_t total_exchanged_bytes = 0;
    long ram_kb = 0;

    KemMeasurement one_way; // PSK auth + Encaps + KDF on the buoy
};

template <typename Func>
void measure_one_way_kem(KemMeasurement& pr, int iterations, Func&& func) {
    // Warm-up
    for (int i = 0; i < KEY_MGMT_WARMUP_ITERATIONS; i++) {
        func();
    }

    pr.sample_times_us.clear();
    pr.sample_times_us.reserve(iterations);

    long long energy_start = read_intel_rapl_uj();

    unsigned long long c0 = read_cpu_cycles();

    for (int i = 0; i < iterations; i++) {
        auto t0 = std::chrono::high_resolution_clock::now();
        func();
        auto t1 = std::chrono::high_resolution_clock::now();
        double sample_us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        pr.sample_times_us.push_back(sample_us);
    }

    unsigned long long c1 = read_cpu_cycles();
    pr.cycles = (c1 >= c0) ? ((c1 - c0) / iterations) : 0;

    long long energy_end = read_intel_rapl_uj();
    if (energy_start != -1 && energy_end >= energy_start) {
        pr.energy_uj = (double)(energy_end - energy_start) / iterations;
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << pr.energy_uj;
        pr.energy_uj_str = ss.str();
    }

    double sum = 0.0;
    for (double v : pr.sample_times_us) sum += v;
    pr.mean_us = sum / iterations;
}

void benchmark_kem(const char* alg_name, KemBenchmarkResult& res) {
    res.alg_name = alg_name;
    
    OQS_KEM *kem = OQS_KEM_new(alg_name);
    if (!kem) {
        std::cerr << "Errore: algoritmo non supportato: " << alg_name << "\n";
        return;
    }

    res.pk_bytes = kem->length_public_key;
    res.ct_bytes = kem->length_ciphertext;
    constexpr size_t PSK_TAG_BYTES = 16;
    // GS challenge: nonce + tag. Buoy response: nonce + KEM ciphertext + tag.
    // The Ground Station public key is provisioned before deployment and is not
    // part of the one-way runtime exchange.
    res.total_exchanged_bytes = 32 + PSK_TAG_BYTES + 32 + res.ct_bytes + PSK_TAG_BYTES;

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
    res.one_way.phase_name = "OneWay_Encapsulation";
    res.one_way.payload_bytes = res.total_exchanged_bytes;
    res.one_way.payload_desc = std::to_string(res.ct_bytes) + " B CT + PSK auth";
    measure_one_way_kem(res.one_way, ITERATIONS, [&]() {
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
    });

    res.ram_kb = get_current_ram_usage_kb();

    OQS_KEM_free(kem);
}

void append_mlkem_to_csv(const std::string& general_csv,
                         const KemBenchmarkResult& res) {
    {
        std::ofstream gf(general_csv, std::ios::app);
        if (gf.is_open()) {
            gf.seekp(0, std::ios::end);
            if (gf.tellp() == 0) {
                gf << "category,scheme,paradigm,exchanged_bytes,sample_id,latency_us,cycles,energy_uj,ram_kb\n";
            }
            for (size_t i = 0; i < res.one_way.sample_times_us.size(); i++) {
                gf << "key_management,"
                   << "\"" << res.alg_name << "\","
                   << "\"Lattice (PQC)\","
                   << res.total_exchanged_bytes << ","
                   << i + 1 << ","
                   << std::fixed << std::setprecision(4) << res.one_way.sample_times_us[i] << ","
                   << res.one_way.cycles << ","
                   << std::fixed << std::setprecision(3) << res.one_way.energy_uj << ","
                   << res.ram_kb << "\n";
            }
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
              << "| " << std::setw(12) << "Variante"
              << "| " << std::setw(17) << "Fase"
              << "| " << std::setw(18) << "Payload"
              << "| " << std::setw(12) << "Tempo(us)"
              << "| " << std::setw(12) << "Cicli/Op"
              << "| " << std::setw(12) << "Energia(uJ)"
              << "|\n";
    std::cout << "|" << std::string(13, '-')
              << "|" << std::string(18, '-')
              << "|" << std::string(19, '-')
              << "|" << std::string(13, '-')
              << "|" << std::string(13, '-')
              << "|" << std::string(13, '-')
              << "|\n";

    std::string general_csv = get_data_dir() + "key_management_raw.csv";
    for (const char* alg : algorithms) {
        std::cout.flush();
        pid_t pid = fork();
        if (pid == 0) {
            KemBenchmarkResult res;
            benchmark_kem(alg, res);

            const auto& measurement = res.one_way;
            std::cout << std::left
                      << "| " << std::setw(12) << res.alg_name
                      << "| " << std::setw(17) << measurement.phase_name
                      << "| " << std::setw(18) << measurement.payload_desc
                      << "| " << std::fixed << std::setprecision(2) << std::setw(12) << measurement.mean_us
                      << "| " << std::setw(12) << measurement.cycles
                      << "| " << std::setw(12) << measurement.energy_uj_str
                      << "|\n";
            std::cout << "| " << std::setw(12) << res.alg_name 
                      << "  [Memoria di Processo Peak RSS: " << res.ram_kb << " KB]\n";
            std::cout << "|" << std::string(13, '-')
                      << "|" << std::string(18, '-')
                      << "|" << std::string(19, '-')
                      << "|" << std::string(13, '-')
                      << "|" << std::string(13, '-')
                      << "|" << std::string(13, '-')
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
