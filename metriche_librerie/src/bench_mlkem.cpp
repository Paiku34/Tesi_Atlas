#include "benchmark_core.hpp"
#include <oqs/oqs.h>
#include <fstream>
#include <iomanip>
#include <sstream>

struct KemPhaseResult {
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

    KemPhaseResult keygen;
    KemPhaseResult encaps;
    KemPhaseResult decaps;
    KemPhaseResult handshake; // Full Ephemeral Handshake (KeyGen + Encaps + Decaps)
};

template <typename Func>
void benchmark_phase(KemPhaseResult& pr, int iterations, Func&& func) {
    // Warm-up
    for (int i = 0; i < 20; i++) {
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
    res.total_exchanged_bytes = res.pk_bytes + res.ct_bytes;

    std::vector<uint8_t> public_key(kem->length_public_key);
    std::vector<uint8_t> secret_key(kem->length_secret_key);
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret_sender(kem->length_shared_secret);
    std::vector<uint8_t> shared_secret_receiver(kem->length_shared_secret);

    const int ITERATIONS = 500;

    // 1. KeyGen (generazione coppia chiavi)
    res.keygen.phase_name = "KeyGen";
    res.keygen.payload_bytes = res.pk_bytes;
    res.keygen.payload_desc = std::to_string(res.pk_bytes) + " B (PK)";
    benchmark_phase(res.keygen, ITERATIONS, [&]() {
        OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
        do_not_optimize_away(public_key);
        do_not_optimize_away(secret_key);
    });

    // 2. Encapsulation (cifratura / incapsulamento segreto)
    res.encaps.phase_name = "Encapsulation";
    res.encaps.payload_bytes = res.ct_bytes;
    res.encaps.payload_desc = std::to_string(res.ct_bytes) + " B (CT)";
    benchmark_phase(res.encaps, ITERATIONS, [&]() {
        OQS_KEM_encaps(kem, ciphertext.data(), shared_secret_sender.data(), public_key.data());
        do_not_optimize_away(ciphertext);
        do_not_optimize_away(shared_secret_sender);
    });

    // 3. Decapsulation (decifratura segreto da ciphertext)
    res.decaps.phase_name = "Decapsulation";
    res.decaps.payload_bytes = 0;
    res.decaps.payload_desc = "0 B (internal)";
    benchmark_phase(res.decaps, ITERATIONS, [&]() {
        OQS_KEM_decaps(kem, shared_secret_receiver.data(), ciphertext.data(), secret_key.data());
        do_not_optimize_away(shared_secret_receiver);
    });

    // 4. Handshake Completo Effimero (KeyGen + Encaps + Decaps)
    res.handshake.phase_name = "Handshake_Total";
    res.handshake.payload_bytes = res.total_exchanged_bytes;
    res.handshake.payload_desc = std::to_string(res.pk_bytes) + "+" + std::to_string(res.ct_bytes) + " B";
    benchmark_phase(res.handshake, ITERATIONS, [&]() {
        OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
        do_not_optimize_away(public_key);
        do_not_optimize_away(secret_key);

        OQS_KEM_encaps(kem, ciphertext.data(), shared_secret_sender.data(), public_key.data());
        do_not_optimize_away(ciphertext);
        do_not_optimize_away(shared_secret_sender);

        OQS_KEM_decaps(kem, shared_secret_receiver.data(), ciphertext.data(), secret_key.data());
        do_not_optimize_away(shared_secret_receiver);
    });

    res.ram_kb = get_current_ram_usage_kb();

    OQS_KEM_free(kem);
}

void append_mlkem_to_csvs(const std::string& general_csv, 
                          const std::string& breakdown_csv, 
                          const KemBenchmarkResult& res) {
    // 1. Salva Handshake Completo nel CSV generale di Key Management (per grafici globali)
    {
        std::ofstream gf(general_csv, std::ios::app);
        if (gf.is_open()) {
            gf.seekp(0, std::ios::end);
            if (gf.tellp() == 0) {
                gf << "category,scheme,paradigm,exchanged_bytes,sample_id,latency_us,cycles,energy_uj,ram_kb\n";
            }
            for (size_t i = 0; i < res.handshake.sample_times_us.size(); i++) {
                gf << "key_management,"
                   << "\"" << res.alg_name << "\","
                   << "\"Lattice (PQC)\","
                   << res.total_exchanged_bytes << ","
                   << i + 1 << ","
                   << std::fixed << std::setprecision(4) << res.handshake.sample_times_us[i] << ","
                   << res.handshake.cycles << ","
                   << std::fixed << std::setprecision(3) << res.handshake.energy_uj << ","
                   << res.ram_kb << "\n";
            }
        }
    }

    // 2. Salva TUTTE le fasi granulari nel CSV di Breakdown dedicato (senza frame né RAM ripetuta)
    {
        std::ofstream bf(breakdown_csv, std::ios::app);
        if (bf.is_open()) {
            bf.seekp(0, std::ios::end);
            if (bf.tellp() == 0) {
                bf << "variant,phase,payload_bytes,sample_id,latency_us,cycles,energy_uj\n";
            }
            const KemPhaseResult* phases[] = { &res.keygen, &res.encaps, &res.decaps, &res.handshake };
            for (const auto* p : phases) {
                for (size_t i = 0; i < p->sample_times_us.size(); i++) {
                    bf << "\"" << res.alg_name << "\","
                       << "\"" << p->phase_name << "\","
                       << p->payload_bytes << ","
                       << i + 1 << ","
                       << std::fixed << std::setprecision(4) << p->sample_times_us[i] << ","
                       << p->cycles << ","
                       << std::fixed << std::setprecision(3) << p->energy_uj << "\n";
                }
            }
        }
    }
}

int main() {
    std::cout << "\n=======================================================================================================\n";
    std::cout << " BENCHMARK: ML-KEM POST-QUANTUM (liboqs) — FASI GRANULARI & HANDSHAKE COMPLETO\n";
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
    std::string breakdown_csv = get_data_dir() + "mlkem_breakdown_raw.csv";

    // Inizializza/Sovrascrivi CSV breakdown a inizio run
    {
        std::ofstream bf(breakdown_csv);
        bf << "variant,phase,payload_bytes,sample_id,latency_us,cycles,energy_uj\n";
    }

    for (const char* alg : algorithms) {
        std::cout.flush();
        pid_t pid = fork();
        if (pid == 0) {
            KemBenchmarkResult res;
            benchmark_kem(alg, res);

            const KemPhaseResult* phases[] = { &res.keygen, &res.encaps, &res.decaps, &res.handshake };
            for (const auto* p : phases) {
                std::cout << std::left 
                          << "| " << std::setw(12) << res.alg_name
                          << "| " << std::setw(17) << p->phase_name
                          << "| " << std::setw(18) << p->payload_desc
                          << "| " << std::fixed << std::setprecision(2) << std::setw(12) << p->mean_us
                          << "| " << std::setw(12) << p->cycles
                          << "| " << std::setw(12) << p->energy_uj_str
                          << "|\n";
            }
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

            append_mlkem_to_csvs(general_csv, breakdown_csv, res);
            _exit(0);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        } else {
            std::cerr << "Errore fork() per " << alg << "\n";
        }
    }

    std::cout << "\n  Dati granulari salvati in: " << breakdown_csv << "\n\n";

    return 0;
}
