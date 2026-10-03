#include "benchmark_core.hpp"
#include <oqs/oqs.h>
#include <fstream>

struct KemBenchmarkResult {
    std::string alg_name;
    size_t pk_bytes;
    size_t ct_bytes;
    size_t total_exchanged_bytes;
    int num_anep96_frames;
    
    double keygen_us = 0.0;
    unsigned long long keygen_cycles = 0;
    
    double encaps_us = 0.0;
    unsigned long long encaps_cycles = 0;
    
    double decaps_us = 0.0;
    unsigned long long decaps_cycles = 0;

    std::string energy_encaps_uj_str = "N/A";
    std::string energy_decaps_uj_str = "N/A";
    double total_energy_uj = -1.0;
    long ram_kb = 0;

    std::vector<double> sample_times_us;
};

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
    res.num_anep96_frames = (res.total_exchanged_bytes + 254) / 255;

    std::vector<uint8_t> public_key(kem->length_public_key);
    std::vector<uint8_t> secret_key(kem->length_secret_key);
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret_sender(kem->length_shared_secret);
    std::vector<uint8_t> shared_secret_receiver(kem->length_shared_secret);

    const int ITERATIONS = 500;

    // 1. KEYGEN BENCHMARK
    auto t0 = std::chrono::high_resolution_clock::now();
    #ifdef COMPILER_IS_X86
    unsigned int aux;
    unsigned long long c0 = __rdtscp(&aux);
    #endif
    for (int i = 0; i < ITERATIONS; i++) {
        OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
        do_not_optimize_away(public_key);
        do_not_optimize_away(secret_key);
    }
    #ifdef COMPILER_IS_X86
    unsigned long long c1 = __rdtscp(&aux);
    res.keygen_cycles = (c1 - c0) / ITERATIONS;
    #endif
    auto t1 = std::chrono::high_resolution_clock::now();
    res.keygen_us = std::chrono::duration<double, std::micro>(t1 - t0).count() / ITERATIONS;

    // ENCAPSULATION
    long long energy_start = read_intel_rapl_uj();

    t0 = std::chrono::high_resolution_clock::now();
    #ifdef COMPILER_IS_X86
    c0 = __rdtscp(&aux);
    #endif
    for (int i = 0; i < ITERATIONS; i++) {
        OQS_KEM_encaps(kem, ciphertext.data(), shared_secret_sender.data(), public_key.data());
        do_not_optimize_away(ciphertext);
        do_not_optimize_away(shared_secret_sender);
    }
    #ifdef COMPILER_IS_X86
    c1 = __rdtscp(&aux);
    res.encaps_cycles = (c1 - c0) / ITERATIONS;
    #endif
    t1 = std::chrono::high_resolution_clock::now();
    
    long long energy_end = read_intel_rapl_uj();

    res.encaps_us = std::chrono::duration<double, std::micro>(t1 - t0).count() / ITERATIONS;

    double e_enc = -1.0;
    if (energy_start != -1 && energy_end >= energy_start) {
        e_enc = (double)(energy_end - energy_start) / ITERATIONS;
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << e_enc;
        res.energy_encaps_uj_str = ss.str();
    }

    // DECAPSULATION
    long long energy_decaps_start = read_intel_rapl_uj();

    t0 = std::chrono::high_resolution_clock::now();
    #ifdef COMPILER_IS_X86
    c0 = __rdtscp(&aux);
    #endif
    for (int i = 0; i < ITERATIONS; i++) {
        OQS_KEM_decaps(kem, shared_secret_receiver.data(),
                       ciphertext.data(), secret_key.data());
        do_not_optimize_away(shared_secret_receiver);
    }
    #ifdef COMPILER_IS_X86
    c1 = __rdtscp(&aux);
    res.decaps_cycles = (c1 - c0) / ITERATIONS;
    #endif
    t1 = std::chrono::high_resolution_clock::now();

    long long energy_decaps_end = read_intel_rapl_uj();

    res.decaps_us = std::chrono::duration<double, std::micro>(t1 - t0).count() / ITERATIONS;

    double e_dec = -1.0;
    if (energy_decaps_start != -1 && energy_decaps_end >= energy_decaps_start) {
        e_dec = (double)(energy_decaps_end - energy_decaps_start) / ITERATIONS;
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << e_dec;
        res.energy_decaps_uj_str = ss.str();
    }

    if (e_enc >= 0 && e_dec >= 0) {
        res.total_energy_uj = e_enc + e_dec;
    }

    res.sample_times_us.clear();
    res.sample_times_us.reserve(ITERATIONS);
    for (int i = 0; i < ITERATIONS; i++) {
        auto sb_t0 = std::chrono::high_resolution_clock::now();
        OQS_KEM_encaps(kem, ciphertext.data(), shared_secret_sender.data(), public_key.data());
        do_not_optimize_away(ciphertext);
        OQS_KEM_decaps(kem, shared_secret_receiver.data(), ciphertext.data(), secret_key.data());
        do_not_optimize_away(shared_secret_receiver);
        auto sb_t1 = std::chrono::high_resolution_clock::now();
        double sample_us = std::chrono::duration<double, std::micro>(sb_t1 - sb_t0).count();
        res.sample_times_us.push_back(sample_us);
    }

    res.ram_kb = get_current_ram_usage_kb();

    OQS_KEM_free(kem);
}

void append_mlkem_samples_to_csv(const std::string& filename, const KemBenchmarkResult& res) {
    std::ofstream file(filename, std::ios::app);
    if (!file.is_open()) return;
    file.seekp(0, std::ios::end);
    if (file.tellp() == 0) {
        file << "category,scheme,paradigm,exchanged_bytes,anep_frames,sample_id,latency_us,cycles,energy_uj,ram_kb\n";
    }
    for (size_t i = 0; i < res.sample_times_us.size(); i++) {
        file << "key_management,"
             << "\"" << res.alg_name << "\","
             << "\"Lattice (PQC)\","
             << res.total_exchanged_bytes << ","
             << res.num_anep96_frames << ","
             << i + 1 << ","
             << std::fixed << std::setprecision(4) << res.sample_times_us[i] << ","
             << (res.encaps_cycles + res.decaps_cycles) << ","
             << std::fixed << std::setprecision(3) << res.total_energy_uj << ","
             << res.ram_kb << "\n";
    }
}

int main() {
    std::cout << "\n======================================================================================================\n";
    std::cout << " BENCHMARK: ML-KEM POST-QUANTUM (liboqs)\n";
    std::cout << "======================================================================================================\n";

    std::vector<const char*> algorithms = {
        OQS_KEM_alg_ml_kem_512,
        OQS_KEM_alg_ml_kem_768,
        OQS_KEM_alg_ml_kem_1024
    };

    std::cout << std::left 
              << "| " << std::setw(12) << "Variante"
              << "| " << std::setw(16) << "Key+CT (B)"
              << "| " << std::setw(7)  << "Frames"
              << "| " << std::setw(10) << "KGen(us)"
              << "| " << std::setw(10) << "Enc(us)"
              << "| " << std::setw(10) << "Dec(us)"
              << "| " << std::setw(10) << "Enc Cyc"
              << "| " << std::setw(10) << "Dec Cyc"
              << "| " << std::setw(10) << "E_enc(uJ)"
              << "| " << std::setw(10) << "E_dec(uJ)"
              << "| " << std::setw(8) << "RSS(KB)"
              << "|\n";
    std::cout << "|" << std::string(13, '-')
              << "|" << std::string(18, '-')
              << "|" << std::string(9, '-')
              << "|" << std::string(12, '-')
              << "|" << std::string(12, '-')
              << "|" << std::string(12, '-')
              << "|" << std::string(12, '-')
              << "|" << std::string(12, '-')
              << "|" << std::string(12, '-')
              << "|" << std::string(12, '-')
              << "|" << std::string(10, '-')
              << "|\n";

    std::string csv_file = get_data_dir() + "key_management_raw.csv";

    for (const char* alg : algorithms) {
        std::cout.flush();
        pid_t pid = fork();
        if (pid == 0) {
            KemBenchmarkResult res;
            benchmark_kem(alg, res);

            std::string bytes_str = std::to_string(res.pk_bytes) + "+" + std::to_string(res.ct_bytes);

            std::cout << std::left 
                      << "| " << std::setw(12) << res.alg_name
                      << "| " << std::setw(16) << bytes_str
                      << "| " << std::setw(7)  << res.num_anep96_frames
                      << "| " << std::fixed << std::setprecision(2)
                      << std::setw(10) << res.keygen_us
                      << "| " << std::setw(10) << res.encaps_us
                      << "| " << std::setw(10) << res.decaps_us
                      << "| " << std::setw(10) << res.encaps_cycles
                      << "| " << std::setw(10) << res.decaps_cycles
                      << "| " << std::setw(10) << res.energy_encaps_uj_str
                      << "| " << std::setw(10) << res.energy_decaps_uj_str
                      << "| " << std::setw(8)  << res.ram_kb
                      << "|\n";
            std::cout.flush();
            append_mlkem_samples_to_csv(csv_file, res);
            _exit(0);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        } else {
            std::cerr << "Errore fork() per " << alg << "\n";
        }
    }

    std::cout << "\n  Frames ANEP = ceil(Key+CT / 255 B) — pacchetti radio necessari a 9600 bps\n\n";

    return 0;
}

