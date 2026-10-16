#ifndef BENCHMARK_CORE_HPP
#define BENCHMARK_CORE_HPP

#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <string>
#include <memory>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <fstream>

#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <x86intrin.h>
#define COMPILER_IS_X86
#endif

#if defined(__linux__) && defined(__aarch64__)
#include <linux/perf_event.h>
#include <sys/syscall.h>
#endif

// Lettura unificata dei cicli CPU hardware per x86_64 e ARMv8 (Cortex-A / Raspberry Pi)
inline unsigned long long read_cpu_cycles() {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    unsigned int aux;
    return __rdtscp(&aux);
#elif defined(__linux__) && defined(__aarch64__)
    static int perf_fd = -2;
    static pid_t last_pid = 0;
    pid_t current_pid = getpid();

    if (perf_fd == -2 || current_pid != last_pid) {
        if (perf_fd >= 0) {
            close(perf_fd);
        }
        last_pid = current_pid;

        struct perf_event_attr pe;
        memset(&pe, 0, sizeof(struct perf_event_attr));
        pe.type = PERF_TYPE_HARDWARE;
        pe.size = sizeof(struct perf_event_attr);
        pe.config = PERF_COUNT_HW_CPU_CYCLES;
        pe.disabled = 0;
        pe.exclude_kernel = 1;
        pe.exclude_hv = 1;
        perf_fd = (int)syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    }
    if (perf_fd >= 0) {
        unsigned long long count = 0;
        if (read(perf_fd, &count, sizeof(count)) == sizeof(count)) {
            return count;
        }
    }
    // Fallback: ARMv8 Generic Timer (cntvct_el0)
    uint64_t val;
    asm volatile("isb; mrs %0, cntvct_el0" : "=r"(val));
    return (unsigned long long)val;
#elif defined(__aarch64__)
    uint64_t val;
    asm volatile("isb; mrs %0, cntvct_el0" : "=r"(val));
    return (unsigned long long)val;
#else
    return 0ULL;
    #endif
}

class ICryptoAlgorithm {
public:
    virtual ~ICryptoAlgorithm() = default;
    virtual std::string get_name() const = 0;
    virtual size_t get_fixed_overhead() const = 0;
    virtual void process(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext) = 0;
};

// Misura il Max Resident Set Size del processo Linux (RAM)
inline long get_current_ram_usage_kb() {
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    return usage.ru_maxrss;
}

// Lettura del sensore hardware Intel RAPL per l'energia fisica reale
inline long long read_intel_rapl_uj() {
    FILE* fp = fopen("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj", "r");
    if (!fp) return -1; // Sensore non trovato o bloccato dalla Macchina Virtuale
    long long energy_uj = 0;
    if (fscanf(fp, "%lld", &energy_uj) != 1) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return energy_uj; // Ritorna l'energia reale in microJoule
}

// Barriera per bloccare le ottimizzazioni aggressive del compilatore (-O3)
template <typename T>
inline void do_not_optimize_away(const T& val) {
    asm volatile("" : : "g"(val) : "memory");
}

inline std::string get_data_dir() {
    if (access("data", F_OK) == 0) return "data/";
    if (access("../data", F_OK) == 0) return "../data/";
    return "./";
}

inline void append_bulk_sample_to_csv(const std::string& algo_name, size_t size, size_t added_bytes, 
                                      int sample_id, double latency_us, unsigned long long cycles_per_op, 
                                      double cycles_per_byte, double energy_uj, long ram_kb) {
    std::string csv_path = get_data_dir() + "bulk_encryption_raw.csv";
    std::ofstream csv(csv_path, std::ios::app);
    if (!csv.is_open()) return;
    csv.seekp(0, std::ios::end);
    if (csv.tellp() == 0) {
        csv << "algorithm,payload_bytes,added_bytes,sample_id,latency_us,cycles_per_op,cycles_per_byte,energy_uj,ram_kb\n";
    }
    csv << "\"" << algo_name << "\","
        << size << ","
        << added_bytes << ","
        << sample_id << ","
        << std::fixed << std::setprecision(4) << latency_us << ","
        << cycles_per_op << ","
        << std::fixed << std::setprecision(2) << cycles_per_byte << ","
        << std::fixed << std::setprecision(3) << energy_uj << ","
        << ram_kb << "\n";
}

inline void run_benchmark_suite(ICryptoAlgorithm* algo, const std::vector<size_t>& packet_sizes) {
    std::cout << "\n======================================================================================================\n";
    std::cout << " ALGORITMO: " << algo->get_name() << "\n";
    std::cout << "======================================================================================================\n";
    
    bool rapl_available = (read_intel_rapl_uj() != -1);
    if (!rapl_available) {
        std::cout << "\033[33m[WARNING] RAPL non disponibile (WSL/VM). Energia segnata come N/A.\033[0m\n\n";
    }

    std::cout << std::left 
              << "| " << std::setw(10) << "Payload" 
              << "| " << std::setw(10) << "Overhead" 
              << "| " << std::setw(12) << "Time (us)" 
              << "| " << std::setw(12) << "Cycles/Op" 
              << "| " << std::setw(12) << "Cycles/Byte"
              << "| " << std::setw(14) << "Energy (uJ)"
              << "|\n";
    std::cout << "|" << std::string(11, '-') << "|" << std::string(12, '-') << "|" << std::string(14, '-') << "|" << std::string(14, '-') << "|" << std::string(14, '-') << "|" << std::string(16, '-') << "|\n";

    // Warm-up dei contatori di ciclo (inizializza perf_event_open prima del cronometro)
    (void)read_cpu_cycles();

    for (size_t size : packet_sizes) {
        std::vector<uint8_t> payload(size, 0x42);
        std::vector<uint8_t> ciphertext;

        // --- FASE 1: WARM-UP (Riscaldamento) ---
        for (int i = 0; i < 100; i++) {
            algo->process(payload, ciphertext);
            do_not_optimize_away(ciphertext);
        }

        // --- FASE 2: MISURAZIONE REALE ---
        long long energy_start = 0, energy_end = 0;
        
        if (rapl_available) {
            energy_start = read_intel_rapl_uj();
        }
        unsigned long long start_cycles = read_cpu_cycles();
        auto start_time = std::chrono::high_resolution_clock::now();

        const int MEASUREMENT_ITERATIONS = 5000;
        std::vector<double> sample_latencies;
        sample_latencies.reserve(MEASUREMENT_ITERATIONS);

        for (int i = 0; i < MEASUREMENT_ITERATIONS; i++) {
            auto s_start = std::chrono::high_resolution_clock::now();
            algo->process(payload, ciphertext);
            do_not_optimize_away(ciphertext);
            auto s_end = std::chrono::high_resolution_clock::now();

            double s_us = std::chrono::duration<double, std::micro>(s_end - s_start).count();
            sample_latencies.push_back(s_us);
        }

        auto end_time = std::chrono::high_resolution_clock::now();
        unsigned long long end_cycles = read_cpu_cycles();

        if (rapl_available) {
            energy_end = read_intel_rapl_uj();
        }

        unsigned long long total_cycles = (end_cycles >= start_cycles) ? ((end_cycles - start_cycles) / MEASUREMENT_ITERATIONS) : 0;
        std::chrono::duration<double, std::micro> elapsed = (end_time - start_time) / (double)MEASUREMENT_ITERATIONS;
        double elapsed_us = elapsed.count();

        double cycles_per_byte = (size > 0) ? ((double)total_cycles / size) : 0.0;
        size_t added_bytes = ciphertext.size() - payload.size();

        double energy_val = -1.0;
        std::string energy_str = "N/A";
        if (rapl_available && energy_end >= energy_start) {
            energy_val = (double)(energy_end - energy_start) / MEASUREMENT_ITERATIONS;
            std::stringstream ss;
            ss << std::fixed << std::setprecision(2) << energy_val;
            energy_str = ss.str();
        }

        std::cout << std::left 
                  << "| " << std::setw(10) << (std::to_string(size) + " B")
                  << "| " << std::setw(10) << ("+" + std::to_string(added_bytes) + " B")
                  << "| " << std::fixed << std::setprecision(2) << std::setw(12) << elapsed_us
                  << "| " << std::setw(12) << total_cycles
                  << "| " << std::setw(12) << cycles_per_byte
                  << "| " << std::setw(14) << energy_str
                  << "|\n";

        long current_ram = get_current_ram_usage_kb();

        for (size_t s = 0; s < sample_latencies.size(); s++) {
            append_bulk_sample_to_csv(algo->get_name(), size, added_bytes, (int)(s + 1), 
                                      sample_latencies[s], total_cycles, cycles_per_byte, energy_val, current_ram);
        }
    }

    long ram_used = get_current_ram_usage_kb();
    std::cout << "\n  RAM Peak (Max RSS): " << ram_used << " KB\n";
}

inline void run_benchmark_isolated(ICryptoAlgorithm* algo, const std::vector<size_t>& packet_sizes) {
    std::cout.flush();
    pid_t pid = fork();
    if (pid == 0) {
        // Processo figlio: spazio di indirizzamento pulito, RSS indipendente
        run_benchmark_suite(algo, packet_sizes);
        std::cout.flush();
        _exit(0);
    } else if (pid > 0) {
        // Processo padre: aspetta che il figlio finisca
        int status;
        waitpid(pid, &status, 0);
    } else {
        std::cerr << "Errore fork() per " << algo->get_name() << "\n";
    }
}

#endif // BENCHMARK_CORE_HPP
