#ifndef CORE_ENERGIA_HPP
#define CORE_ENERGIA_HPP

#include <iostream>
#include <chrono>
#include <vector>
#include <iomanip>
#include <string>
#include <memory>
#include <atomic>
#include <csignal>
#include <cmath>
#include <cstring>
#include <unistd.h>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#include <x86intrin.h>
#define COMPILER_IS_X86
#endif

#if defined(__linux__) && defined(__aarch64__)
#include <linux/perf_event.h>
#include <sys/syscall.h>
#endif

// Flag globale atomico per fermare il burn CPU pulitamente con CTRL+C o timer
inline std::atomic<bool>& get_keep_running_flag() {
    static std::atomic<bool> flag(true);
    return flag;
}

inline void signal_handler_stop(int) {
    get_keep_running_flag().store(false);
}

// Lettura cicli CPU hardware (ARMv8 Cortex-A / x86)
inline unsigned long long read_cpu_cycles_hw() {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    unsigned int aux;
    return __rdtscp(&aux);
#elif defined(__linux__) && defined(__aarch64__)
    static int perf_fd = -2;
    static pid_t last_pid = 0;
    pid_t current_pid = getpid();

    if (perf_fd == -2 || current_pid != last_pid) {
        if (perf_fd >= 0) close(perf_fd);
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

template <typename T>
inline void do_not_optimize_away(const T& val) {
    asm volatile("" : : "g"(val) : "memory");
}

class IAlgorithmRunner {
public:
    virtual ~IAlgorithmRunner() = default;
    virtual std::string get_name() const = 0;
    virtual std::string get_category() const = 0; // "AEAD" o "KEY_MGMT"
    virtual size_t get_payload_size() const = 0;
    virtual void setup(size_t payload_size) = 0;
    virtual void run_single_op() = 0;
};

struct BenchmarkStats {
    std::string name;
    std::string category;
    size_t payload_bytes = 0;
    double latency_us_mean = 0.0;
    double latency_us_std = 0.0;
    unsigned long long cycles_per_op = 0;
    uint64_t total_ops_performed = 0;
};

// Misura la latenza software con alta precisione su N iterazioni e warm-up configurabile
inline BenchmarkStats measure_software_latency(IAlgorithmRunner* runner, size_t payload_size, int iterations = 5000, int warmup_iterations = 100) {
    runner->setup(payload_size);

    // Warm-up identico alla suite principale in src/
    for (int i = 0; i < warmup_iterations; i++) {
        runner->run_single_op();
    }

    std::vector<double> sample_times_us;
    sample_times_us.reserve(iterations);

    unsigned long long c_start = read_cpu_cycles_hw();

    for (int i = 0; i < iterations; i++) {
        auto t0 = std::chrono::high_resolution_clock::now();
        runner->run_single_op();
        auto t1 = std::chrono::high_resolution_clock::now();
        double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
        sample_times_us.push_back(us);
    }

    unsigned long long c_end = read_cpu_cycles_hw();

    double sum = 0.0;
    for (double v : sample_times_us) sum += v;
    double mean = sum / (double)iterations;

    double sq_diff_sum = 0.0;
    for (double v : sample_times_us) sq_diff_sum += (v - mean) * (v - mean);
    double std_dev = std::sqrt(sq_diff_sum / (double)iterations);

    unsigned long long cycles = (c_end >= c_start) ? ((c_end - c_start) / iterations) : 0;

    BenchmarkStats stats;
    stats.name = runner->get_name();
    stats.category = runner->get_category();
    stats.payload_bytes = payload_size;
    stats.latency_us_mean = mean;
    stats.latency_us_std = std_dev;
    stats.cycles_per_op = cycles;
    stats.total_ops_performed = (uint64_t)iterations;

    return stats;
}

// Esegue un loop continuo al 100% CPU per consentire la lettura stabile dell'amperometro
inline uint64_t run_steady_state_burn(IAlgorithmRunner* runner, size_t payload_size, int max_seconds = 0) {
    runner->setup(payload_size);
    get_keep_running_flag().store(true);
    std::signal(SIGINT, signal_handler_stop);
    std::signal(SIGTERM, signal_handler_stop);

    uint64_t ops = 0;
    auto start_time = std::chrono::steady_clock::now();

    while (get_keep_running_flag().load()) {
        runner->run_single_op();
        ops++;

        if (max_seconds > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time).count();
            if (elapsed >= max_seconds) {
                break;
            }
        }
    }

    return ops;
}

#endif // CORE_ENERGIA_HPP
