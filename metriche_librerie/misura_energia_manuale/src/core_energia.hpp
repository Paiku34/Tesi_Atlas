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
