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

// Costanti unificate del protocollo Secure Sonobuoy Telemetry (NATO ANEP-96 / ATLAS)
static constexpr size_t HANDSHAKE_NONCE_BYTES = 32; // Nonce casuale GS e Boa (256 bit, entropia e anti-replay)
static constexpr size_t PSK_TAG_BYTES         = 16; // Tag MAC autenticazione PSK trasmesso su canale (128 bit)
static constexpr size_t SESSION_KEY_BYTES     = 32; // Chiave di sessione simmetrica derivata (256 bit per AEAD)
static constexpr size_t AEAD_TAG_BYTES        = 16; // Tag di autenticazione AEAD standard (128 bit per GCM, Poly1305, Ascon)

// Etichette di contesto HKDF (Domain Separation)
static constexpr const char* HKDF_LABEL_SYMM  = "ATLAS_SH";
static constexpr const char* HKDF_LABEL_ECDH  = "ATLAS_ECDH";
static constexpr const char* HKDF_LABEL_MLKEM = "ATLAS_MLKEM";

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
