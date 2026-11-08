/* =============================================================================
 * bench_core.h — Core benchmark engine per ARM Bare-Metal (C puro)
 *
 * Sostituisce integralmente "benchmark_core.hpp" di Linux:
 *  - Niente C++ (std::vector, std::string, chrono, iostream) -> Buffer statici e C99/C11
 *  - Niente perf_event_open() o rdtscp -> hal_read_cycles() (DWT / PMCCNTR hardware)
 *  - Niente getrusage() (RSS) -> hal_stack_used_bytes() (Stack Watermarking)
 *  - Niente fork() / IPC -> Esecuzione sequenziale deterministica
 *  - Niente std::ofstream -> CSV output diretto su UART via printf()
 * =========================================================================== */

#ifndef BENCH_CORE_H
#define BENCH_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "hal/hal.h"
#include "rng_seed.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Frequenza di clock del core per conversione cicli -> tempo */
#ifndef CLOCK_HZ
#define CLOCK_HZ 168000000UL /* Default: 168 MHz (STM32F4) */
#endif

/* Conversione cicli CPU in microsecondi (us) */
static inline double cycles_to_us(uint32_t cycles) {
    return ((double)cycles * 1000000.0) / (double)CLOCK_HZ;
}

/* Barriera anti-ottimizzazione del compilatore (-O3/-Os) */
#define DO_NOT_OPTIMIZE_AWAY(val) do { \
    __asm__ volatile("" : : "g"(val) : "memory"); \
} while(0)

/* Helper barriera per puntatori/buffer */
static inline void do_not_optimize_buffer(const void *p, size_t len) {
    (void)len;
    __asm__ volatile("" : : "r"(p) : "memory");
}

/* Struttura descrittiva di un algoritmo AEAD per il benchmark */
typedef struct {
    const char *name;
    size_t fixed_overhead; /* Es. 28 B (12B nonce + 16B tag) o 32 B */
    int (*init)(void);
    int (*process)(const uint8_t *plaintext, size_t pt_len,
                   uint8_t *ciphertext, size_t *ct_len);
} aead_algorithm_t;

/* Parametri suite AEAD */
#define AEAD_WARMUP_ITERATIONS   100
#define AEAD_BENCH_ITERATIONS    5000 /* 5000 campioni per taglia (come nel codice originale Linux) */
#define MAX_PAYLOAD_SIZE         1024
#define MAX_CIPHERTEXT_SIZE      (MAX_PAYLOAD_SIZE + 64)

/* Abilita l'emissione seriale dei singoli record CSV raw (1 riga per iterazione)
 * per compatibilita' totale con analyze_benchmarks.py */
#ifndef EMIT_RAW_CSV_SAMPLES
#define EMIT_RAW_CSV_SAMPLES     1
#endif

/* Esegue il benchmark per una lista di payload sizes con output compatibile al CSV originale:
 * Formato CSV: algorithm,payload_bytes,added_bytes,sample_id,latency_us,cycles_per_op,cycles_per_byte,energy_uj,ram_kb
 */
void run_aead_benchmark(const aead_algorithm_t *algo,
                        const size_t *packet_sizes,
                        size_t num_sizes,
                        int iterations);

/* Stampa header del CSV bulk encryption (se non gia' stampato) */
void print_bulk_csv_header(void);

/* Stampa header del CSV key management */
void print_key_mgmt_csv_header(void);

#ifdef __cplusplus
}
#endif

#endif /* BENCH_CORE_H */
