/* =============================================================================
 * main_mbedtls_aead.c — Benchmark Bare-Metal: Solo AEAD mbed TLS (AES-GCM / ChaCha)
 * =========================================================================== */
#include <stdio.h>
#include "hal/hal.h"
#include "rng_seed.h"
#include "bench_core.h"

extern void run_mbedtls_aead_benchmark(void);

void Reset_Handler(void) __attribute__((weak, alias("main")));

int main(void) {
    hal_system_init();
    hal_uart_init();
    hal_cycles_init();
    rng_init();

    printf("\r\n\r\n");
    printf("################################################################################\r\n");
    printf("# ATLAS SONOBUOY CRYPTO BENCHMARK — MBED TLS AEAD (AES-256-GCM / ChaCha20)    #\r\n");
    printf("# Core Clock Target: %lu MHz                                                 #\r\n", (unsigned long)(CLOCK_HZ / 1000000UL));
    printf("################################################################################\r\n\r\n");

    print_bulk_csv_header();
    run_mbedtls_aead_benchmark();

    printf("\r\n>>> BENCHMARK MBED TLS AEAD COMPLETATO <<<\r\n");

    while (1) {
        #if defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
        __asm volatile("wfi");
        #endif
    }
    return 0;
}
