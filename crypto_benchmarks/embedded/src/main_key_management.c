/* =============================================================================
 * main_key_management.c — Benchmark Bare-Metal: Solo Key Management (PSK/HKDF/X25519)
 * =========================================================================== */
#include <stdio.h>
#include "hal/hal.h"
#include "rng_seed.h"
#include "bench_core.h"

extern void run_all_key_management_benchmarks(void);

void Reset_Handler(void) __attribute__((weak, alias("main")));

int main(void) {
    hal_system_init();
    hal_uart_init();
    hal_cycles_init();
    rng_init();

    printf("\r\n\r\n");
    printf("################################################################################\r\n");
    printf("# ATLAS SONOBUOY CRYPTO BENCHMARK — KEY MANAGEMENT ROADMAP                    #\r\n");
    printf("# Core Clock Target: %lu MHz                                                 #\r\n", (unsigned long)(CLOCK_HZ / 1000000UL));
    printf("################################################################################\r\n\r\n");

    print_key_mgmt_csv_header();
    run_all_key_management_benchmarks();

    printf("\r\n>>> BENCHMARK KEY MANAGEMENT COMPLETATO <<<\r\n");

    while (1) {
        #if defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
        __asm volatile("wfi");
        #endif
    }
    return 0;
}
