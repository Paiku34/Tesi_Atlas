/* =============================================================================
 * main.c — Entry Point Principale del Firmware Benchmark Bare-Metal
 *
 * Inizializza l'hardware (Clock, DWT/PMCCNTR, UART, RNG) ed esegue in sequenza
 * deterministica le suite di benchmark che su Linux venivano eseguite da run_all.sh:
 *   1. Suite AEAD (Ascon-128, AES-256-GCM, ChaCha20-Poly1305)
 *   2. Suite Key Management (PSK+HKDF, Symmetric Handshake, X25519)
 *   3. Suite ML-KEM Post-Quantum (se abilitata)
 * =========================================================================== */

#include <stdio.h>
#include "hal/hal.h"
#include "rng_seed.h"
#include "bench_core.h"

/* Dichiarazione delle suite di benchmark */
extern void run_all_aead_benchmarks(void);
extern void run_all_key_management_benchmarks(void);
extern void run_all_mlkem_benchmarks(void);

/* Entry point per il linker script se non c'e' ancora startup.s del chip */
void Reset_Handler(void) __attribute__((weak, alias("main")));

int main(void) {
    /* 1. Inizializzazione sistema hardware e periferiche di base */
    hal_system_init();

    /* 2. Inizializzazione UART per output seriale printf() */
    hal_uart_init();

    /* 3. Inizializzazione contatore cicli CPU ad altissima risoluzione */
    hal_cycles_init();

    /* 4. Inizializzazione Random Number Generator (CTR-DRBG alimentato da TRNG/ADC) */
    rng_init();

    printf("\r\n\r\n");
    printf("################################################################################\r\n");
    printf("# ATLAS SONOBUOY CRYPTO BENCHMARK — BARE-METAL ARM SUITE                      #\r\n");
    printf("# Core Clock Target: %lu MHz                                                 #\r\n", (unsigned long)(CLOCK_HZ / 1000000UL));
    printf("# Misura cicli: Hardware DWT / PMCCNTR (Zero jitter OS)                        #\r\n");
    printf("# Misura RAM:   Stack Watermarking (0xDEADBEEF)                                #\r\n");
    printf("################################################################################\r\n\r\n");

    /* Stampa gli header CSV (se catturati su file seriale da PuTTY/Tera Term) */
    print_bulk_csv_header();
    print_key_mgmt_csv_header();

    /* --- SUITE 1: AEAD BULK ENCRYPTION --- */
    run_all_aead_benchmarks();

    /* --- SUITE 2: KEY MANAGEMENT ROADMAP --- */
    run_all_key_management_benchmarks();

    /* --- SUITE 3: POST-QUANTUM ML-KEM --- */
    run_all_mlkem_benchmarks();

    printf("\r\n\r\n");
    printf("################################################################################\r\n");
    printf("# TUTTI I BENCHMARK SONO STATI COMPLETATI CON SUCCESSO!                        #\r\n");
    printf("################################################################################\r\n");

    /* Loop infinito di arresto bare-metal */
    while (1) {
        #if defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
        __asm volatile("wfi"); /* Wait For Interrupt: basso consumo */
        #endif
    }

    return 0;
}
