/* =============================================================================
 * hal.h — Hardware Abstraction Layer per benchmark bare-metal
 *
 * Interfaccia astratta che nasconde le differenze tra Cortex-M e Cortex-A.
 * Ogni target implementa queste funzioni in hal_cortexm.c o hal_cortexa.c
 * =========================================================================== */
#ifndef HAL_H
#define HAL_H

#include <stdint.h>
#include <stddef.h>

/* ---- Inizializzazione sistema ---- */

/* Configura clock di sistema, abilita periferiche, UART, etc.
 * Chiamata una volta sola all'avvio, prima di qualsiasi benchmark. */
void hal_system_init(void);

/* ---- Cycle Counter (sostituisce perf_event_open / __rdtscp) ---- */

/* Abilita e resetta il contatore di cicli hardware.
 * Cortex-M: DWT->CYCCNT   |   Cortex-A: PMCCNTR (CP15) */
void hal_cycles_init(void);

/* Legge il contatore di cicli corrente (32 bit, wraps).
 * Costo: 1 istruzione, zero overhead da syscall. */
static inline uint32_t hal_read_cycles(void);

/* ---- UART (sostituisce std::cout / std::ofstream) ---- */

/* Inizializza UART a UART_BAUD (default 115200).
 * Output leggibile da PuTTY/Tera Term via USB. */
void hal_uart_init(void);

/* Trasmette un singolo byte (bloccante). */
void hal_uart_putc(char c);

/* Trasmette un buffer di len byte. */
void hal_uart_write(const char *buf, size_t len);

/* ---- Entropia Hardware (sostituisce /dev/urandom) ---- */

/* Raccoglie len byte di entropia hardware grezza nel buffer out.
 * Fonte: TRNG periferico o rumore ADC (dipende dal target).
 * Ritorna 0 su successo, -1 se non disponibile. */
int hal_entropy_collect(uint8_t *out, size_t len);

/* ---- Stack Watermarking (sostituisce getrusage / RSS) ---- */

/* Riempie lo stack libero con un pattern noto (0xDEADBEEF).
 * Chiamare PRIMA del benchmark da misurare. */
void hal_stack_paint(void);

/* Conta quanti byte di stack sono stati effettivamente usati
 * cercando dove il pattern è stato sovrascritto.
 * Chiamare DOPO il benchmark da misurare. */
uint32_t hal_stack_used_bytes(void);

/* ---- Implementazione inline di hal_read_cycles ---- */

static inline uint32_t hal_read_cycles(void) {
#if defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
    /* Cortex-M4 / M7: DWT Cycle Counter */
    return *((volatile uint32_t *)0xE0001004u);  /* DWT->CYCCNT */

#elif defined(__ARM_ARCH_7A__)
    /* Cortex-A9 / A7: CP15 Performance Monitor PMCCNTR */
    uint32_t val;
    __asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(val));
    return val;

#elif defined(__aarch64__)
    /* Cortex-A53/A72 AArch64 bare-metal */
    uint64_t val;
    __asm volatile("mrs %0, pmccntr_el0" : "=r"(val));
    return (uint32_t)val;

#else
    /* Fallback: compilazione host/simulatore — ritorna 0 */
    return 0u;
#endif
}

#endif /* HAL_H */
