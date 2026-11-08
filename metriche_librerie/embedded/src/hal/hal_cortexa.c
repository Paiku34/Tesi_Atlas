/* =============================================================================
 * hal_cortexa.c — Implementazione HAL per ARM Cortex-A bare-metal (A9, A7, A53)
 *
 * Compilato solo quando il target è ARMv7-A.
 * =========================================================================== */
#include "hal/hal.h"
#include <string.h>

#if defined(__ARM_ARCH_7A__)
/* =========================================================================
 * Cortex-A9 (ARMv7-A) — implementazione reale
 * ========================================================================= */

void hal_system_init(void) {
    /*
     * TODO: TO BE IMPLEMENTED per il target specifico.
     *
     * Su Zynq-7020 il FSBL (First Stage Boot Loader) tipicamente configura:
     *   - PLL e clock tree (CPU @ 667 MHz)
     *   - DDR controller
     *   - MIO / EMIO per UART
     *
     * Su altri Cortex-A bare-metal:
     *   - Configurare clock PLL
     *   - Abilitare MMU e cache (opzionale per benchmark, ma impatta perf)
     *   - Configurare GIC (Generic Interrupt Controller) se servono interrupt
     */
}

void hal_cycles_init(void) {
    uint32_t val;

    /* Abilita tutti i contatori nel PMCR (Performance Monitor Control Register) */
    __asm volatile("mrc p15, 0, %0, c9, c12, 0" : "=r"(val));
    val |= (1u << 0)   /* Enable */
         | (1u << 2);  /* Reset cycle counter */
    __asm volatile("mcr p15, 0, %0, c9, c12, 0" :: "r"(val));

    /* Abilita il cycle counter (bit 31 di PMCNTENSET) */
    __asm volatile("mcr p15, 0, %0, c9, c12, 1" :: "r"(1u << 31));
}

void hal_uart_init(void) {
    /*
     * TODO: TO BE IMPLEMENTED per il target specifico.
     *
     * Zynq PS UART (UART0 o UART1):
     *   - Base address: 0xE0000000 (UART0) o 0xE0001000 (UART1)
     *   - Configurare baud rate divisor per UART_BAUD
     *   - Abilitare TX
     *
     * Per ora placeholder.
     */
}

void hal_uart_putc(char c) {
    /*
     * TODO: TO BE IMPLEMENTED
     *
     * Esempio Zynq UART1:
     *   #define UART1_BASE  0xE0001000
     *   #define UART_SR     (*(volatile uint32_t *)(UART1_BASE + 0x2C))
     *   #define UART_FIFO   (*(volatile uint32_t *)(UART1_BASE + 0x30))
     *   #define UART_SR_TXFULL (1u << 4)
     *
     *   while (UART_SR & UART_SR_TXFULL) {}
     *   UART_FIFO = (uint8_t)c;
     */
    (void)c;
}

void hal_uart_write(const char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        hal_uart_putc(buf[i]);
    }
}

int hal_entropy_collect(uint8_t *out, size_t len) {
    /*
     * TODO: TO BE IMPLEMENTED
     *
     * Zynq-7020 non ha un TRNG periferico nativo.
     * Opzioni:
     *   1. Rumore ADC (XADC) — campionare canale on-die temperature, LSB come entropia
     *   2. Jitter timer — usare differenze tra free-running timer e cycle counter
     *   3. Seed esterno via UART al boot
     *
     * Per ora: ritorna -1 (non disponibile).
     * Il CTR-DRBG userà seed fisso di fallback.
     */
    (void)out;
    (void)len;
    return -1;
}

/* ---- Stack Watermarking ---- */

/* Su Cortex-A il linker script definisce questi simboli.
 * Se il BSP non li definisce, usiamo valori di fallback. */
extern uint32_t _estack     __attribute__((weak));
extern uint32_t _Min_Stack_Size __attribute__((weak));

#define STACK_FILL_PATTERN 0xDEADBEEFu

/* Area di fallback se i simboli del linker non sono disponibili */
static uint32_t fallback_stack_bottom = 0;
static uint32_t fallback_stack_top    = 0;

void hal_stack_paint(void) {
    uint32_t stack_top, stack_size;

    if ((uint32_t)&_estack != 0 && (uint32_t)&_Min_Stack_Size != 0) {
        stack_top  = (uint32_t)&_estack;
        stack_size = (uint32_t)&_Min_Stack_Size;
    } else {
        /* Fallback: stima lo stack dal SP corrente */
        register uint32_t sp_now;
        __asm volatile("mov %0, sp" : "=r"(sp_now));
        stack_top  = (sp_now + 0xFFFF) & ~0xFFFF;  /* Arrotonda a 64KB */
        stack_size = 0x10000;  /* 64 KB */
        fallback_stack_top    = stack_top;
        fallback_stack_bottom = stack_top - stack_size;
    }

    uint32_t stack_bottom = stack_top - stack_size;
    volatile uint32_t *p = (volatile uint32_t *)stack_bottom;

    register uint32_t sp_now;
    __asm volatile("mov %0, sp" : "=r"(sp_now));

    while ((uint32_t)p < sp_now - 64u) {
        *p++ = STACK_FILL_PATTERN;
    }
}

uint32_t hal_stack_used_bytes(void) {
    uint32_t stack_top, stack_size;

    if ((uint32_t)&_estack != 0 && (uint32_t)&_Min_Stack_Size != 0) {
        stack_top  = (uint32_t)&_estack;
        stack_size = (uint32_t)&_Min_Stack_Size;
    } else {
        stack_top  = fallback_stack_top;
        stack_size = 0x10000;
    }

    uint32_t stack_bottom = stack_top - stack_size;
    volatile uint32_t *p = (volatile uint32_t *)stack_bottom;

    while (*p == STACK_FILL_PATTERN) {
        p++;
    }
    return stack_top - (uint32_t)p;
}

#else
/* Non Cortex-A: funzioni weak vuote (Cortex-M compila hal_cortexm.c) */
__attribute__((weak)) void hal_system_init(void) {}
__attribute__((weak)) void hal_cycles_init(void) {}
__attribute__((weak)) void hal_uart_init(void) {}
__attribute__((weak)) void hal_uart_putc(char c) { (void)c; }
__attribute__((weak)) void hal_uart_write(const char *buf, size_t len) { (void)buf; (void)len; }
__attribute__((weak)) int  hal_entropy_collect(uint8_t *out, size_t len) { (void)out; (void)len; return -1; }
__attribute__((weak)) void hal_stack_paint(void) {}
__attribute__((weak)) uint32_t hal_stack_used_bytes(void) { return 0; }

#endif /* __ARM_ARCH_7A__ */
