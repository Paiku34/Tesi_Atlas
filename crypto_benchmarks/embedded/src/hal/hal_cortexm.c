/* =============================================================================
 * hal_cortexm.c — Implementazione HAL per ARM Cortex-M (M4 / M7)
 *
 * Compilato solo quando il target è ARMv7-M (flag -mcpu=cortex-m4 o m7).
 * Se il target è Cortex-A, questo file produce funzioni vuote (weak).
 * =========================================================================== */
#include "hal/hal.h"

#if defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
/* =========================================================================
 * Cortex-M4 / M7 — implementazione reale
 * ========================================================================= */

/* Registri DWT */
#define DWT_CTRL    (*(volatile uint32_t *)0xE0001000u)
#define DWT_CYCCNT  (*(volatile uint32_t *)0xE0001004u)
#define DEMCR       (*(volatile uint32_t *)0xE000EDFCu)
#define TRCENA_BIT  (1u << 24)
#define CYCCNTENA   (1u << 0)

void hal_system_init(void) {
    /*
     * TODO: TO BE IMPLEMENTED per il target specifico.
     *
     * Qui va la configurazione del clock di sistema (SystemClock_Config),
     * abilitazione periferiche (RCC), configurazione GPIO, etc.
     *
     * Esempio STM32F4 HAL:
     *   HAL_Init();
     *   SystemClock_Config();  // PLL a 168 MHz
     *   __HAL_RCC_GPIOA_CLK_ENABLE();
     *   __HAL_RCC_USART2_CLK_ENABLE();
     *
     * Per ora il codice compila ma il sistema deve essere inizializzato
     * dal startup code del BSP specifico.
     */
}

void hal_cycles_init(void) {
    /* Abilita il trace (necessario per DWT) */
    DEMCR |= TRCENA_BIT;
    /* Reset contatore */
    DWT_CYCCNT = 0u;
    /* Abilita contatore cicli */
    DWT_CTRL |= CYCCNTENA;
}

void hal_uart_init(void) {
    /*
     * TODO: TO BE IMPLEMENTED per il target specifico.
     *
     * Configurare la UART hardware (USART2 su STM32F4 tipicamente).
     * Il baud rate è definito dalla macro UART_BAUD (default 115200).
     *
     * Esempio STM32 HAL:
     *   huart2.Instance = USART2;
     *   huart2.Init.BaudRate = UART_BAUD;
     *   huart2.Init.WordLength = UART_WORDLENGTH_8B;
     *   huart2.Init.StopBits = UART_STOPBITS_1;
     *   huart2.Init.Parity = UART_PARITY_NONE;
     *   huart2.Init.Mode = UART_MODE_TX;
     *   HAL_UART_Init(&huart2);
     *
     * Per ora il retarget in uart_retarget.c è un placeholder.
     */
}

void hal_uart_putc(char c) {
    /*
     * TODO: TO BE IMPLEMENTED
     *
     * Esempio CMSIS diretto:
     *   while (!(USART2->SR & USART_SR_TXE)) {}
     *   USART2->DR = (uint8_t)c;
     *
     * Esempio STM32 HAL:
     *   HAL_UART_Transmit(&huart2, (uint8_t*)&c, 1, HAL_MAX_DELAY);
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
     * TODO: TO BE IMPLEMENTED per il target specifico.
     *
     * Opzione 1 — STM32 con periferico RNG (F4/H7/L4):
     *   __HAL_RCC_RNG_CLK_ENABLE();
     *   RNG_HandleTypeDef hrng = { .Instance = RNG };
     *   HAL_RNG_Init(&hrng);
     *   for (size_t i = 0; i < len; i += 4) {
     *       uint32_t rnd;
     *       HAL_RNG_GenerateRandomNumber(&hrng, &rnd);
     *       size_t chunk = (len - i >= 4) ? 4 : (len - i);
     *       memcpy(out + i, &rnd, chunk);
     *   }
     *   return 0;
     *
     * Opzione 2 — Nessun TRNG, rumore ADC:
     *   Campiona un canale ADC floating, estrai LSB per entropia.
     *   Più lento, qualità inferiore, ma funziona ovunque.
     *
     * Per ora: ritorna -1 (non disponibile).
     * Il CTR-DRBG in rng_seed.c userà un seed fisso di fallback.
     */
    (void)out;
    (void)len;
    return -1;
}

/* ---- Stack Watermarking ---- */

/* Simboli definiti dal linker script */
extern uint32_t _estack;
extern uint32_t _Min_Stack_Size;

#define STACK_FILL_PATTERN 0xDEADBEEFu

void hal_stack_paint(void) {
    /* Calcola il fondo dello stack */
    uint32_t stack_bottom = (uint32_t)&_estack - (uint32_t)&_Min_Stack_Size;
    volatile uint32_t *p = (volatile uint32_t *)stack_bottom;

    /* Leggi SP corrente — non sovrascrivere lo stack in uso! */
    register uint32_t sp_now;
    __asm volatile("mov %0, sp" : "=r"(sp_now));

    /* Riempi dal fondo fino a 64 byte sotto lo SP corrente */
    while ((uint32_t)p < sp_now - 64u) {
        *p++ = STACK_FILL_PATTERN;
    }
}

uint32_t hal_stack_used_bytes(void) {
    uint32_t stack_bottom = (uint32_t)&_estack - (uint32_t)&_Min_Stack_Size;
    volatile uint32_t *p = (volatile uint32_t *)stack_bottom;

    /* Cerca il primo word che non è più il pattern → inizio dello stack usato */
    while (*p == STACK_FILL_PATTERN) {
        p++;
    }
    return (uint32_t)&_estack - (uint32_t)p;
}

#else
/* =========================================================================
 * NON Cortex-M: funzioni weak vuote (Cortex-A compila hal_cortexa.c)
 * ========================================================================= */
__attribute__((weak)) void hal_system_init(void) {}
__attribute__((weak)) void hal_cycles_init(void) {}
__attribute__((weak)) void hal_uart_init(void) {}
__attribute__((weak)) void hal_uart_putc(char c) { (void)c; }
__attribute__((weak)) void hal_uart_write(const char *buf, size_t len) { (void)buf; (void)len; }
__attribute__((weak)) int  hal_entropy_collect(uint8_t *out, size_t len) { (void)out; (void)len; return -1; }
__attribute__((weak)) void hal_stack_paint(void) {}
__attribute__((weak)) uint32_t hal_stack_used_bytes(void) { return 0; }

#endif /* __ARM_ARCH_7M__ || __ARM_ARCH_7EM__ */
