/* =============================================================================
 * rng_seed.c — Generatore di numeri casuali per bare-metal
 *
 * Sostituisce /dev/urandom (Linux) e randombytes_buf() (Libsodium).
 * Usa CTR-DRBG di mbed TLS alimentato dall'entropia hardware del HAL.
 *
 * ORIGINALE:   fopen("/dev/urandom") / randombytes_buf()
 * BARE-METAL:  hal_entropy_collect() → mbed TLS CTR-DRBG → rng_fill()
 * =========================================================================== */
#include "rng_seed.h"
#include "hal/hal.h"
#include <string.h>
#include <stdio.h>

/* =============================================================================
 * Implementazione CON mbed TLS (quando la libreria è disponibile)
 * =========================================================================== */
#ifdef HAS_MBEDTLS

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

static mbedtls_ctr_drbg_context g_ctr_drbg;
static mbedtls_entropy_context  g_entropy;
static int g_rng_initialized = 0;

/* Callback che mbed TLS chiama per ottenere entropia grezza */
static int entropy_hw_callback(void *data, unsigned char *output, size_t len, size_t *olen) {
    (void)data;
    int ret = hal_entropy_collect(output, len);
    if (ret == 0) {
        *olen = len;
    } else {
        /* Fallback: seed deterministico (NON sicuro, solo per benchmark!) */
        static uint32_t fallback_state = 0x12345678u;
        for (size_t i = 0; i < len; i++) {
            fallback_state ^= fallback_state << 13;
            fallback_state ^= fallback_state >> 17;
            fallback_state ^= fallback_state << 5;
            output[i] = (uint8_t)(fallback_state & 0xFF);
        }
        *olen = len;
        /* Primo avviso (non spammare) */
        static int warned = 0;
        if (!warned) {
            printf("[RNG] WARNING: usando seed deterministico (no TRNG HW). "
                   "OK per benchmark, NON per produzione!\n");
            warned = 1;
        }
    }
    return 0;
}

void rng_init(void) {
    if (g_rng_initialized) return;

    mbedtls_ctr_drbg_init(&g_ctr_drbg);
    mbedtls_entropy_init(&g_entropy);

    /* Registra la sorgente di entropia hardware */
    mbedtls_entropy_add_source(&g_entropy, entropy_hw_callback, NULL,
                                32, MBEDTLS_ENTROPY_SOURCE_STRONG);

    /* Seed iniziale con stringa personalizzazione */
    const char *pers = "ATLAS_SONOBUOY_BENCH";
    int ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg, mbedtls_entropy_func, &g_entropy,
                                     (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        printf("[RNG] ERRORE: mbedtls_ctr_drbg_seed fallito (ret=%d)\n", ret);
    }

    g_rng_initialized = 1;
}

int rng_fill(uint8_t *buf, size_t len) {
    if (!g_rng_initialized) {
        rng_init();
    }
    return mbedtls_ctr_drbg_random(&g_ctr_drbg, buf, len);
}

/* Callback con firma compatibile mbed TLS (per passarlo a funzioni ECDH etc.) */
int rng_callback(void *p_rng, unsigned char *output, size_t output_len) {
    (void)p_rng;
    return rng_fill(output, output_len);
}

#else
/* =============================================================================
 * Implementazione SENZA mbed TLS (fallback XORSHIFT — solo per compilazione)
 * =========================================================================== */

static uint32_t rng_state = 0x1234ABCDu;

void rng_init(void) {
    /* Prova a raccogliere un seed hardware */
    uint32_t hw_seed;
    if (hal_entropy_collect((uint8_t *)&hw_seed, sizeof(hw_seed)) == 0) {
        rng_state = hw_seed;
    }
    printf("[RNG] WARNING: CTR-DRBG non disponibile (mbed TLS assente). "
           "Usando XORSHIFT32 — NON crittograficamente sicuro!\n");
}

int rng_fill(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 17;
        rng_state ^= rng_state << 5;
        buf[i] = (uint8_t)(rng_state & 0xFF);
    }
    return 0;
}

int rng_callback(void *p_rng, unsigned char *output, size_t output_len) {
    (void)p_rng;
    return rng_fill(output, output_len);
}

#endif /* HAS_MBEDTLS */
