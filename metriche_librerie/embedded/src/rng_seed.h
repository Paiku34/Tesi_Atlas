/* =============================================================================
 * rng_seed.h — Interfaccia RNG bare-metal
 * =========================================================================== */
#ifndef RNG_SEED_H
#define RNG_SEED_H

#include <stdint.h>
#include <stddef.h>

/* Inizializza il DRBG. Chiamare una volta sola all'avvio. */
void rng_init(void);

/* Riempie buf con len byte pseudocasuali. Ritorna 0 su successo. */
int rng_fill(uint8_t *buf, size_t len);

/* Callback con firma compatibile mbed TLS (void *p_rng, uchar *out, size_t len).
 * Da passare a mbedtls_ecdh_gen_public(), mbedtls_ctr_drbg_random(), etc. */
int rng_callback(void *p_rng, unsigned char *output, size_t output_len);

#endif /* RNG_SEED_H */
