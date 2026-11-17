/* =============================================================================
 * bench_aead.c — Porting Bare-Metal dei benchmark AEAD
 *
 * Sostituisce:
 *   - bench_ascon.cpp (ascon-c)
 *   - bench_aead_libsodium.cpp (Libsodium AES-256-GCM + ChaCha20-Poly1305)
 *   - bench_aead_openssl.cpp (OpenSSL EVP AES-256-GCM + ChaCha20-Poly1305)
 *
 * Differenze architetturali implementate:
 *   1. Eliminato C++ e allocazioni dinamiche (std::vector, new, malloc).
 *   2. Ascon usa la variante 32-bit (bi32_armv7m / opt32) invece di opt64.
 *   3. OpenSSL e Libsodium sostituiti da mbed TLS (mbedtls_gcm_*, mbedtls_chachapoly_*).
 *   4. Nonce incrementale a 64-bit esattamente identico al codice originale.
 * =========================================================================== */

#include "bench_core.h"

/* =============================================================================
 * 1. ASCON-AEAD128 (Stand-Alone via ascon-c)
 * =========================================================================== */

/* Prototipo ufficiale della funzione ascon-c API */
extern int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k
);

static uint8_t s_ascon_key[16];
static uint8_t s_ascon_npub[16];
static uint64_t s_ascon_nonce_counter = 0;

static int ascon_init(void) {
    /* ORIGINALE (Linux): fopen("/dev/urandom")
     * BARE-METAL: CTR-DRBG con seed hardware */
    rng_fill(s_ascon_key, sizeof(s_ascon_key));
    memset(s_ascon_npub, 0, sizeof(s_ascon_npub));
    s_ascon_nonce_counter = 0;
    return 0;
}

static int ascon_process(const uint8_t *plaintext, size_t pt_len,
                         uint8_t *ciphertext, size_t *ct_len) {
    s_ascon_nonce_counter++;
    memcpy(s_ascon_npub, &s_ascon_nonce_counter, sizeof(s_ascon_nonce_counter));

    /* Layout ciphertext identico all'originale: [16B Nonce] + [Ciphertext + 16B Tag] */
    memcpy(ciphertext, s_ascon_npub, 16);

    unsigned long long clen = 0;
    int ret = crypto_aead_encrypt(
        ciphertext + 16, &clen,
        plaintext, (unsigned long long)pt_len,
        NULL, 0,
        NULL, s_ascon_npub, s_ascon_key
    );

    if (ret != 0) {
        return ret;
    }

    *ct_len = 16 + (size_t)clen;
    return 0;
}

/* =============================================================================
 * 2. AES-256-GCM (Transizione da OpenSSL/Libsodium a mbed TLS)
 * =========================================================================== */

#ifdef HAS_MBEDTLS
#include "mbedtls/gcm.h"

static mbedtls_gcm_context s_gcm_ctx;
static uint8_t s_aes_key[32];
static uint8_t s_aes_iv[12];
static uint64_t s_aes_iv_counter = 0;

static int aes_gcm_init(void) {
    rng_fill(s_aes_key, sizeof(s_aes_key));
    memset(s_aes_iv, 0, sizeof(s_aes_iv));
    s_aes_iv_counter = 0;

    mbedtls_gcm_init(&s_gcm_ctx);
    int ret = mbedtls_gcm_setkey(&s_gcm_ctx, MBEDTLS_CIPHER_ID_AES, s_aes_key, 256);
    return ret;
}

static int aes_gcm_process(const uint8_t *plaintext, size_t pt_len,
                           uint8_t *ciphertext, size_t *ct_len) {
    s_aes_iv_counter++;
    memcpy(s_aes_iv, &s_aes_iv_counter, sizeof(s_aes_iv_counter));

    /* Layout identico all'originale: [12B IV] + [Ciphertext] + [16B Tag] */
    memcpy(ciphertext, s_aes_iv, 12);

    uint8_t tag[16];
    int ret = mbedtls_gcm_crypt_and_tag(
        &s_gcm_ctx, MBEDTLS_GCM_ENCRYPT,
        pt_len,
        s_aes_iv, 12,
        NULL, 0, /* No AAD */
        plaintext,
        ciphertext + 12,
        16, tag
    );

    if (ret != 0) return ret;

    memcpy(ciphertext + 12 + pt_len, tag, 16);
    *ct_len = 12 + pt_len + 16;
    return 0;
}

#else
/* Stub quando mbed TLS non e' ancora collegata al build */
static int aes_gcm_init(void) {
    printf("[AEAD] AES-256-GCM mbed TLS: TO BE IMPLEMENTED / mbed TLS non ancora linkata\r\n");
    return -1;
}
static int aes_gcm_process(const uint8_t *pt, size_t len, uint8_t *ct, size_t *clen) {
    (void)pt; (void)len; (void)ct; (void)clen;
    return -1;
}
#endif

/* =============================================================================
 * 3. ChaCha20-Poly1305 (Transizione da OpenSSL/Libsodium a mbed TLS)
 * =========================================================================== */

#ifdef HAS_MBEDTLS
#include "mbedtls/chachapoly.h"

static mbedtls_chachapoly_context s_chachapoly_ctx;
static uint8_t s_chacha_key[32];
static uint8_t s_chacha_iv[12];
static uint64_t s_chacha_iv_counter = 0;

static int chacha_init(void) {
    rng_fill(s_chacha_key, sizeof(s_chacha_key));
    memset(s_chacha_iv, 0, sizeof(s_chacha_iv));
    s_chacha_iv_counter = 0;

    mbedtls_chachapoly_init(&s_chachapoly_ctx);
    int ret = mbedtls_chachapoly_setkey(&s_chachapoly_ctx, s_chacha_key);
    return ret;
}

static int chacha_process(const uint8_t *plaintext, size_t pt_len,
                          uint8_t *ciphertext, size_t *ct_len) {
    s_chacha_iv_counter++;
    memcpy(s_chacha_iv, &s_chacha_iv_counter, sizeof(s_chacha_iv_counter));

    /* Layout identico all'originale: [12B Nonce] + [Ciphertext] + [16B Tag] */
    memcpy(ciphertext, s_chacha_iv, 12);

    uint8_t tag[16];
    int ret = mbedtls_chachapoly_encrypt_and_tag(
        &s_chachapoly_ctx,
        pt_len,
        s_chacha_iv,
        NULL, 0, /* No AAD */
        plaintext,
        ciphertext + 12,
        tag
    );

    if (ret != 0) return ret;

    memcpy(ciphertext + 12 + pt_len, tag, 16);
    *ct_len = 12 + pt_len + 16;
    return 0;
}

#else
/* Stub quando mbed TLS non e' ancora collegata al build */
static int chacha_init(void) {
    printf("[AEAD] ChaCha20-Poly1305 mbed TLS: TO BE IMPLEMENTED / mbed TLS non ancora linkata\r\n");
    return -1;
}
static int chacha_process(const uint8_t *pt, size_t len, uint8_t *ct, size_t *clen) {
    (void)pt; (void)len; (void)ct; (void)clen;
    return -1;
}
#endif

/* =============================================================================
 * Tabella Algoritmi AEAD registrati
 * =========================================================================== */

static const aead_algorithm_t s_aead_algorithms[] = {
    {
        .name = "Ascon-AEAD128 (ascon-c 32-bit)",
        .fixed_overhead = 32, /* 16B Nonce + 16B Tag */
        .init = ascon_init,
        .process = ascon_process
    },
    {
        .name = "AES-256-GCM (mbed TLS)",
        .fixed_overhead = 28, /* 12B IV + 16B Tag */
        .init = aes_gcm_init,
        .process = aes_gcm_process
    },
    {
        .name = "ChaCha20-Poly1305 (mbed TLS)",
        .fixed_overhead = 28, /* 12B Nonce + 16B Tag */
        .init = chacha_init,
        .process = chacha_process
    }
};

void run_ascon_benchmark(void) {
    const size_t packet_sizes[] = {8, 16, 32, 64, 128, 256, 512, 1024};
    const size_t num_sizes = sizeof(packet_sizes) / sizeof(packet_sizes[0]);
    run_aead_benchmark(&s_aead_algorithms[0], packet_sizes, num_sizes, AEAD_BENCH_ITERATIONS);
}

void run_mbedtls_aead_benchmark(void) {
    const size_t packet_sizes[] = {8, 16, 32, 64, 128, 256, 512, 1024};
    const size_t num_sizes = sizeof(packet_sizes) / sizeof(packet_sizes[0]);
    run_aead_benchmark(&s_aead_algorithms[1], packet_sizes, num_sizes, AEAD_BENCH_ITERATIONS); /* AES-256-GCM */
    run_aead_benchmark(&s_aead_algorithms[2], packet_sizes, num_sizes, AEAD_BENCH_ITERATIONS); /* ChaCha20 */
}

void run_all_aead_benchmarks(void) {
    run_ascon_benchmark();
    run_mbedtls_aead_benchmark();
}
