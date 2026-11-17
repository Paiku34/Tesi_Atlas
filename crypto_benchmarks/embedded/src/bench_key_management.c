/* =============================================================================
 * bench_key_management.c — Porting Bare-Metal Key Management Roadmap
 *
 * Sostituisce:
 *   - bench_key_management.cpp (Libsodium PSK-KDF, Symmetric Handshake, X25519)
 *
 * Schemi implementati in C puro con mbed TLS:
 *   1. PSK + KDF (HKDF-SHA256 locale, zero byte trasmessi via radio)
 *   2. Symmetric handshake (buoy-side response HMAC-SHA256 + HKDF, 80 byte)
 *   3. ECC X25519 (ECDH Curve25519, 64 byte scambiati)
 * =========================================================================== */

#include "bench_core.h"

#define KM_ITERATIONS 1000

typedef struct {
    const char *scheme_name;
    const char *paradigm;
    size_t exchanged_bytes;
    double avg_latency_us;
    uint32_t avg_cycles;
    uint32_t stack_used_bytes;
} km_summary_t;

/* =============================================================================
 * 1. PSK + KDF (HKDF-SHA256 via mbed TLS)
 * =========================================================================== */
#ifdef HAS_MBEDTLS
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

static void bench_psk_kdf(km_summary_t *res) {
    res->scheme_name = "PSK + KDF (mbed TLS HKDF)";
    res->paradigm = "Symmetric Pre-Shared";
    res->exchanged_bytes = 0; /* 0 B via radio */

    uint8_t psk[32];
    uint8_t session_key[32];
    rng_fill(psk, sizeof(psk));

    const uint8_t salt[8] = "ATLAS_KM";
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    /* Warm-up (50 iterazioni come in Linux) */
    for (int i = 0; i < 50; i++) {
        uint64_t subkey_id = (uint64_t)i;
        mbedtls_hkdf(md_info, salt, sizeof(salt), psk, sizeof(psk),
                     (const unsigned char *)&subkey_id, sizeof(subkey_id),
                     session_key, sizeof(session_key));
        DO_NOT_OPTIMIZE_AWAY(session_key[0]);
    }

    hal_stack_paint();
    uint32_t c0 = hal_read_cycles();

    for (int i = 0; i < KM_ITERATIONS; i++) {
        uint64_t subkey_id = (uint64_t)i;
        mbedtls_hkdf(md_info, salt, sizeof(salt), psk, sizeof(psk),
                     (const unsigned char *)&subkey_id, sizeof(subkey_id),
                     session_key, sizeof(session_key));
        DO_NOT_OPTIMIZE_AWAY(session_key[0]);
    }

    uint32_t c1 = hal_read_cycles();
    uint32_t total = (c1 >= c0) ? (c1 - c0) : 0;
    res->avg_cycles = total / KM_ITERATIONS;
    res->avg_latency_us = cycles_to_us(res->avg_cycles);
    res->stack_used_bytes = hal_stack_used_bytes();
}

/* =============================================================================
 * 2. Symmetric handshake (buoy-side HMAC-SHA256 + HKDF via mbed TLS)
 * =========================================================================== */
static void bench_symmetric_handshake(km_summary_t *res) {
    res->scheme_name = "Symmetric Handshake";
    res->paradigm = "Symmetric Auth, Buoy Only";
    res->exchanged_bytes = 80; /* 32B nc + 32B ns + 16B tag */

    uint8_t psk[32];
    rng_fill(psk, sizeof(psk));

    uint8_t nc[32], ns[32], tag[32], session_key[32];
    uint8_t handshake_data[64];
    uint8_t prk[32];

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    /* The Ground Station nonce is received before the measured operation. */
    rng_fill(nc, 32);

    /* Warm-up */
    for (int i = 0; i < 50; i++) {
        rng_fill(ns, 32);
        memcpy(handshake_data, nc, 32);
        memcpy(handshake_data + 32, ns, 32);
        mbedtls_md_hmac(md_info, psk, 32, handshake_data, 64, tag);
        mbedtls_hkdf_extract(md_info, handshake_data, sizeof(handshake_data), psk, sizeof(psk), prk);
        mbedtls_hkdf_expand(md_info, prk, 32, (const unsigned char *)"ATLAS_SH", 8, session_key, 32);
        DO_NOT_OPTIMIZE_AWAY(session_key[0]);
    }

    hal_stack_paint();
    uint32_t c0 = hal_read_cycles();

    for (int i = 0; i < KM_ITERATIONS; i++) {
        /* The GS nonce is already available; measure only the buoy response. */
        rng_fill(ns, 32);
        memcpy(handshake_data, nc, 32);
        memcpy(handshake_data + 32, ns, 32);

        /* The buoy authenticates its response with the PSK. */
        mbedtls_md_hmac(md_info, psk, 32, handshake_data, 64, tag);

        /* Derive the session key on the buoy side. */
        mbedtls_hkdf_extract(md_info, handshake_data, sizeof(handshake_data), psk, sizeof(psk), prk);
        mbedtls_hkdf_expand(md_info, prk, 32, (const unsigned char *)"ATLAS_SH", 8, session_key, 32);
        DO_NOT_OPTIMIZE_AWAY(session_key[0]);
    }

    uint32_t c1 = hal_read_cycles();
    uint32_t total = (c1 >= c0) ? (c1 - c0) : 0;
    res->avg_cycles = total / KM_ITERATIONS;
    res->avg_latency_us = cycles_to_us(res->avg_cycles);
    res->stack_used_bytes = hal_stack_used_bytes();
}

/* =============================================================================
 * 3. ECC X25519 (ECDH via mbed TLS 3.x API pubblica)
 * =========================================================================== */
#include "mbedtls/ecdh.h"

static void bench_x25519(km_summary_t *res) {
    res->scheme_name = "ECDH X25519 (mbed TLS)";
    res->paradigm = "Classical (ECC)";
    res->exchanged_bytes = 64; /* 32B Client PK + 32B Server PK */

    mbedtls_ecdh_context ctx_client, ctx_server;
    mbedtls_ecdh_init(&ctx_client);
    mbedtls_ecdh_init(&ctx_server);

    mbedtls_ecdh_setup(&ctx_client, MBEDTLS_ECP_DP_CURVE25519);
    mbedtls_ecdh_setup(&ctx_server, MBEDTLS_ECP_DP_CURVE25519);

    uint8_t client_pub[64], server_pub[64];
    size_t client_pub_len = 0, server_pub_len = 0;
    uint8_t shared_secret[32];
    size_t shared_secret_len = 0;

    /* Warm-up */
    for (int i = 0; i < 10; i++) {
        mbedtls_ecdh_make_public(&ctx_client, &client_pub_len, client_pub, sizeof(client_pub), rng_callback, NULL);
        mbedtls_ecdh_make_public(&ctx_server, &server_pub_len, server_pub, sizeof(server_pub), rng_callback, NULL);
        mbedtls_ecdh_read_public(&ctx_client, server_pub, server_pub_len);
        mbedtls_ecdh_calc_secret(&ctx_client, &shared_secret_len, shared_secret, sizeof(shared_secret), rng_callback, NULL);
        DO_NOT_OPTIMIZE_AWAY(shared_secret[0]);
    }

    hal_stack_paint();
    uint32_t c0 = hal_read_cycles();

    for (int i = 0; i < KM_ITERATIONS; i++) {
        /* Client KeyGen (genera chiave privata e serializza chiave pubblica) */
        mbedtls_ecdh_make_public(&ctx_client, &client_pub_len, client_pub, sizeof(client_pub), rng_callback, NULL);

        /* Server KeyGen (genera chiave privata e serializza chiave pubblica) */
        mbedtls_ecdh_make_public(&ctx_server, &server_pub_len, server_pub, sizeof(server_pub), rng_callback, NULL);

        /* Client legge la chiave pubblica del Server e calcola il segreto condiviso */
        mbedtls_ecdh_read_public(&ctx_client, server_pub, server_pub_len);
        mbedtls_ecdh_calc_secret(&ctx_client, &shared_secret_len, shared_secret, sizeof(shared_secret), rng_callback, NULL);
        DO_NOT_OPTIMIZE_AWAY(shared_secret[0]);
    }

    uint32_t c1 = hal_read_cycles();
    uint32_t total = (c1 >= c0) ? (c1 - c0) : 0;
    res->avg_cycles = total / KM_ITERATIONS;
    res->avg_latency_us = cycles_to_us(res->avg_cycles);
    res->stack_used_bytes = hal_stack_used_bytes();

    mbedtls_ecdh_free(&ctx_client);
    mbedtls_ecdh_free(&ctx_server);
}

#else
/* Stub quando mbed TLS non e' ancora linkata */
static void bench_psk_kdf(km_summary_t *res) {
    res->scheme_name = "PSK + KDF (mbed TLS)";
    res->paradigm = "Symmetric Pre-Shared";
    res->exchanged_bytes = 0;
    printf("[KM] PSK-KDF: TO BE IMPLEMENTED / mbed TLS non ancora linkata\r\n");
}
static void bench_symmetric_handshake(km_summary_t *res) {
    res->scheme_name = "Symmetric Handshake";
    res->paradigm = "Symmetric Auth, Buoy Only";
    res->exchanged_bytes = 80;
    printf("[KM] Handshake: TO BE IMPLEMENTED / mbed TLS non ancora linkata\r\n");
}
static void bench_x25519(km_summary_t *res) {
    res->scheme_name = "ECDH X25519 (mbed TLS)";
    res->paradigm = "Classical (ECC)";
    res->exchanged_bytes = 64;
    printf("[KM] X25519: TO BE IMPLEMENTED / mbed TLS non ancora linkata\r\n");
}
#endif

void run_all_key_management_benchmarks(void) {
    printf("\r\n======================================================================================================\r\n");
    printf(" BENCHMARK: KEY MANAGEMENT ROADMAP (PSK -> Symmetric Handshake -> ECC X25519)\r\n");
    printf(" Tesi: Secure Sonobuoy Telemetry (Bare-Metal Baseline)\r\n");
    printf("======================================================================================================\r\n");
    printf("| Schema                     | Paradigma              | Scambiati    | Tempo Medio(us)| Cicli/Op     | Stack (B)   |\r\n");
    printf("|----------------------------|------------------------|--------------|----------------|--------------|-------------|\r\n");

    km_summary_t results[3];
    memset(results, 0, sizeof(results));

    bench_psk_kdf(&results[0]);
    bench_symmetric_handshake(&results[1]);
    bench_x25519(&results[2]);

    for (int i = 0; i < 3; i++) {
        printf("| %-26s | %-22s | %-10u B | %-14.2f | %-12u | %-9u B |\r\n",
               results[i].scheme_name,
               results[i].paradigm,
               (unsigned)results[i].exchanged_bytes,
               results[i].avg_latency_us,
               (unsigned)results[i].avg_cycles,
               (unsigned)results[i].stack_used_bytes);
    }
}
