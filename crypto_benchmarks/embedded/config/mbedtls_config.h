/* =============================================================================
 * mbedtls_config.h — Configurazione custom mbed TLS per sonobuoy bare-metal
 *
 * Solo i moduli strettamente necessari per il benchmark crittografico.
 * Questo file sostituisce il default mbedtls/mbedtls_config.h
 * =========================================================================== */
#ifndef MBEDTLS_CUSTOM_CONFIG_H
#define MBEDTLS_CUSTOM_CONFIG_H

/* ---- Cifrari AEAD (sostituiscono OpenSSL EVP_*) ---- */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C
#define MBEDTLS_CIPHER_C

/* ---- Key Derivation (sostituisce Libsodium crypto_kdf / HKDF) ---- */
#define MBEDTLS_HKDF_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_MD_C

/* ---- ECDH X25519 (sostituisce Libsodium crypto_kx) ---- */
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_BIGNUM_C

/* ---- HMAC per Symmetric Handshake (sostituisce Libsodium crypto_auth) ---- */
#define MBEDTLS_SHA256_C
/* HMAC è integrato in mbedtls_md_hmac_* — non serve define separato */

/* ---- RNG: CTR-DRBG alimentato da hardware (sostituisce /dev/urandom) ---- */
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_NO_PLATFORM_ENTROPY    /* no /dev/urandom, no OS entropy */

/* ---- Platform bare-metal ---- */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY        /* hook per allocatore custom */
/* Opzionale: arena statica al posto di malloc
 * #define MBEDTLS_MEMORY_BUFFER_ALLOC_C
 */

/* ---- Rimuovi tutto ciò che non serve (riduce code size) ---- */
/* NO TLS, NO X.509, NO PEM, NO sockets */
/* NO MBEDTLS_NET_C */
/* NO MBEDTLS_SSL_TLS_C */
/* NO MBEDTLS_X509_CRT_PARSE_C */
/* NO MBEDTLS_PEM_PARSE_C */
/* NO MBEDTLS_FS_IO */

/* ---- Ottimizzazioni ---- */
#define MBEDTLS_AES_ROM_TABLES         /* S-box in Flash, risparmia ~8KB RAM */
/* #define MBEDTLS_AES_FEWER_TABLES */  /* ulteriore risparmio, leggero calo perf */

/* ---- Self-test (utile in debug, disattivare in produzione) ---- */
#define MBEDTLS_SELF_TEST

/* ---- Necessario per il funzionamento interno ---- */
#define MBEDTLS_PLATFORM_UTIL_C
#define MBEDTLS_ERROR_C

#endif /* MBEDTLS_CUSTOM_CONFIG_H */
