/* =============================================================================
 * bench_mlkem.c — Porting Bare-Metal ML-KEM (Post-Quantum)
 *
 * Sostituisce:
 *   - bench_mlkem.cpp (liboqs C++)
 *
 * Su bare-metal liboqs non e' compatibile (richiede OS/POSIX e malloc massiccio).
 * Viene predisposto per usare la reference C pura di "pqcrystals/kyber" oppure
 * la libreria ottimizzata "pqm4" per Cortex-M4.
 * =========================================================================== */

#include "bench_core.h"

#ifdef HAS_MLKEM
/* Header reference C Kyber/ML-KEM */
#include "kem.h"

void run_all_mlkem_benchmarks(void) {
    printf("\r\n=======================================================================================================\r\n");
    printf(" BENCHMARK: ML-KEM POST-QUANTUM (Reference C / pqm4) — FASI GRANULARI\r\n");
    printf("=======================================================================================================\r\n");
    printf("| Variante     | Fase            | Payload          | Tempo(us)    | Cicli/Op     | Stack (B)   |\r\n");
    printf("|--------------|-----------------|------------------|--------------|--------------|-------------|\r\n");

    /* Buffer statici ML-KEM (es. Kyber-512) */
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss_sender[CRYPTO_BYTES];
    uint8_t ss_receiver[CRYPTO_BYTES];

    const int iters = 100; /* Su MCU il PQC richiede molti cicli, 100 iters sono sufficienti */

    /* 1. KeyGen */
    hal_stack_paint();
    uint32_t c0 = hal_read_cycles();
    for (int i = 0; i < iters; i++) {
        crypto_kem_keypair(pk, sk);
        DO_NOT_OPTIMIZE_AWAY(pk[0]);
    }
    uint32_t c1 = hal_read_cycles();
    uint32_t kg_cycles = (c1 >= c0) ? ((c1 - c0) / iters) : 0;
    uint32_t kg_stack = hal_stack_used_bytes();

    /* 2. Encaps */
    hal_stack_paint();
    c0 = hal_read_cycles();
    for (int i = 0; i < iters; i++) {
        crypto_kem_enc(ct, ss_sender, pk);
        DO_NOT_OPTIMIZE_AWAY(ct[0]);
    }
    c1 = hal_read_cycles();
    uint32_t enc_cycles = (c1 >= c0) ? ((c1 - c0) / iters) : 0;
    uint32_t enc_stack = hal_stack_used_bytes();

    /* 3. Decaps */
    hal_stack_paint();
    c0 = hal_read_cycles();
    for (int i = 0; i < iters; i++) {
        crypto_kem_dec(ss_receiver, ct, sk);
        DO_NOT_OPTIMIZE_AWAY(ss_receiver[0]);
    }
    c1 = hal_read_cycles();
    uint32_t dec_cycles = (c1 >= c0) ? ((c1 - c0) / iters) : 0;
    uint32_t dec_stack = hal_stack_used_bytes();

    printf("| ML-KEM-512   | KeyGen          | %-16s | %-12.2f | %-12u | %-11u |\r\n",
           "800 B (PK)", cycles_to_us(kg_cycles), (unsigned)kg_cycles, (unsigned)kg_stack);
    printf("| ML-KEM-512   | Encapsulation   | %-16s | %-12.2f | %-12u | %-11u |\r\n",
           "768 B (CT)", cycles_to_us(enc_cycles), (unsigned)enc_cycles, (unsigned)enc_stack);
    printf("| ML-KEM-512   | Decapsulation   | %-16s | %-12.2f | %-12u | %-11u |\r\n",
           "0 B (internal)", cycles_to_us(dec_cycles), (unsigned)dec_cycles, (unsigned)dec_stack);
    printf("| ML-KEM-512   | Handshake Total | %-16s | %-12.2f | %-12u | %-11u |\r\n",
           "1568 B Total", cycles_to_us(kg_cycles + enc_cycles + dec_cycles),
           (unsigned)(kg_cycles + enc_cycles + dec_cycles), (unsigned)enc_stack);
}

#else

void run_all_mlkem_benchmarks(void) {
    printf("\r\n=======================================================================================================\r\n");
    printf(" BENCHMARK: ML-KEM POST-QUANTUM\r\n");
    printf("=======================================================================================================\r\n");
    printf("[ML-KEM] TO BE IMPLEMENTED / Opzionale:\r\n");
    printf("  liboqs originale e' incompatibile con bare-metal (dipende da OS e glibc).\r\n");
    printf("  Per abilitare il benchmark PQC su bare-metal:\r\n");
    printf("  1. Clonare 'pqcrystals/kyber' (reference C) o 'pqm4' dentro 'embedded/lib/mlkem-c-ref'\r\n");
    printf("  2. Ricompilare con -DHAS_MLKEM=1 nel CMake\r\n");
    printf("  (Nota del documento ATLAS: per la boa GWB l'approccio primario raccomandato resta PSK).\r\n");
}

#endif /* HAS_MLKEM */
