/* =============================================================================
 * bench_core.c — Implementazione dell'engine di benchmark bare-metal
 *
 * Mantiene la stessa logica di campionamento e gli stessi output CSV
 * dei benchmark Linux originali (run_benchmark_suite in benchmark_core.hpp).
 * =========================================================================== */

#include "bench_core.h"

/* Buffer statici globali per evitare qualsiasi malloc() */
static uint8_t s_payload_buf[MAX_PAYLOAD_SIZE];
static uint8_t s_ciphertext_buf[MAX_CIPHERTEXT_SIZE];

static bool s_bulk_header_printed = false;
static bool s_km_header_printed = false;

void print_bulk_csv_header(void) {
    if (!s_bulk_header_printed) {
        /* Esattamente l'header atteso da analyze_benchmarks.py per bulk_encryption_raw.csv */
        printf("algorithm,payload_bytes,added_bytes,sample_id,latency_us,cycles_per_op,cycles_per_byte,energy_uj,ram_kb\r\n");
        s_bulk_header_printed = true;
    }
}

void print_key_mgmt_csv_header(void) {
    if (!s_km_header_printed) {
        /* Esattamente l'header atteso da analyze_benchmarks.py per key_management_raw.csv */
        printf("category,scheme,paradigm,exchanged_bytes,sample_id,latency_us,cycles,energy_uj,ram_kb\r\n");
        s_km_header_printed = true;
    }
}

void run_aead_benchmark(const aead_algorithm_t *algo,
                        const size_t *packet_sizes,
                        size_t num_sizes,
                        int iterations) {
    if (!algo || !algo->process) return;

    if (algo->init) {
        if (algo->init() != 0) {
            printf("[BENCH] ERRORE: inizializzazione fallita per %s\r\n", algo->name);
            return;
        }
    }

    printf("\r\n======================================================================================================\r\n");
    printf(" ALGORITMO: %s\r\n", algo->name);
    printf("======================================================================================================\r\n");
    printf("| Payload   | Overhead  | Time (us)    | Cycles/Op    | Cycles/Byte  | Stack (B)   |\r\n");
    printf("|-----------|-----------|--------------|--------------|--------------|-------------|\r\n");

    /* Warm-up iniziale contatori */
    (void)hal_read_cycles();

    for (size_t idx = 0; idx < num_sizes; idx++) {
        size_t size = packet_sizes[idx];
        if (size > MAX_PAYLOAD_SIZE) {
            printf("[BENCH] Skip size %u: eccede MAX_PAYLOAD_SIZE (%u)\r\n", (unsigned)size, (unsigned)MAX_PAYLOAD_SIZE);
            continue;
        }

        /* Inizializza payload fisso 0x42 come nel codice Linux */
        memset(s_payload_buf, 0x42, size);
        size_t ct_len = 0;

        /* --- FASE 1: WARM-UP (100 iterazioni) --- */
        for (int w = 0; w < AEAD_WARMUP_ITERATIONS; w++) {
            algo->process(s_payload_buf, size, s_ciphertext_buf, &ct_len);
            do_not_optimize_buffer(s_ciphertext_buf, ct_len);
        }

        /* --- FASE 2: MISURAZIONE WATERMARK STACK --- */
        hal_stack_paint();

        /* --- FASE 3: MISURAZIONE CICLI E LATENZA --- */
        uint32_t start_cycles = hal_read_cycles();

        for (int i = 0; i < iterations; i++) {
            uint32_t s_start = hal_read_cycles();
            algo->process(s_payload_buf, size, s_ciphertext_buf, &ct_len);
            do_not_optimize_buffer(s_ciphertext_buf, ct_len);
            uint32_t s_end = hal_read_cycles();

            uint32_t single_op_cycles = (s_end >= s_start) ? (s_end - s_start) : 0;
            double s_us = cycles_to_us(single_op_cycles);

            /* In bare-metal senza sonde esterne, RAPL non c'e' (-1.000).
             * ram_kb contiene qui la quantita' di stack usata in byte o KB.
             * Per compatibilita' con gli script usiamo stack watermark. */
            /* Stampa linea CSV campionata singolarmente per sample_id (come in Linux) */
            /* Se si vuole evitare saturazione UART, si puo' inviare a batch o solo riassunto,
             * ma per fedelta' al 100% con Linux stampiamo il record compatibile CSV: */
            #if defined(EMIT_RAW_CSV_SAMPLES)
            printf("\"%s\",%u,%u,%d,%.4f,%u,%.2f,-1.000,%u\r\n",
                   algo->name,
                   (unsigned)size,
                   (unsigned)(ct_len > size ? ct_len - size : algo->fixed_overhead),
                   i + 1,
                   s_us,
                   (unsigned)single_op_cycles,
                   size > 0 ? ((double)single_op_cycles / (double)size) : 0.0,
                   (unsigned)hal_stack_used_bytes());
            #endif
        }

        uint32_t end_cycles = hal_read_cycles();
        uint32_t stack_used = hal_stack_used_bytes();

        uint32_t total_cycles = (end_cycles >= start_cycles) ? (end_cycles - start_cycles) : 0;
        uint32_t avg_cycles_per_op = (iterations > 0) ? (total_cycles / (uint32_t)iterations) : 0;
        double avg_elapsed_us = cycles_to_us(avg_cycles_per_op);
        double cycles_per_byte = (size > 0) ? ((double)avg_cycles_per_op / (double)size) : 0.0;
        size_t added_bytes = (ct_len >= size) ? (ct_len - size) : algo->fixed_overhead;

        /* Tabella a video leggibile su PuTTY */
        printf("| %-8u B | +%-7u B | %-12.2f | %-12u | %-12.2f | %-9u B |\r\n",
               (unsigned)size,
               (unsigned)added_bytes,
               avg_elapsed_us,
               (unsigned)avg_cycles_per_op,
               cycles_per_byte,
               (unsigned)stack_used);
    }
}
