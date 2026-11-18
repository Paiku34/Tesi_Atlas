#include "serial_port.hpp"
#include "radio_packet.hpp"
#include "crypto_engine.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <thread>
#include <iomanip>
#include <numeric>
#include <algorithm>
#include <sodium.h>

#ifdef __linux__
#include <sys/resource.h>
#endif

using namespace radio;

struct TelemetryResult {
    std::string algo_name;
    size_t payload_bytes;
    double crypto_tx_us;
    double rtt_ms;
    bool ack_received;
    size_t frame_bytes;
    double overhead_pct;
    double throughput_bps;
    int retries;
};

struct KemResult {
    std::string kem_name;
    double encaps_us;
    double rtt_ms;
    bool ack_received;
    size_t ciphertext_bytes;
    size_t shared_secret_bytes;
    size_t frame_bytes;
    int retries;
};

static int adaptive_timeout_ms(size_t frame_bytes, int base_timeout_ms = 1500) {
    // A 57600 baud, 1 byte ~= 0.17 ms
    double tx_time_ms = (static_cast<double>(frame_bytes) * 10.0 / 57600.0) * 1000.0;
    int estimated_ms = static_cast<int>(tx_time_ms * 2.5) + base_timeout_ms;
    return std::max(base_timeout_ms, estimated_ms);
}

static bool wait_for_ack(SerialPort& serial, uint32_t expected_seq, int timeout_ms, double& out_rtt_ms,
                         const std::chrono::steady_clock::time_point& t_tx, bool check_seq = true) {
    uint8_t in_magic = 0;
    auto ack_start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - ack_start).count() < timeout_ms) {
        if (serial.read_byte(in_magic, 100) && in_magic == MAGIC_ACK) {
            AckPacket ack;
            ack.magic = in_magic;
            if (serial.read_exact(reinterpret_cast<uint8_t*>(&ack) + 1, sizeof(AckPacket) - 1, 300)) {
                if (ack.status_code == 0 && (!check_seq || ack.seq_num == expected_seq)) {
                    out_rtt_ms = std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - t_tx).count();
                    return true;
                }
            }
        }
    }
    return false;
}

void run_telemetry_burst(SerialPort& serial,
                         CryptoEngine& crypto,
                         CryptoAlgorithm algo,
                         const std::string& algo_name,
                         size_t payload_size,
                         int num_packets,
                         std::vector<TelemetryResult>& results,
                         uint32_t& seq_counter,
                         int max_retries = 2) {

    std::cout << "  > Test " << algo_name << " | Payload: " << payload_size << " B | " << num_packets << " pacchetti...\n";
    std::vector<uint8_t> dummy_payload(payload_size);
    for (size_t i = 0; i < payload_size; ++i) {
        dummy_payload[i] = static_cast<uint8_t>((i + 1) & 0xFF);
    }

    for (int p = 0; p < num_packets; ++p) {
        uint32_t current_seq = ++seq_counter;

        // 1. Cifratura in memoria con misura accurata
        auto t_start_crypto = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> ciphertext;
        uint8_t tag[AEAD_TAG_LEN];
        bool ok = crypto.encrypt(algo, current_seq, dummy_payload.data(), dummy_payload.size(), ciphertext, tag);
        auto t_end_crypto = std::chrono::high_resolution_clock::now();

        if (!ok) {
            std::cerr << "    [ERR] Cifratura fallita per seq " << current_seq << "\n";
            continue;
        }

        double crypto_time_us = std::chrono::duration<double, std::micro>(t_end_crypto - t_start_crypto).count();

        TelemetryHeader header{MAGIC_TELEMETRY, static_cast<uint8_t>(algo), current_seq, static_cast<uint16_t>(ciphertext.size())};
        size_t tag_len = (algo == CryptoAlgorithm::BASELINE_CLEAR) ? 0 : AEAD_TAG_LEN;

        std::vector<uint8_t> frame(sizeof(header) + ciphertext.size() + tag_len);
        std::memcpy(frame.data(), &header, sizeof(header));
        std::memcpy(frame.data() + sizeof(header), ciphertext.data(), ciphertext.size());
        if (tag_len > 0) {
            std::memcpy(frame.data() + sizeof(header) + ciphertext.size(), tag, tag_len);
        }

        size_t frame_bytes = frame.size();
        double overhead_pct = ((static_cast<double>(frame_bytes) - payload_size) / payload_size) * 100.0;

        // 3. Trasmissione su seriale con ritrasmissione se timeout
        bool ack_ok = false;
        double rtt_ms = -1.0;
        int retries_used = 0;

        for (int r = 0; r <= max_retries; ++r) {
            auto t_tx = std::chrono::steady_clock::now();
            serial.write_exact(frame.data(), frame.size());

            int to_ms = adaptive_timeout_ms(frame_bytes, 1000);
            if (wait_for_ack(serial, current_seq, to_ms, rtt_ms, t_tx, true)) {
                ack_ok = true;
                break;
            }
            retries_used++;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        double throughput_bps = (ack_ok && rtt_ms > 0) ? (payload_size * 8.0 / (rtt_ms / 1000.0)) : 0.0;
        results.push_back({algo_name, payload_size, crypto_time_us, rtt_ms, ack_ok, frame_bytes, overhead_pct, throughput_bps, retries_used});

        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
}

// -----------------------------------------------------------------------------
// Test KEM Handshake autenticato con PSK (conforme a bench_mlkem / bench_key_management)
// -----------------------------------------------------------------------------
void run_kem_handshake_test(SerialPort& serial,
                            CryptoEngine& crypto,
                            KemAlgorithm algo,
                            const std::string& kem_name,
                            int num_handshakes,
                            std::vector<KemResult>& kem_results) {

    std::cout << "\n>>> INIZIO KEM HANDSHAKE SU CANALE RADIO: " << kem_name << " <<<\n";

    for (int h = 0; h < num_handshakes; ++h) {
        // Step 1: Ricevi la Challenge GS (Downlink)
        // La GS trasmette: Magic (0x43) + KemID (1B) + gs_nonce (32B) + auth_tag (16B) = 50 Byte
        KemChallengeHeader chlng;
        uint8_t magic = 0;
        bool got_challenge = false;

        auto t_wait_chlng = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now() - t_wait_chlng).count() < 3000) {
            if (serial.read_byte(magic, 100) && magic == MAGIC_KEM_CHLNG) {
                chlng.magic = magic;
                if (serial.read_exact(reinterpret_cast<uint8_t*>(&chlng) + 1, sizeof(KemChallengeHeader) - 1, 500)) {
                    if (chlng.kem_id == static_cast<uint8_t>(algo)) {
                        got_challenge = true;
                        break;
                    }
                }
            }
        }

        if (!got_challenge) {
            std::cerr << "  [WARN] Timeout attesa Challenge GS per " << kem_name << "\n";
            continue;
        }

        // Step 2: Verifica autenticità della Challenge GS tramite PSK
        uint8_t challenge_data[1 + HANDSHAKE_NONCE_BYTES];
        challenge_data[0] = chlng.kem_id;
        std::memcpy(challenge_data + 1, chlng.gs_nonce, HANDSHAKE_NONCE_BYTES);

        if (!crypto.verify_psk_mac(challenge_data, sizeof(challenge_data), chlng.auth_tag)) {
            std::cerr << "  [AUTH_FAIL] Challenge GS non valida (MAC PSK errato)!\n";
            continue;
        }

        // Step 3: Operazione KEM locale misurata (conforme al benchmark della boa)
        auto t_encap_start = std::chrono::high_resolution_clock::now();
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> shared_secret;
        bool ok = crypto.kem_encapsulate(algo, ciphertext, shared_secret);
        auto t_encap_end = std::chrono::high_resolution_clock::now();

        if (!ok) {
            std::cerr << "  [ERR] KEM encapsulate fallito per " << kem_name << "\n";
            continue;
        }
        double encap_us = std::chrono::duration<double, std::micro>(t_encap_end - t_encap_start).count();

        // Genera Nonce Boa (32B)
        uint8_t buoy_nonce[HANDSHAKE_NONCE_BYTES];
        randombytes_buf(buoy_nonce, sizeof(buoy_nonce));

        // Calcola MAC PSK sulla risposta (gs_nonce + buoy_nonce + ciphertext)
        std::vector<uint8_t> auth_input;
        auth_input.reserve(HANDSHAKE_NONCE_BYTES * 2 + ciphertext.size());
        auth_input.insert(auth_input.end(), chlng.gs_nonce, chlng.gs_nonce + HANDSHAKE_NONCE_BYTES);
        auth_input.insert(auth_input.end(), buoy_nonce, buoy_nonce + HANDSHAKE_NONCE_BYTES);
        auth_input.insert(auth_input.end(), ciphertext.begin(), ciphertext.end());

        uint8_t response_tag[PSK_TAG_BYTES];
        crypto.compute_psk_mac(auth_input.data(), auth_input.size(), response_tag);

        // Step 4: Assembla e trasmette il frame di risposta
        KemResponseHeader resp_hdr;
        resp_hdr.magic = MAGIC_KEM_RESP;
        resp_hdr.kem_id = static_cast<uint8_t>(algo);
        resp_hdr.ct_len = static_cast<uint16_t>(ciphertext.size());
        std::memcpy(resp_hdr.buoy_nonce, buoy_nonce, HANDSHAKE_NONCE_BYTES);

        std::vector<uint8_t> frame(sizeof(resp_hdr) + ciphertext.size() + PSK_TAG_BYTES);
        std::memcpy(frame.data(), &resp_hdr, sizeof(resp_hdr));
        std::memcpy(frame.data() + sizeof(resp_hdr), ciphertext.data(), ciphertext.size());
        std::memcpy(frame.data() + sizeof(resp_hdr) + ciphertext.size(), response_tag, PSK_TAG_BYTES);

        auto t_tx = std::chrono::steady_clock::now();
        serial.write_exact(frame.data(), frame.size());

        // Attesa ACK finale di sessione
        double rtt_ms = -1.0;
        int to_ms = adaptive_timeout_ms(frame.size(), 2000);
        bool ack_ok = wait_for_ack(serial, 0, to_ms, rtt_ms, t_tx, false);

        if (ack_ok) {
            const char* label = (algo == KemAlgorithm::X25519) ? HKDF_LABEL_ECDH : HKDF_LABEL_MLKEM;
            crypto.derive_session_keys(label, shared_secret.data(), shared_secret.size());
            std::cout << "  [OK Handshake " << (h + 1) << "/" << num_handshakes << "] "
                      << "CT: " << ciphertext.size() << " B | Encap: "
                      << std::fixed << std::setprecision(1) << encap_us << " us | RTT: "
                      << std::setprecision(1) << rtt_ms << " ms\n";
        } else {
            std::cout << "  [TIMEOUT Handshake " << (h + 1) << "/" << num_handshakes << "]\n";
        }

        kem_results.push_back({kem_name, encap_us, rtt_ms, ack_ok, ciphertext.size(), shared_secret.size(), frame.size(), ack_ok ? 0 : 1});
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int main(int argc, char* argv[]) {
    std::string device = "/dev/ttyUSB0";
    int baudrate = 57600;
    std::string prov_dir = "provisioning";
    std::string data_dir = "data";

    if (argc > 1) device = argv[1];
    if (argc > 2) baudrate = std::stoi(argv[2]);
    if (argc > 3) prov_dir = argv[3];
    if (argc > 4) data_dir = argv[4];

    std::string csv_out = data_dir + "/radio_telemetry_results.csv";
    std::string kem_csv_out = data_dir + "/radio_kem_results.csv";

    std::cout << "========================================================\n";
    std::cout << "  ZENO ATLAS - BOA TELEMETRY NODE (Raspberry Pi)\n";
    std::cout << "  Device: " << device << " (" << baudrate << " baud)\n";
    std::cout << "  Provisioning dir: " << prov_dir << "\n";
    std::cout << "========================================================\n\n";

    SerialPort serial;
    if (!serial.open_device(device, baudrate)) {
        std::cerr << "Impossibile aprire il dispositivo " << device << "\n";
        return 1;
    }

    CryptoEngine crypto;
    if (!crypto.load_provisioning(prov_dir, false)) {
        std::cerr << "[FATAL] Fallimento caricamento provisioning per la Boa!\n"
                  << "        Esegui prima './generate_keys " << prov_dir << "'\n";
        return 1;
    }

    uint32_t seq_counter = 1000;
    std::vector<TelemetryResult> results;
    std::vector<KemResult> kem_results;

    const std::vector<size_t> payloads = {8, 16, 32, 64, 128, 256};
    const int PACKETS_PER_RUN = 50;

    // 1. KEM Handshake Suite
    const std::vector<std::pair<KemAlgorithm, std::string>> kem_algos = {
        {KemAlgorithm::X25519,      "X25519 (Libsodium)"},
        {KemAlgorithm::ML_KEM_512,  "ML-KEM-512 (liboqs)"},
        {KemAlgorithm::ML_KEM_768,  "ML-KEM-768 (liboqs)"},
        {KemAlgorithm::ML_KEM_1024, "ML-KEM-1024 (liboqs)"}
    };

    for (const auto& ka : kem_algos) {
        run_kem_handshake_test(serial, crypto, ka.first, ka.second, 10, kem_results);
    }

    // 2. AEAD Telemetry Suite
    const std::vector<std::pair<CryptoAlgorithm, std::string>> algos = {
        {CryptoAlgorithm::BASELINE_CLEAR,   "Baseline (In Chiaro)"},
        {CryptoAlgorithm::ASCON_128,        "Ascon-AEAD128 (ascon-c)"},
        {CryptoAlgorithm::AES_256_GCM,      "AES-256-GCM (OpenSSL)"},
        {CryptoAlgorithm::CHACHA20_SODIUM,  "ChaCha20-Poly1305 (Libsodium)"},
        {CryptoAlgorithm::CHACHA20_OPENSSL, "ChaCha20-Poly1305 (OpenSSL)"}
    };

    for (const auto& alg : algos) {
        std::cout << "\n--- AVVIO TEST TELEMETRIA: " << alg.second << " ---\n";
        for (size_t sz : payloads) {
            run_telemetry_burst(serial, crypto, alg.first, alg.second, sz, PACKETS_PER_RUN, results, seq_counter);
        }
    }

    // Esportazione CSV Telemetria
    {
        std::ofstream out(csv_out);
        out << "Algorithm,Payload_B,Crypto_Time_us,RTT_ms,Success,Frame_B,Overhead_pct,Throughput_bps,Retries\n";
        for (const auto& r : results) {
            out << r.algo_name << "," << r.payload_bytes << ","
                << std::fixed << std::setprecision(3) << r.crypto_tx_us << ","
                << (r.ack_received ? std::to_string(r.rtt_ms) : "TIMEOUT") << ","
                << (r.ack_received ? 1 : 0) << ","
                << r.frame_bytes << ","
                << std::setprecision(2) << r.overhead_pct << ","
                << std::setprecision(1) << r.throughput_bps << ","
                << r.retries << "\n";
        }
    }

    // Esportazione CSV KEM
    if (!kem_results.empty()) {
        std::ofstream out(kem_csv_out);
        out << "KEM_Algorithm,Encaps_Time_us,RTT_ms,Success,Ciphertext_B,SharedSecret_B,Frame_B,Retries\n";
        for (const auto& r : kem_results) {
            out << r.kem_name << ","
                << std::fixed << std::setprecision(3) << r.encaps_us << ","
                << (r.ack_received ? std::to_string(r.rtt_ms) : "TIMEOUT") << ","
                << (r.ack_received ? 1 : 0) << ","
                << r.ciphertext_bytes << ","
                << r.shared_secret_bytes << ","
                << r.frame_bytes << ","
                << r.retries << "\n";
        }
    }

    std::cout << "\n[OK] Campagna completata con successo!\n"
              << "     File generati: " << csv_out << " e " << kem_csv_out << "\n";
    return 0;
}
