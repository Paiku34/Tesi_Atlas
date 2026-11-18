#include "serial_port.hpp"
#include "radio_packet.hpp"
#include "crypto_engine.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <csignal>
#include <thread>
#include <sodium.h>

using namespace radio;

static volatile bool g_running = true;
void sigint_handler(int) {
    g_running = false;
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

    std::string csv_out = data_dir + "/ground_station_log.csv";

    std::signal(SIGINT, sigint_handler);

    std::cout << "========================================================\n";
    std::cout << "  ZENO ATLAS - GROUND STATION (Zeno PC Receiver)\n";
    std::cout << "  Device: " << device << " (" << baudrate << " baud)\n";
    std::cout << "  Provisioning dir: " << prov_dir << "\n";
    std::cout << "  Log CSV: " << csv_out << "\n";
    std::cout << "========================================================\n\n";

    SerialPort serial;
    if (!serial.open_device(device, baudrate)) {
        std::cerr << "Impossibile aprire il dispositivo seriale " << device << "\n";
        return 1;
    }

    CryptoEngine crypto;
    if (!crypto.load_provisioning(prov_dir, true)) {
        std::cerr << "[FATAL] Fallimento caricamento provisioning per la Ground Station!\n";
        return 1;
    }

    std::ofstream csv(csv_out);
    csv << "Timestamp_epoch_ms,Type,Id,Payload_B,Crypto_Time_us,Status\n";

    uint32_t last_seen_seq = 0;
    size_t total_telemetry = 0;
    size_t total_kem = 0;
    size_t auth_failures = 0;
    size_t replay_drops = 0;

    // Buffer per memorizzare l'ultimo nonce GS emesso
    uint8_t current_gs_nonce[HANDSHAKE_NONCE_BYTES] = {0};
    uint8_t current_kem_id = 0;
    size_t current_kem_count = 0;
    const size_t KEM_HANDSHAKES_PER_ALGO = 10;
    auto t_last_challenge = std::chrono::steady_clock::now();

    // Trigger iniziale per inviare periodicamente sfide KEM se non arrivano pacchetti
    auto send_challenge = [&](KemAlgorithm alg) {
        current_kem_id = static_cast<uint8_t>(alg);
        randombytes_buf(current_gs_nonce, sizeof(current_gs_nonce));

        uint8_t challenge_data[1 + HANDSHAKE_NONCE_BYTES];
        challenge_data[0] = current_kem_id;
        std::memcpy(challenge_data + 1, current_gs_nonce, HANDSHAKE_NONCE_BYTES);

        KemChallengeHeader chlng_hdr;
        chlng_hdr.magic = MAGIC_KEM_CHLNG;
        chlng_hdr.kem_id = current_kem_id;
        std::memcpy(chlng_hdr.gs_nonce, current_gs_nonce, HANDSHAKE_NONCE_BYTES);
        crypto.compute_psk_mac(challenge_data, sizeof(challenge_data), chlng_hdr.auth_tag);

        serial.write_exact(reinterpret_cast<const uint8_t*>(&chlng_hdr), sizeof(chlng_hdr));
        t_last_challenge = std::chrono::steady_clock::now();
    };

    std::cout << "[OK] Ground station pronta. In ascolto...\n";

    // Invia prima sfida di default (X25519)
    send_challenge(KemAlgorithm::X25519);

    while (g_running) {
        uint8_t magic = 0;
        if (!serial.read_byte(magic, 500)) {
            // Se inattivo da più di 4 secondi, reinvia la sfida per facilitare il sync all'avvio della boa
            auto elapsed_s = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - t_last_challenge).count();
            if (elapsed_s >= 4) {
                send_challenge(static_cast<KemAlgorithm>(current_kem_id));
            }
            continue;
        }

        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // -----------------------------------------------------------------
        // RICEZIONE TELEMETRIA AEAD
        // -----------------------------------------------------------------
        if (magic == MAGIC_TELEMETRY) {
            TelemetryHeader header;
            header.magic = magic;

            if (!serial.read_exact(reinterpret_cast<uint8_t*>(&header) + 1, sizeof(TelemetryHeader) - 1, 200)) {
                serial.flush();
                continue;
            }

            auto algo = static_cast<CryptoAlgorithm>(header.algo_id);
            size_t tag_len = (algo == CryptoAlgorithm::BASELINE_CLEAR) ? 0 : AEAD_TAG_LEN;

            std::vector<uint8_t> ciphertext(header.len);
            uint8_t in_tag[AEAD_TAG_LEN] = {0};

            bool read_ok = serial.read_exact(ciphertext.data(), ciphertext.size(), 500);
            if (read_ok && tag_len > 0) {
                read_ok = serial.read_exact(in_tag, tag_len, 200);
            }

            if (!read_ok) {
                serial.flush();
                continue;
            }

            total_telemetry++;
            AckPacket ack{MAGIC_ACK, header.seq_num, 0x00};

            if (header.seq_num == last_seen_seq) {
                // Ritrasmissione dell'ultimo pacchetto: reinvia ACK OK (0x00) senza riprocessare
                ack.status_code = 0x00;
                serial.write_exact(reinterpret_cast<uint8_t*>(&ack), sizeof(ack));
                continue;
            } else if (header.seq_num < last_seen_seq) {
                // Pacchetto anomalo obsoleto: scarta
                replay_drops++;
                continue;
            }

            auto t_dec_start = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> plaintext;
            bool ok = crypto.decrypt(algo, header.seq_num, ciphertext.data(), ciphertext.size(), in_tag, plaintext);
            auto t_dec_end = std::chrono::high_resolution_clock::now();
            double dec_time_us = std::chrono::duration<double, std::micro>(t_dec_end - t_dec_start).count();

            if (!ok) {
                auth_failures++;
                ack.status_code = 0x02; // Auth Fail
                csv << now_ms << ",TELEMETRY," << header.seq_num << "," << header.len << ","
                    << std::fixed << std::setprecision(3) << dec_time_us << ",AUTH_FAIL\n";
            } else {
                last_seen_seq = header.seq_num;
                std::cout << "[OK Telemetria] Rx Seq " << header.seq_num
                          << " | Algo: " << static_cast<int>(header.algo_id)
                          << " | Len: " << plaintext.size() << " B | Decrypt: "
                          << std::fixed << std::setprecision(1) << dec_time_us << " us\n";
                csv << now_ms << ",TELEMETRY," << header.seq_num << "," << plaintext.size() << ","
                    << std::fixed << std::setprecision(3) << dec_time_us << ",OK\n";
            }

            serial.write_exact(reinterpret_cast<uint8_t*>(&ack), sizeof(ack));
        }
        // -----------------------------------------------------------------
        // RICEZIONE RISPOSTA KEM HANDSHAKE
        // -----------------------------------------------------------------
        else if (magic == MAGIC_KEM_RESP) {
            KemResponseHeader resp_hdr;
            resp_hdr.magic = magic;

            if (!serial.read_exact(reinterpret_cast<uint8_t*>(&resp_hdr) + 1, sizeof(KemResponseHeader) - 1, 200)) {
                serial.flush();
                continue;
            }

            std::vector<uint8_t> ciphertext(resp_hdr.ct_len);
            uint8_t response_tag[PSK_TAG_BYTES];

            if (!serial.read_exact(ciphertext.data(), ciphertext.size(), 3000) ||
                !serial.read_exact(response_tag, PSK_TAG_BYTES, 300)) {
                serial.flush();
                continue;
            }

            total_kem++;
            auto kem_algo = static_cast<KemAlgorithm>(resp_hdr.kem_id);

            // Step 1: Verifica del MAC PSK sulla risposta della boa
            std::vector<uint8_t> auth_input;
            auth_input.reserve(HANDSHAKE_NONCE_BYTES * 2 + ciphertext.size());
            auth_input.insert(auth_input.end(), current_gs_nonce, current_gs_nonce + HANDSHAKE_NONCE_BYTES);
            auth_input.insert(auth_input.end(), resp_hdr.buoy_nonce, resp_hdr.buoy_nonce + HANDSHAKE_NONCE_BYTES);
            auth_input.insert(auth_input.end(), ciphertext.begin(), ciphertext.end());

            bool psk_valid = crypto.verify_psk_mac(auth_input.data(), auth_input.size(), response_tag);
            if (!psk_valid) {
                auth_failures++;
                AckPacket ack{MAGIC_ACK, 0, 0x02};
                serial.write_exact(reinterpret_cast<uint8_t*>(&ack), sizeof(ack));
                csv << now_ms << ",KEM," << static_cast<int>(resp_hdr.kem_id) << "," << ciphertext.size() << ",0.000,PSK_AUTH_FAIL\n";
                continue;
            }

            // Step 2: Decapsulamento locale (misurato)
            auto t_dec_start = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> shared_secret;
            bool ok = crypto.kem_decapsulate(kem_algo, ciphertext.data(), ciphertext.size(), shared_secret);
            auto t_dec_end = std::chrono::high_resolution_clock::now();
            double dec_time_us = std::chrono::duration<double, std::micro>(t_dec_end - t_dec_start).count();

            AckPacket ack{MAGIC_ACK, 0, static_cast<uint8_t>(ok ? 0x00 : 0x02)};
            serial.write_exact(reinterpret_cast<uint8_t*>(&ack), sizeof(ack));

            if (ok) {
                const char* label = (kem_algo == KemAlgorithm::X25519) ? HKDF_LABEL_ECDH : HKDF_LABEL_MLKEM;
                crypto.derive_session_keys(label, shared_secret.data(), shared_secret.size());

                std::cout << "[OK KEM Handshake] Alg: " << static_cast<int>(resp_hdr.kem_id)
                          << " | CT Len: " << ciphertext.size() << " B | Decaps: "
                          << std::fixed << std::setprecision(1) << dec_time_us << " us\n";
                csv << now_ms << ",KEM," << static_cast<int>(resp_hdr.kem_id) << "," << ciphertext.size() << ","
                    << std::fixed << std::setprecision(3) << dec_time_us << ",OK\n";

                current_kem_count++;
                if (current_kem_count >= KEM_HANDSHAKES_PER_ALGO) {
                    current_kem_count = 0;
                    auto next_id = static_cast<uint8_t>(kem_algo) + 1;
                    if (next_id > static_cast<uint8_t>(KemAlgorithm::ML_KEM_1024)) next_id = 1;
                    send_challenge(static_cast<KemAlgorithm>(next_id));
                } else {
                    send_challenge(kem_algo);
                }
            } else {
                csv << now_ms << ",KEM," << static_cast<int>(resp_hdr.kem_id) << "," << ciphertext.size() << ","
                    << std::fixed << std::setprecision(3) << dec_time_us << ",DECAPS_FAIL\n";
            }
        }
    }

    csv.close();
    std::cout << "\n=== STATISTICHE SESSIONE ===\n"
              << "Telemetrie ricevute:   " << total_telemetry << "\n"
              << "KEM Handshake eseguiti:" << total_kem << "\n"
              << "Replay scartati:       " << replay_drops << "\n"
              << "Errori Autenticazione: " << auth_failures << "\n";

    return 0;
}
