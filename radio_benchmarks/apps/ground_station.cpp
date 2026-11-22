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
#include <cstring>
#include <sodium.h>

using namespace radio;

constexpr size_t MAX_VALID_PACKET_LEN = 4096;

static volatile bool g_running = true;
void sigint_handler(int) {
    g_running = false;
}

int main(int argc, char* argv[]) {
    std::string device = "/dev/ttyUSB0";
    int baudrate = 57600;
    std::string prov_dir = "provisioning";
    std::string data_dir = "data";
    int max_retries = 0;

    if (argc > 1) device = argv[1];
    if (argc > 2) baudrate = std::stoi(argv[2]);
    if (argc > 3) prov_dir = argv[3];
    if (argc > 4) data_dir = argv[4];
    if (argc > 5) max_retries = std::stoi(argv[5]);

    std::string csv_out = data_dir + "/ground_station_log.csv";
    std::string kem_csv_out = data_dir + "/ground_station_kem_results.csv";

    std::signal(SIGINT, sigint_handler);

    std::cout << "========================================================\n";
    std::cout << "  ZENO ATLAS - GROUND STATION (Zeno PC Receiver)\n";
    std::cout << "  Device: " << device << " (" << baudrate << " baud)\n";
    std::cout << "  Provisioning dir: " << prov_dir << "\n";
    std::cout << "  Max Retries: " << max_retries << "\n";
    std::cout << "  Log CSV: " << csv_out << "\n";
    std::cout << "  KEM CSV: " << kem_csv_out << "\n";
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
    csv << "Timestamp_epoch_ms,Type,Id,Payload_B,Status\n";

    std::ofstream kem_csv(kem_csv_out);
    kem_csv << "Timestamp_epoch_ms,KEM_Id,Attempt,E2E_Handshake_ms,Success,Ciphertext_B,Retries,Status\n";

    uint32_t last_seen_seq = 0;
    size_t total_telemetry = 0;
    size_t total_kem = 0;
    size_t auth_failures = 0;
    size_t replay_drops = 0;
    size_t corrupted_frames = 0;

    // Stato Handshake KEM guidato dalla Ground Station
    uint8_t current_gs_nonce[HANDSHAKE_NONCE_BYTES] = {0};
    uint8_t current_kem_id = static_cast<uint8_t>(KemAlgorithm::X25519);
    size_t current_kem_attempt = 0;
    int current_kem_retries = 0;
    const size_t KEM_HANDSHAKES_PER_ALGO = 50;
    bool kem_campaign_active = false;
    bool waiting_kem_response = false;
    std::chrono::steady_clock::time_point t_hs_attempt_start;
    std::chrono::steady_clock::time_point t_hs_send;

    auto send_challenge = [&](KemAlgorithm alg, bool is_retry = false) {
        current_kem_id = static_cast<uint8_t>(alg);
        auto now = std::chrono::steady_clock::now();
        if (!is_retry) {
            t_hs_attempt_start = now;
        }
        t_hs_send = now;

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
        waiting_kem_response = true;
    };

    auto advance_kem_state = [&]() {
        current_kem_retries = 0;
        current_kem_attempt++;
        if (current_kem_attempt >= KEM_HANDSHAKES_PER_ALGO) {
            current_kem_attempt = 0;
            uint8_t next_id = current_kem_id + 1;
            if (next_id > static_cast<uint8_t>(KemAlgorithm::ML_KEM_1024)) {
                kem_campaign_active = false;
                waiting_kem_response = false;
                std::cout << "[OK] Campagna KEM completata sulla Ground Station.\n";
                return;
            }
            current_kem_id = next_id;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        send_challenge(static_cast<KemAlgorithm>(current_kem_id), false);
    };

    auto handle_kem_failure_or_retry = [&](int64_t now_ms, size_t ct_len, const std::string& status_str) {
        if (current_kem_retries < max_retries) {
            current_kem_retries++;
            std::cout << "[RETRY KEM " << current_kem_retries << "/" << max_retries << "] Alg: "
                      << static_cast<int>(current_kem_id) << " | Tentativo "
                      << (current_kem_attempt + 1) << "/" << KEM_HANDSHAKES_PER_ALGO
                      << " (" << status_str << ")\n";
            send_challenge(static_cast<KemAlgorithm>(current_kem_id), true);
        } else {
            kem_csv << now_ms << "," << static_cast<int>(current_kem_id) << ","
                    << (current_kem_attempt + 1) << ",TIMEOUT,0," << ct_len << ","
                    << current_kem_retries << "," << status_str << "\n";
            waiting_kem_response = false;
            advance_kem_state();
        }
    };

    std::cout << "[OK] Ground station pronta. In attesa di MAGIC_START dalla boa (termina con Ctrl+C)...\n";

    while (g_running) {
        uint8_t magic = 0;
        if (!serial.read_byte(magic, 200)) {
            if (kem_campaign_active && waiting_kem_response) {
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t_hs_send).count();
                if (elapsed_ms >= 5000) {
                    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    std::cout << "[TIMEOUT KEM] Alg: " << static_cast<int>(current_kem_id)
                              << " | Tentativo " << (current_kem_attempt + 1) << "/" << KEM_HANDSHAKES_PER_ALGO << "\n";
                    csv << now_ms << ",KEM," << static_cast<int>(current_kem_id) << ",0,TIMEOUT\n";
                    handle_kem_failure_or_retry(now_ms, 0, "TIMEOUT");
                }
            }
            continue;
        }

        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // -----------------------------------------------------------------
        // SEGNALE INIZIALE DI SINCRONIZZAZIONE DALLA BOA
        // -----------------------------------------------------------------
        if (magic == MAGIC_START) {
            std::cout << "[SYNC] Ricevuto MAGIC_START dalla boa. Reset sequenza e avvio KEM...\n";
            last_seen_seq = 0;
            current_kem_id = static_cast<uint8_t>(KemAlgorithm::X25519);
            current_kem_attempt = 0;
            current_kem_retries = 0;
            kem_campaign_active = true;
            AckPacket ack{MAGIC_ACK, 0, 0x00};
            serial.write_exact(reinterpret_cast<uint8_t*>(&ack), sizeof(ack));
            send_challenge(KemAlgorithm::X25519, false);
        }
        // -----------------------------------------------------------------
        // RICEZIONE TELEMETRIA AEAD
        // -----------------------------------------------------------------
        else if (magic == MAGIC_TELEMETRY) {
            TelemetryHeader header;
            header.magic = magic;

            if (!serial.read_exact(reinterpret_cast<uint8_t*>(&header) + 1, sizeof(TelemetryHeader) - 1, 200) ||
                header.len > MAX_VALID_PACKET_LEN) {
                corrupted_frames++;
                csv << now_ms << ",TELEMETRY,0,0,CORRUPTED_TRUNCATED\n";
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
                corrupted_frames++;
                csv << now_ms << ",TELEMETRY," << header.seq_num << "," << header.len << ",CORRUPTED_TRUNCATED\n";
                serial.flush();
                continue;
            }

            total_telemetry++;
            AckPacket ack{MAGIC_ACK, header.seq_num, 0x00};

            if (header.seq_num == last_seen_seq) {
                ack.status_code = 0x00;
                serial.write_exact(reinterpret_cast<uint8_t*>(&ack), sizeof(ack));
                continue;
            } else if (header.seq_num < last_seen_seq) {
                replay_drops++;
                continue;
            }

            std::vector<uint8_t> plaintext;
            bool ok = crypto.decrypt(algo, header.seq_num, ciphertext.data(), ciphertext.size(), in_tag, plaintext);

            if (!ok) {
                auth_failures++;
                ack.status_code = 0x02; // Auth Fail
                csv << now_ms << ",TELEMETRY," << header.seq_num << "," << header.len << ",AUTH_FAIL\n";
            } else {
                last_seen_seq = header.seq_num;
                std::cout << "[OK Telemetria] Rx Seq " << header.seq_num
                          << " | Algo: " << static_cast<int>(header.algo_id)
                          << " | Len: " << plaintext.size() << " B\n";
                csv << now_ms << ",TELEMETRY," << header.seq_num << "," << plaintext.size() << ",OK\n";
            }

            // L'ACK parte solo dopo aver completato la decifratura
            serial.write_exact(reinterpret_cast<uint8_t*>(&ack), sizeof(ack));
        }
        // -----------------------------------------------------------------
        // RICEZIONE RISPOSTA KEM HANDSHAKE
        // -----------------------------------------------------------------
        else if (magic == MAGIC_KEM_RESP) {
            KemResponseHeader resp_hdr;
            resp_hdr.magic = magic;

            if (!serial.read_exact(reinterpret_cast<uint8_t*>(&resp_hdr) + 1, sizeof(KemResponseHeader) - 1, 200) ||
                resp_hdr.ct_len > MAX_VALID_PACKET_LEN) {
                corrupted_frames++;
                csv << now_ms << ",KEM," << static_cast<int>(current_kem_id) << ",0,CORRUPTED_TRUNCATED\n";
                serial.flush();
                if (kem_campaign_active && waiting_kem_response) {
                    handle_kem_failure_or_retry(now_ms, 0, "CORRUPTED_TRUNCATED");
                }
                continue;
            }

            std::vector<uint8_t> ciphertext(resp_hdr.ct_len);
            uint8_t response_tag[PSK_TAG_BYTES];

            if (!serial.read_exact(ciphertext.data(), ciphertext.size(), 3000) ||
                !serial.read_exact(response_tag, PSK_TAG_BYTES, 300)) {
                corrupted_frames++;
                csv << now_ms << ",KEM," << static_cast<int>(resp_hdr.kem_id) << "," << resp_hdr.ct_len << ",CORRUPTED_TRUNCATED\n";
                serial.flush();
                if (kem_campaign_active && waiting_kem_response) {
                    handle_kem_failure_or_retry(now_ms, resp_hdr.ct_len, "CORRUPTED_TRUNCATED");
                }
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
                csv << now_ms << ",KEM," << static_cast<int>(resp_hdr.kem_id) << "," << ciphertext.size() << ",PSK_AUTH_FAIL\n";
                if (kem_campaign_active && waiting_kem_response) {
                    handle_kem_failure_or_retry(now_ms, ciphertext.size(), "PSK_AUTH_FAIL");
                }
                continue;
            }

            // Step 2: Decapsulamento locale + Derivazione chiavi di sessione (HKDF)
            std::vector<uint8_t> shared_secret;
            bool ok = crypto.kem_decapsulate(kem_algo, ciphertext.data(), ciphertext.size(), shared_secret);

            if (ok) {
                const char* label = (kem_algo == KemAlgorithm::X25519) ? HKDF_LABEL_ECDH : HKDF_LABEL_MLKEM;
                crypto.derive_session_keys(label, shared_secret.data(), shared_secret.size());
            }

            // Stop timer E2E dell'intero scambio (include eventuali retries fino al completamento)
            double e2e_hs_ms = std::chrono::duration<double, std::milli>(
                std::chrono::steady_clock::now() - t_hs_attempt_start).count();

            // Step 3: L'ACK parte solo dopo aver completato anche l'HKDF
            AckPacket ack{MAGIC_ACK, 0, static_cast<uint8_t>(ok ? 0x00 : 0x02)};
            serial.write_exact(reinterpret_cast<uint8_t*>(&ack), sizeof(ack));

            if (ok) {
                std::cout << "[OK KEM Handshake] Alg: " << static_cast<int>(resp_hdr.kem_id)
                          << " | CT Len: " << ciphertext.size() << " B | E2E: "
                          << std::fixed << std::setprecision(1) << e2e_hs_ms << " ms"
                          << " | Retries: " << current_kem_retries << "\n";
                csv << now_ms << ",KEM," << static_cast<int>(resp_hdr.kem_id) << "," << ciphertext.size() << ",OK\n";
                if (kem_campaign_active && waiting_kem_response) {
                    kem_csv << now_ms << "," << static_cast<int>(resp_hdr.kem_id) << ","
                            << (current_kem_attempt + 1) << "," << std::fixed << std::setprecision(3) << e2e_hs_ms
                            << ",1," << ciphertext.size() << "," << current_kem_retries << ",OK\n";
                    waiting_kem_response = false;
                    advance_kem_state();
                }
            } else {
                csv << now_ms << ",KEM," << static_cast<int>(resp_hdr.kem_id) << "," << ciphertext.size() << ",DECAPS_FAIL\n";
                if (kem_campaign_active && waiting_kem_response) {
                    handle_kem_failure_or_retry(now_ms, ciphertext.size(), "DECAPS_FAIL");
                }
            }
        }
    }

    csv.close();
    kem_csv.close();
    std::cout << "\n=== STATISTICHE SESSIONE ===\n"
              << "Telemetrie ricevute:   " << total_telemetry << "\n"
              << "KEM Handshake eseguiti:" << total_kem << "\n"
              << "Frame corrotti/tronc.: " << corrupted_frames << "\n"
              << "Replay scartati:       " << replay_drops << "\n"
              << "Errori Autenticazione: " << auth_failures << "\n";

    return 0;
}