#include "serial_port.hpp"
#include "radio_packet.hpp"
#include "crypto_engine.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <csignal>

using namespace radio;

static volatile bool g_running = true;
void sigint_handler(int) {
    g_running = false;
}

int main(int argc, char* argv[]) {
    std::string device = "/dev/ttyUSB0";
    int baudrate = 57600;
    std::string csv_out = "ground_station_log.csv";

    if (argc > 1) device = argv[1];
    if (argc > 2) baudrate = std::stoi(argv[2]);
    if (argc > 3) csv_out = argv[3];

    std::signal(SIGINT, sigint_handler);

    std::cout << "========================================================\n";
    std::cout << "  ZENO ATLAS - GROUND STATION (Zeno PC Receiver)\n";
    std::cout << "  Device: " << device << " (" << baudrate << " baud)\n";
    std::cout << "  Log CSV: " << csv_out << "\n";
    std::cout << "========================================================\n\n";

    SerialPort serial;
    if (!serial.open_device(device, baudrate)) {
        std::cerr << "Impossibile aprire il dispositivo seriale " << device << "\n";
        return 1;
    }
    std::cout << "[OK] Ground station in ascolto su " << device << "...\n";

    std::ofstream csv(csv_out);
    csv << "Timestamp_epoch_ms,Type,SeqOrKemId,Payload_B,Decrypt_Time_us,Status\n";

    CryptoEngine crypto;
    uint32_t last_seen_seq = 0;
    size_t total_telemetry = 0;
    size_t total_kem = 0;
    size_t auth_failures = 0;
    size_t replay_drops = 0;

    while (g_running) {
        uint8_t magic = 0;
        if (!serial.read_byte(magic, 500)) {
            continue;
        }

        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

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

            if (header.seq_num <= last_seen_seq) {
                replay_drops++;
                ack.status_code = 0x01;
                serial.write_exact(reinterpret_cast<uint8_t*>(&ack), sizeof(ack));
                csv << now_ms << ",TELEMETRY," << header.seq_num << "," << header.len << ",0.000,REPLAY\n";
                continue;
            }

            auto t_dec_start = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> plaintext;
            bool ok = crypto.decrypt(algo, header.seq_num, ciphertext.data(), ciphertext.size(), in_tag, plaintext);
            auto t_dec_end = std::chrono::high_resolution_clock::now();
            double dec_time_us = std::chrono::duration<double, std::micro>(t_dec_end - t_dec_start).count();

            if (!ok) {
                auth_failures++;
                ack.status_code = 0x02;
                csv << now_ms << ",TELEMETRY," << header.seq_num << "," << header.len << ","
                    << std::fixed << std::setprecision(3) << dec_time_us << ",AUTH_FAIL\n";
            } else {
                last_seen_seq = header.seq_num;
                std::cout << "[OK] Rx Seq " << header.seq_num << " | Algo: " << static_cast<int>(header.algo_id)
                          << " | Len: " << plaintext.size() << " B | Decrypt: "
                          << std::fixed << std::setprecision(1) << dec_time_us << " us\n";
                csv << now_ms << ",TELEMETRY," << header.seq_num << "," << plaintext.size() << ","
                    << std::fixed << std::setprecision(3) << dec_time_us << ",OK\n";
            }

            serial.write_exact(reinterpret_cast<uint8_t*>(&ack), sizeof(ack));
        } else if (magic == MAGIC_KEM) {
            KemHeader kh;
            kh.magic = magic;

            if (!serial.read_exact(reinterpret_cast<uint8_t*>(&kh) + 1, sizeof(KemHeader) - 1, 200)) {
                serial.flush();
                continue;
            }

            std::vector<uint8_t> kem_ct(kh.ct_len);
            if (!serial.read_exact(kem_ct.data(), kem_ct.size(), 3000)) {
                serial.flush();
                continue;
            }

            total_kem++;
            auto kem_algo = static_cast<KemAlgorithm>(kh.kem_id);

            auto t_dec_start = std::chrono::high_resolution_clock::now();
            std::vector<uint8_t> shared_secret;
            bool ok = crypto.kem_decapsulate(kem_algo, kem_ct.data(), kem_ct.size(), shared_secret);
            auto t_dec_end = std::chrono::high_resolution_clock::now();
            double dec_time_us = std::chrono::duration<double, std::micro>(t_dec_end - t_dec_start).count();

            AckPacket ack{MAGIC_ACK, 0, static_cast<uint8_t>(ok ? 0x00 : 0x02)};

            if (ok) {
                crypto.set_session_key_from_kem(shared_secret.data(), shared_secret.size());
                std::cout << "[OK] KEM Handshake Rx | Alg: " << static_cast<int>(kh.kem_id)
                          << " | CT Len: " << kem_ct.size() << " B | Decaps: "
                          << std::fixed << std::setprecision(1) << dec_time_us << " us\n";
                csv << now_ms << ",KEM," << static_cast<int>(kh.kem_id) << "," << kem_ct.size() << ","
                    << std::fixed << std::setprecision(3) << dec_time_us << ",OK\n";
            } else {
                csv << now_ms << ",KEM," << static_cast<int>(kh.kem_id) << "," << kem_ct.size() << ","
                    << std::fixed << std::setprecision(3) << dec_time_us << ",DECAPS_FAIL\n";
            }

            serial.write_exact(reinterpret_cast<uint8_t*>(&ack), sizeof(ack));
        }
    }

    csv.close();

    std::cout << "\n=== STATISTICHE SESSIONE ===\n"
              << "Pacchetti telemetria ricevuti: " << total_telemetry << "\n"
              << "Handshake KEM ricevuti:        " << total_kem << "\n"
              << "Replay scartati:               " << replay_drops << "\n"
              << "Errori Autenticazione:         " << auth_failures << "\n";

    return 0;
}
