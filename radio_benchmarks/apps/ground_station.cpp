#include "serial_port.hpp"
#include "radio_packet.hpp"
#include "crypto_engine.hpp"

#include <iostream>
#include <vector>
#include <chrono>
#include <csignal>

using namespace radio;

static volatile bool g_running = true;
void sigint_handler(int) {
    g_running = false;
}

int main(int argc, char* argv[]) {
    std::string device = "/dev/ttyUSB0";
    int baudrate = 57600;

    if (argc > 1) device = argv[1];
    if (argc > 2) baudrate = std::stoi(argv[2]);

    std::signal(SIGINT, sigint_handler);

    std::cout << "========================================================\n";
    std::cout << "  ZENO ATLAS - GROUND STATION (Zeno PC Receiver)\n";
    std::cout << "  Device: " << device << " (" << baudrate << " baud)\n";
    std::cout << "========================================================\n\n";

    SerialPort serial;
    if (!serial.open_device(device, baudrate)) {
        std::cerr << "Impossibile aprire il dispositivo seriale " << device << "\n";
        return 1;
    }
    std::cout << "[OK] Ground station in ascolto su " << device << "...\n";

    CryptoEngine crypto;
    uint32_t last_seen_seq = 0;
    size_t total_packets = 0;
    size_t auth_failures = 0;
    size_t replay_drops = 0;

    while (g_running) {
        uint8_t magic = 0;
        // Cerca il Magic Byte sullo stream seriale
        if (!serial.read_byte(magic, 500)) {
            continue;
        }

        if (magic == MAGIC_TELEMETRY) {
            TelemetryHeader header;
            header.magic = magic;

            // Leggi il resto dell'header
            if (!serial.read_exact(reinterpret_cast<uint8_t*>(&header) + 1, sizeof(TelemetryHeader) - 1, 200)) {
                std::cerr << "[WARN] Timeout ricezione header telemetria\n";
                continue;
            }

            // Leggi il payload cifrato + Tag
            std::vector<uint8_t> ciphertext(header.len);
            uint8_t in_tag[AEAD_TAG_LEN];

            if (!serial.read_exact(ciphertext.data(), ciphertext.size(), 500) ||
                !serial.read_exact(in_tag, AEAD_TAG_LEN, 200)) {
                std::cerr << "[WARN] Frame incompleto per seq " << header.seq_num << "\n";
                continue;
            }

            total_packets++;
            AckPacket ack;
            ack.magic = MAGIC_ACK;
            ack.seq_num = header.seq_num;
            ack.status_code = 0x00;

            // 1. Replay Protection
            if (header.seq_num <= last_seen_seq) {
                replay_drops++;
                ack.status_code = 0x01; // Replay
                serial.write_exact(reinterpret_cast<uint8_t*>(&ack), sizeof(ack));
                std::cout << "[REPLAY] Scartato seq " << header.seq_num << " (ultimo: " << last_seen_seq << ")\n";
                continue;
            }

            // 2. Decifratura & Verifica Autenticità
            std::vector<uint8_t> plaintext;
            auto algo = static_cast<CryptoAlgorithm>(header.algo_id);
            bool ok = crypto.decrypt(algo, header.seq_num, ciphertext.data(), ciphertext.size(), in_tag, plaintext);

            if (!ok) {
                auth_failures++;
                ack.status_code = 0x02; // Auth Fail
                std::cout << "[AUTH_FAIL] Tag non valido per seq " << header.seq_num << "!\n";
            } else {
                last_seen_seq = header.seq_num;
                std::cout << "[OK] Rx Seq " << header.seq_num
                          << " | Algo ID: " << static_cast<int>(header.algo_id)
                          << " | Len: " << plaintext.size() << " B\n";
            }

            // Invia immediatamente l'ACK radio
            serial.write_exact(reinterpret_cast<uint8_t*>(&ack), sizeof(ack));
        }
    }

    std::cout << "\n=== STATISTICHE SESSIONE ===\n";
    std::cout << "Pacchetti totali ricevuti: " << total_packets << "\n";
    std::cout << "Replay scartati:           " << replay_drops << "\n";
    std::cout << "Errori Autenticazione:     " << auth_failures << "\n";

    return 0;
}
