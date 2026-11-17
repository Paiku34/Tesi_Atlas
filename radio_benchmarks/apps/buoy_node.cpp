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

using namespace radio;

struct TelemetryResult {
    std::string algo_name;
    size_t payload_bytes;
    double crypto_tx_us;
    double rtt_ms;
    bool ack_received;
};

void run_telemetry_burst(SerialPort& serial,
                         CryptoEngine& crypto,
                         CryptoAlgorithm algo,
                         const std::string& algo_name,
                         size_t payload_size,
                         int num_packets,
                         std::vector<TelemetryResult>& results,
                         uint32_t& seq_counter) {

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

        // 2. Assemblaggio Frame
        TelemetryHeader header;
        header.magic = MAGIC_TELEMETRY;
        header.algo_id = static_cast<uint8_t>(algo);
        header.seq_num = current_seq;
        header.len = static_cast<uint16_t>(ciphertext.size());

        std::vector<uint8_t> frame;
        frame.resize(sizeof(header) + ciphertext.size() + AEAD_TAG_LEN);
        std::memcpy(frame.data(), &header, sizeof(header));
        std::memcpy(frame.data() + sizeof(header), ciphertext.data(), ciphertext.size());
        std::memcpy(frame.data() + sizeof(header) + ciphertext.size(), tag, AEAD_TAG_LEN);

        // 3. Trasmissione su seriale con misura RTT
        auto t_tx = std::chrono::steady_clock::now();
        serial.write_exact(frame.data(), frame.size());

        // 4. Attesa ACK (timeout 1500 ms per radio a bassa velocità)
        bool ack_ok = false;
        double rtt_ms = -1.0;
        uint8_t in_magic = 0;

        auto ack_start = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - ack_start).count() < 1500) {
            if (serial.read_byte(in_magic, 100)) {
                if (in_magic == MAGIC_ACK) {
                    AckPacket ack;
                    ack.magic = in_magic;
                    if (serial.read_exact(reinterpret_cast<uint8_t*>(&ack) + 1, sizeof(AckPacket) - 1, 200)) {
                        if (ack.seq_num == current_seq && ack.status_code == 0) {
                            auto t_rx = std::chrono::steady_clock::now();
                            rtt_ms = std::chrono::duration<double, std::milli>(t_rx - t_tx).count();
                            ack_ok = true;
                            break;
                        }
                    }
                }
            }
        }

        results.push_back({algo_name, payload_size, crypto_time_us, rtt_ms, ack_ok});

        // Breve pausa inter-pacchetto per permettere al modem RFD868+ di svuotare il buffer
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
}

int main(int argc, char* argv[]) {
    std::string device = "/dev/ttyUSB0";
    int baudrate = 57600;
    std::string csv_out = "radio_telemetry_results.csv";

    if (argc > 1) device = argv[1];
    if (argc > 2) baudrate = std::stoi(argv[2]);
    if (argc > 3) csv_out = argv[3];

    std::cout << "========================================================\n";
    std::cout << "  ZENO ATLAS - BOA TELEMETRY NODE (Raspberry Pi)\n";
    std::cout << "  Device: " << device << " (" << baudrate << " baud)\n";
    std::cout << "========================================================\n\n";

    SerialPort serial;
    if (!serial.open_device(device, baudrate)) {
        std::cerr << "Impossibile aprire il dispositivo " << device << "\n";
        return 1;
    }
    std::cout << "[OK] Porta seriale aperta e configurata.\n";

    CryptoEngine crypto;
    uint32_t seq_counter = 1000;
    std::vector<TelemetryResult> results;

    const std::vector<size_t> payloads = {8, 16, 32, 64, 128, 256};
    const int PACKETS_PER_RUN = 50;

    const std::vector<std::pair<CryptoAlgorithm, std::string>> algos = {
        {CryptoAlgorithm::BASELINE_CLEAR,   "Baseline (In Chiaro)"},
        {CryptoAlgorithm::ASCON_128,        "Ascon-AEAD128 (ascon-c)"},
        {CryptoAlgorithm::AES_256_GCM,      "AES-256-GCM (OpenSSL)"},
        {CryptoAlgorithm::CHACHA20_SODIUM,  "ChaCha20-Poly1305 (Libsodium)"},
        {CryptoAlgorithm::CHACHA20_OPENSSL, "ChaCha20-Poly1305 (OpenSSL)"}
    };

    for (const auto& alg : algos) {
        std::cout << "\n--- AVVIO TEST: " << alg.second << " ---\n";
        for (size_t sz : payloads) {
            run_telemetry_burst(serial, crypto, alg.first, alg.second, sz, PACKETS_PER_RUN, results, seq_counter);
        }
    }

    // Salvataggio CSV
    std::ofstream out(csv_out);
    out << "Algorithm,Payload_B,Crypto_Time_us,RTT_ms,Success\n";
    for (const auto& r : results) {
        out << r.algo_name << ","
            << r.payload_bytes << ","
            << std::fixed << std::setprecision(3) << r.crypto_tx_us << ","
            << (r.ack_received ? std::to_string(r.rtt_ms) : "TIMEOUT") << ","
            << (r.ack_received ? 1 : 0) << "\n";
    }
    out.close();

    std::cout << "\n[OK] Test completati! Risultati esportati in: " << csv_out << "\n";
    return 0;
}
