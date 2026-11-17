#pragma once

#include <cstdint>
#include <vector>
#include <cstring>

namespace radio {

// Magic bytes per identificazione e resincronizzazione automatica
constexpr uint8_t MAGIC_TELEMETRY = 0xAA; // Uplink Boa -> Ground Station
constexpr uint8_t MAGIC_ACK       = 0x55; // Downlink Ground Station -> Boa
constexpr uint8_t MAGIC_KEM       = 0x4B; // 'K' Handshake KEM

constexpr size_t AEAD_TAG_LEN     = 16;   // Tag di autenticazione per tutti gli AEAD testati

enum class CryptoAlgorithm : uint8_t {
    BASELINE_CLEAR   = 0, // Nessuna cifratura (solo per confronto baseline)
    ASCON_128        = 1,
    AES_256_GCM      = 2,
    CHACHA20_SODIUM  = 3, // ChaCha20-Poly1305 (Libsodium)
    CHACHA20_OPENSSL = 4  // ChaCha20-Poly1305 (OpenSSL)
};

enum class KemAlgorithm : uint8_t {
    X25519     = 1,
    ML_KEM_512 = 2,
    ML_KEM_768 = 3,
    ML_KEM_1024= 4
};

// -----------------------------------------------------------------------
// 1. Frame Telemetria (Uplink)
// Overhead radio totale: 1B (Magic) + 1B (Algo) + 4B (Seq) + 2B (Len) + 16B (Tag) = 24 Byte
// -----------------------------------------------------------------------
#pragma pack(push, 1)
struct TelemetryHeader {
    uint8_t  magic;    // 0xAA
    uint8_t  algo_id;  // CryptoAlgorithm
    uint32_t seq_num;  // Monotonic counter (funge anche da Nonce e Replay Protection)
    uint16_t len;      // Lunghezza del solo ciphertext (payload) in byte
};
#pragma pack(pop)

// -----------------------------------------------------------------------
// 2. Frame ACK / Echo (Downlink)
// Overhead: 6 Byte
// -----------------------------------------------------------------------
#pragma pack(push, 1)
struct AckPacket {
    uint8_t  magic;       // 0x55
    uint32_t seq_num;     // Sequence number del pacchetto telemetria confermato
    uint8_t  status_code; // 0x00 = OK, 0x01 = Replay Scartato, 0x02 = Auth Tag Fallito
};
#pragma pack(pop)

// -----------------------------------------------------------------------
// 3. Frame KEM Handshake
// -----------------------------------------------------------------------
#pragma pack(push, 1)
struct KemHeader {
    uint8_t  magic;    // 0x4B
    uint8_t  kem_id;   // KemAlgorithm
    uint16_t ct_len;   // Lunghezza del Ciphertext (es. 32B per X25519, 1088B per ML-KEM-768)
};
#pragma pack(pop)

/**
 * @brief Derivazione deterministica del Nonce a partire dal SeqNum.
 * Evita di trasmettere 12 o 16 byte di nonce via radio.
 *
 * @param algo Algoritmo crittografico in uso
 * @param seq_num Numero di sequenza del pacchetto corrente
 * @param session_salt Salt/prefisso fisso concordato nella sessione (almeno 12 byte)
 * @param out_nonce Buffer di destinazione (12 byte per AES/ChaCha, 16 byte per Ascon)
 */
inline void derive_nonce(CryptoAlgorithm algo, uint32_t seq_num, const uint8_t* session_salt, uint8_t* out_nonce) {
    if (algo == CryptoAlgorithm::ASCON_128) {
        // Ascon usa 16 byte: 12 byte di session_salt + 4 byte di seq_num (big-endian)
        std::memcpy(out_nonce, session_salt, 12);
        out_nonce[12] = static_cast<uint8_t>((seq_num >> 24) & 0xFF);
        out_nonce[13] = static_cast<uint8_t>((seq_num >> 16) & 0xFF);
        out_nonce[14] = static_cast<uint8_t>((seq_num >> 8) & 0xFF);
        out_nonce[15] = static_cast<uint8_t>(seq_num & 0xFF);
    } else {
        // AES-256-GCM e ChaCha20-Poly1305 usano 12 byte: 8 byte salt + 4 byte seq_num
        std::memcpy(out_nonce, session_salt, 8);
        out_nonce[8]  = static_cast<uint8_t>((seq_num >> 24) & 0xFF);
        out_nonce[9]  = static_cast<uint8_t>((seq_num >> 16) & 0xFF);
        out_nonce[10] = static_cast<uint8_t>((seq_num >> 8) & 0xFF);
        out_nonce[11] = static_cast<uint8_t>(seq_num & 0xFF);
    }
}

} // namespace radio
