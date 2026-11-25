#pragma once

#include <cstdint>
#include <cstring>

namespace radio {

// Magic bytes per identificazione e resincronizzazione automatica
constexpr uint8_t MAGIC_TELEMETRY   = 0xAA; // Uplink Telemetria Boa -> Ground Station
constexpr uint8_t MAGIC_ACK         = 0x55; // Downlink ACK Ground Station -> Boa
constexpr uint8_t MAGIC_KEM_CHLNG   = 0x43; // 'C' Downlink Challenge GS -> Boa
constexpr uint8_t MAGIC_KEM_RESP    = 0x4B; // 'K' Uplink Response Boa -> GS
constexpr uint8_t MAGIC_START       = 0x40; // START Boa -> GS


// Parametri conformi 1-to-1 a benchmark_core.hpp
constexpr size_t HANDSHAKE_NONCE_BYTES = 32; // 256-bit nonce casuale GS e Boa
constexpr size_t PSK_TAG_BYTES         = 16; // Tag MAC autenticazione PSK (128 bit)
constexpr size_t SESSION_KEY_BYTES     = 32; // Chiave di sessione (256 bit per AEAD)
constexpr size_t SESSION_SALT_BYTES    = 12; // Salt fisso per nonce contatore AEAD
constexpr size_t AEAD_TAG_LEN          = 16; // Tag autenticazione AEAD standard (128 bit)

// Etichette di separazione di dominio HKDF (identiche a benchmark_core.hpp)
constexpr const char* HKDF_LABEL_SYMM  = "ATLAS_SH";
constexpr const char* HKDF_LABEL_ECDH  = "ATLAS_ECDH";
constexpr const char* HKDF_LABEL_MLKEM = "ATLAS_MLKEM";

enum class CryptoAlgorithm : uint8_t {
    BASELINE_CLEAR   = 0, // Nessuna cifratura (solo per confronto baseline)
    ASCON_128        = 1,
    AES_256_GCM      = 2,
    CHACHA20_SODIUM  = 3, // ChaCha20-Poly1305 (Libsodium)
    CHACHA20_OPENSSL = 4, // ChaCha20-Poly1305 (OpenSSL)
    RSA_1024_E3      = 5, // RSA-1024 OAEP-SHA256 (e=3, solo confronto uplink)
    RSA_2048_E3      = 6  // RSA-2048 OAEP-SHA256 (e=3, solo confronto uplink)
};

inline bool is_aead_algorithm(CryptoAlgorithm algo) {
    return algo == CryptoAlgorithm::ASCON_128 ||
           algo == CryptoAlgorithm::AES_256_GCM ||
           algo == CryptoAlgorithm::CHACHA20_SODIUM ||
           algo == CryptoAlgorithm::CHACHA20_OPENSSL;
}

enum class KemAlgorithm : uint8_t {
    X25519      = 1,
    ML_KEM_512  = 2,
    ML_KEM_768  = 3,
    ML_KEM_1024 = 4
};

// -----------------------------------------------------------------------
// 1. Frame Telemetria (Uplink)
// -----------------------------------------------------------------------
#pragma pack(push, 1)
struct TelemetryHeader {
    uint8_t  magic;    // 0xAA
    uint8_t  algo_id;  // CryptoAlgorithm
    uint32_t seq_num;  // Monotonic counter (funge anche da Nonce e Replay Protection)
    uint16_t len;      // Lunghezza del ciphertext (payload) in byte
};

// -----------------------------------------------------------------------
// 2. Frame ACK / Echo (Downlink)
// -----------------------------------------------------------------------
struct AckPacket {
    uint8_t  magic;       // 0x55
    uint32_t seq_num;     // Sequence number confermato
    uint8_t  status_code; // 0x00 = OK, 0x01 = Replay Scartato, 0x02 = Auth Fallita
};

// -----------------------------------------------------------------------
// 3. Handshake KEM - Step 1: Challenge GS (Downlink)
// Dimensione totale fissa: 1B (Magic) + 1B (KemID) + 32B (Nonce GS) + 16B (Tag PSK) = 50 Byte
// -----------------------------------------------------------------------
struct KemChallengeHeader {
    uint8_t  magic;                               // 0x43 ('C')
    uint8_t  kem_id;                              // KemAlgorithm
    uint8_t  gs_nonce[HANDSHAKE_NONCE_BYTES];     // 32 Byte
    uint8_t  auth_tag[PSK_TAG_BYTES];             // 16 Byte MAC calcolato su (kem_id + gs_nonce) con PSK
};

// -----------------------------------------------------------------------
// 4. Handshake KEM - Step 2: Response Boa (Uplink)
// Contiene: Magic (1B) + KemID (1B) + ct_len (2B) + buoy_nonce (32B) + Ciphertext (NB) + auth_tag (16B)
// -----------------------------------------------------------------------
struct KemResponseHeader {
    uint8_t  magic;                               // 0x4B ('K')
    uint8_t  kem_id;                              // KemAlgorithm
    uint16_t ct_len;                              // Lunghezza ciphertext KEM
    uint8_t  buoy_nonce[HANDSHAKE_NONCE_BYTES];   // 32 Byte
    // Segue Ciphertext[ct_len]
    // Segue auth_tag[16] (MAC su: gs_nonce + buoy_nonce + Ciphertext con PSK)
};
#pragma pack(pop)

/**
 * @brief Derivazione deterministica del Nonce AEAD a partire dal SeqNum.
 * Combina il session_salt (derivato da HKDF) con il monotonic counter.
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
