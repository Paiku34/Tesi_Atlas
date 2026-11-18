#pragma once

#include "radio_packet.hpp"
#include <vector>
#include <cstdint>
#include <string>

namespace radio {

class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine();

    /**
     * @brief Carica le chiavi di provisioning (PSK e chiavi GS da file o buffer)
     * @param prov_dir Directory dove risiedono i file delle chiavi (es. "provisioning")
     * @param is_ground_station Se true carica anche le chiavi private .sec, se false solo .pub e psk.key
     */
    bool load_provisioning(const std::string& prov_dir, bool is_ground_station);

    /**
     * @brief Calcola il MAC PSK a 128 bit conforme a benchmark_core.hpp (crypto_auth Libsodium)
     */
    void compute_psk_mac(const uint8_t* data, size_t data_len, uint8_t out_tag[PSK_TAG_BYTES]);

    /**
     * @brief Verifica il MAC PSK con confronto a tempo costante (sodium_memcmp)
     */
    bool verify_psk_mac(const uint8_t* data, size_t data_len, const uint8_t in_tag[PSK_TAG_BYTES]);

    /**
     * @brief Deriva la session_key (32B) e il session_salt (12B) tramite HKDF-SHA256
     * conforme 1-to-1 a bench_key_management.cpp e bench_mlkem.cpp:
     * - Salt = PSK
     * - IKM  = Shared Secret
     */
    bool derive_session_keys(const char* label,
                             const uint8_t* shared_secret, size_t ss_len);

    /**
     * @brief Cifra un payload con l'algoritmo AEAD specificato derivando il nonce da SeqNum
     */
    bool encrypt(CryptoAlgorithm algo,
                 uint32_t seq_num,
                 const uint8_t* plaintext,
                 size_t pt_len,
                 std::vector<uint8_t>& out_ciphertext,
                 uint8_t out_tag[AEAD_TAG_LEN]);

    /**
     * @brief Decifra e verifica l'autenticità del payload ricevuto
     */
    bool decrypt(CryptoAlgorithm algo,
                 uint32_t seq_num,
                 const uint8_t* ciphertext,
                 size_t ct_len,
                 const uint8_t in_tag[AEAD_TAG_LEN],
                 std::vector<uint8_t>& out_plaintext);

    /**
     * @brief KEM Encapsulate (lato Boa): usa la chiave pubblica statica della Ground Station
     */
    bool kem_encapsulate(KemAlgorithm algo,
                         std::vector<uint8_t>& out_ciphertext,
                         std::vector<uint8_t>& out_shared_secret);

    /**
     * @brief KEM Decapsulate (lato Ground Station): usa la chiave privata statica della Ground Station
     */
    bool kem_decapsulate(KemAlgorithm algo,
                         const uint8_t* ciphertext,
                         size_t ct_len,
                         std::vector<uint8_t>& out_shared_secret);

    const uint8_t* get_session_key() const { return session_key_; }
    const uint8_t* get_session_salt() const { return session_salt_; }

private:
    uint8_t psk_[32];                     // Pre-Shared Key (256 bit)
    uint8_t session_key_[32];             // Chiave AEAD corrente (256 bit)
    uint8_t session_salt_[12];            // Salt AEAD corrente (96 bit)

    // Chiavi statiche GS X25519
    uint8_t gs_x25519_pk_[32];
    uint8_t gs_x25519_sk_[32];

    // Chiavi statiche GS ML-KEM
    std::vector<uint8_t> gs_mlkem512_pk_;
    std::vector<uint8_t> gs_mlkem512_sk_;
    std::vector<uint8_t> gs_mlkem768_pk_;
    std::vector<uint8_t> gs_mlkem768_sk_;
    std::vector<uint8_t> gs_mlkem1024_pk_;
    std::vector<uint8_t> gs_mlkem1024_sk_;

    bool is_gs_ = false;
};

} // namespace radio
