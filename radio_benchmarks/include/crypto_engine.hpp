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
     * @brief Inizializza le chiavi di sessione e i salt derivati
     */
    void setup_keys();

    /**
     * @brief Cifra un payload con l'algoritmo AEAD specificato derivando il nonce dal SeqNum
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
     * @brief KEM Decapsulate (lato Ground Station): usa la chiave privata statica
     */
    bool kem_decapsulate(KemAlgorithm algo,
                         const uint8_t* ciphertext,
                         size_t ct_len,
                         std::vector<uint8_t>& out_shared_secret);

private:
    uint8_t session_key_[32];   // Chiave a 256 bit per AEAD
    uint8_t session_salt_[12];  // Salt di 12 byte per derivazione nonce
};

} // namespace radio
