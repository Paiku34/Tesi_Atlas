#include "benchmark_core.hpp"
#include <sodium.h>
#include <cstring>

class AES256GCM_Libsodium : public ICryptoAlgorithm {
    uint8_t key[crypto_aead_aes256gcm_KEYBYTES];
    uint8_t npub[crypto_aead_aes256gcm_NPUBBYTES];
    uint64_t nonce_counter = 0;
public:
    AES256GCM_Libsodium() {
        randombytes_buf(key, sizeof(key));
        memset(npub, 0, sizeof(npub));
    }
    std::string get_name() const override { return "AES-256-GCM (Libsodium [AES-NI])"; }
    size_t get_fixed_overhead() const override { return 28; }

    void process(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext) override {
        if (!crypto_aead_aes256gcm_is_available()) return;

        // Incrementa il nonce (counter mode)
        nonce_counter++;
        memcpy(npub, &nonce_counter, sizeof(nonce_counter));

        ciphertext.resize(sizeof(npub) + plaintext.size() + crypto_aead_aes256gcm_ABYTES);
        std::copy(npub, npub + sizeof(npub), ciphertext.begin());

        unsigned long long clen = 0;
        crypto_aead_aes256gcm_encrypt(
            ciphertext.data() + sizeof(npub), &clen,
            plaintext.data(), plaintext.size(),
            NULL, 0,
            NULL, npub, key
        );
    }
};

class ChaCha20Poly1305_Libsodium : public ICryptoAlgorithm {
    uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    uint8_t npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    uint64_t nonce_counter = 0;
public:
    ChaCha20Poly1305_Libsodium() {
        randombytes_buf(key, sizeof(key));
        memset(npub, 0, sizeof(npub));
    }
    std::string get_name() const override { return "ChaCha20-Poly1305 (Libsodium)"; }
    size_t get_fixed_overhead() const override { return 28; }

    void process(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext) override {
        // Incrementa il nonce (counter mode)
        nonce_counter++;
        memcpy(npub, &nonce_counter, sizeof(nonce_counter));

        ciphertext.resize(sizeof(npub) + plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
        std::copy(npub, npub + sizeof(npub), ciphertext.begin());

        unsigned long long clen = 0;
        crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext.data() + sizeof(npub), &clen,
            plaintext.data(), plaintext.size(),
            NULL, 0,
            NULL, npub, key
        );
    }
};

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Errore inizializzazione sodium\n";
        return 1;
    }

    std::cout << "\n>>> BENCHMARK ISOLATO: LIBSODIUM <<<\n";
    std::vector<size_t> packet_sizes = {32, 64, 128, 255, 512, 1024};

    if (!crypto_aead_aes256gcm_is_available()) {
        std::cout << "\033[33m[WARNING] AES-NI non disponibile. AES-256-GCM libsodium saltato.\033[0m\n\n";
    } else {
        AES256GCM_Libsodium aes;
        run_benchmark_isolated(&aes, packet_sizes);
    }

    ChaCha20Poly1305_Libsodium chacha;
    run_benchmark_isolated(&chacha, packet_sizes);
    return 0;
}
