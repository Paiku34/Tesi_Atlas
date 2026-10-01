#include "benchmark_core.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>

class AES256GCM_OpenSSL : public ICryptoAlgorithm {
    uint8_t key[32];
    uint8_t iv[12];
    uint64_t iv_counter = 0;
public:
    AES256GCM_OpenSSL() {
        RAND_bytes(key, sizeof(key));
        memset(iv, 0, sizeof(iv));
    }
    std::string get_name() const override { return "AES-256-GCM (OpenSSL)"; }
    size_t get_fixed_overhead() const override { return 28; }
    
    void process(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext) override {
        // Nonce incrementale
        iv_counter++;
        memcpy(iv, &iv_counter, sizeof(iv_counter));

        ciphertext.resize(12 + plaintext.size() + 16);
        std::copy(iv, iv + 12, ciphertext.begin());

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

        int len = 0;
        int ciphertext_len = 0;
        EVP_EncryptUpdate(ctx, ciphertext.data() + 12, &len, plaintext.data(), plaintext.size());
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + 12 + len, &len);
        ciphertext_len += len;
        
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, ciphertext.data() + 12 + ciphertext_len);
        EVP_CIPHER_CTX_free(ctx);
    }
};

class ChaCha20Poly1305_OpenSSL : public ICryptoAlgorithm {
    uint8_t key[32];
    uint8_t iv[12];
    uint64_t iv_counter = 0;
public:
    ChaCha20Poly1305_OpenSSL() {
        RAND_bytes(key, sizeof(key));
        memset(iv, 0, sizeof(iv));
    }
    std::string get_name() const override { return "ChaCha20-Poly1305 (OpenSSL)"; }
    size_t get_fixed_overhead() const override { return 28; }
    
    void process(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext) override {
        // Nonce incrementale
        iv_counter++;
        memcpy(iv, &iv_counter, sizeof(iv_counter));

        ciphertext.resize(12 + plaintext.size() + 16);
        std::copy(iv, iv + 12, ciphertext.begin());

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

        int len = 0;
        int ciphertext_len = 0;
        EVP_EncryptUpdate(ctx, ciphertext.data() + 12, &len, plaintext.data(), plaintext.size());
        ciphertext_len = len;
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + 12 + len, &len);
        ciphertext_len += len;
        
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, ciphertext.data() + 12 + ciphertext_len);
        EVP_CIPHER_CTX_free(ctx);
    }
};

int main() {
    std::cout << "\n>>> BENCHMARK ISOLATO: OPENSSL <<<\n";
    std::vector<size_t> packet_sizes = {32, 64, 128, 255, 512, 1024};
    
    AES256GCM_OpenSSL aes;
    ChaCha20Poly1305_OpenSSL chacha;

    run_benchmark_isolated(&aes, packet_sizes);
    run_benchmark_isolated(&chacha, packet_sizes);
    return 0;
}
