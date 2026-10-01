#include "benchmark_core.hpp"
#include <cstring>

extern "C" {
    int crypto_aead_encrypt(
        unsigned char *c, unsigned long long *clen,
        const unsigned char *m, unsigned long long mlen,
        const unsigned char *ad, unsigned long long adlen,
        const unsigned char *nsec,
        const unsigned char *npub,
        const unsigned char *k
    );
}

class AsconAEAD128_Real : public ICryptoAlgorithm {
    uint8_t key[16];
    uint8_t npub[16];
    uint64_t nonce_counter = 0;
public:
    AsconAEAD128_Real() {
        // Chiave random generata una sola volta
        FILE* urandom = fopen("/dev/urandom", "r");
        if (urandom) {
            fread(key, 1, sizeof(key), urandom);
            fclose(urandom);
        } else {
            // Fallback deterministico se /dev/urandom non disponibile
            for (int i = 0; i < 16; i++) key[i] = (uint8_t)i;
        }
        memset(npub, 0, sizeof(npub));
    }
    std::string get_name() const override { return "Ascon-AEAD128 (ascon-c opt64)"; }
    size_t get_fixed_overhead() const override { return 32; } // 16B Nonce + 16B Tag
    
    void process(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext) override {
        // Incrementa il nonce (counter mode)
        nonce_counter++;
        memcpy(npub, &nonce_counter, sizeof(nonce_counter));
        
        std::vector<uint8_t> ct_and_tag(plaintext.size() + 16);
        unsigned long long clen = 0;

        crypto_aead_encrypt(
            ct_and_tag.data(), &clen,
            plaintext.data(), plaintext.size(),
            NULL, 0,
            NULL, npub, key
        );

        ciphertext.resize(16 + clen);
        std::copy(npub, npub + 16, ciphertext.begin());
        std::copy(ct_and_tag.begin(), ct_and_tag.end(), ciphertext.begin() + 16);
    }
};

int main() {
    std::cout << "\n>>> BENCHMARK ISOLATO: ASCON-C (STAND-ALONE) <<<\n";
    std::vector<size_t> packet_sizes = {32, 64, 128, 255, 512, 1024};

    AsconAEAD128_Real ascon;
    run_benchmark_isolated(&ascon, packet_sizes);
    return 0;
}
