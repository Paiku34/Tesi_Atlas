#include "core_energia.hpp"
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <map>
#include <memory>

// Import Ascon-c AEAD
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

// -----------------------------------------------------------------------------
// 1. ASCON-AEAD128 (ascon-c opt64)
// -----------------------------------------------------------------------------
class AsconRunner : public IAlgorithmRunner {
    uint8_t key[16];
    uint8_t npub[16];
    uint64_t counter = 0;
    std::vector<uint8_t> pt;
    std::vector<uint8_t> ct;
public:
    AsconRunner() {
        for (int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 7 + 3);
        memset(npub, 0, sizeof(npub));
    }
    std::string get_name() const override { return "Ascon-AEAD128"; }
    std::string get_category() const override { return "AEAD"; }
    size_t get_payload_size() const override { return pt.size(); }

    void setup(size_t payload_size) override {
        pt.assign(payload_size, 0x42);
        ct.resize(16 + payload_size + 16); // 16B nonce + ct + 16B tag
        counter = 0;
    }

    void run_single_op() override {
        counter++;
        memcpy(npub, &counter, sizeof(counter));
        unsigned long long clen = 0;
        crypto_aead_encrypt(
            ct.data() + 16, &clen,
            pt.data(), pt.size(),
            NULL, 0, NULL, npub, key
        );
        memcpy(ct.data(), npub, 16);
        do_not_optimize_away(ct);
    }
};

// -----------------------------------------------------------------------------
// 2. AES-128-GCM (OpenSSL)
// -----------------------------------------------------------------------------
class AES128GCM_OpenSSL_Runner : public IAlgorithmRunner {
    uint8_t key[16];
    uint8_t iv[12];
    uint64_t counter = 0;
    std::vector<uint8_t> pt;
    std::vector<uint8_t> ct;
public:
    AES128GCM_OpenSSL_Runner() {
        RAND_bytes(key, sizeof(key));
        memset(iv, 0, sizeof(iv));
    }
    std::string get_name() const override { return "AES-128-GCM (OpenSSL)"; }
    std::string get_category() const override { return "AEAD"; }
    size_t get_payload_size() const override { return pt.size(); }

    void setup(size_t payload_size) override {
        pt.assign(payload_size, 0x5A);
        ct.resize(12 + payload_size + 16);
        counter = 0;
    }

    void run_single_op() override {
        counter++;
        memcpy(iv, &counter, sizeof(counter));
        memcpy(ct.data(), iv, 12);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

        int len = 0;
        int ct_len = 0;
        EVP_EncryptUpdate(ctx, ct.data() + 12, &len, pt.data(), pt.size());
        ct_len = len;
        EVP_EncryptFinal_ex(ctx, ct.data() + 12 + len, &len);
        ct_len += len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, ct.data() + 12 + ct_len);
        EVP_CIPHER_CTX_free(ctx);

        do_not_optimize_away(ct);
    }
};

// -----------------------------------------------------------------------------
// 3. AES-256-GCM (OpenSSL)
// -----------------------------------------------------------------------------
class AES256GCM_OpenSSL_Runner : public IAlgorithmRunner {
    uint8_t key[32];
    uint8_t iv[12];
    uint64_t counter = 0;
    std::vector<uint8_t> pt;
    std::vector<uint8_t> ct;
public:
    AES256GCM_OpenSSL_Runner() {
        RAND_bytes(key, sizeof(key));
        memset(iv, 0, sizeof(iv));
    }
    std::string get_name() const override { return "AES-256-GCM (OpenSSL)"; }
    std::string get_category() const override { return "AEAD"; }
    size_t get_payload_size() const override { return pt.size(); }

    void setup(size_t payload_size) override {
        pt.assign(payload_size, 0x5B);
        ct.resize(12 + payload_size + 16);
        counter = 0;
    }

    void run_single_op() override {
        counter++;
        memcpy(iv, &counter, sizeof(counter));
        memcpy(ct.data(), iv, 12);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

        int len = 0;
        int ct_len = 0;
        EVP_EncryptUpdate(ctx, ct.data() + 12, &len, pt.data(), pt.size());
        ct_len = len;
        EVP_EncryptFinal_ex(ctx, ct.data() + 12 + len, &len);
        ct_len += len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, ct.data() + 12 + ct_len);
        EVP_CIPHER_CTX_free(ctx);

        do_not_optimize_away(ct);
    }
};

// -----------------------------------------------------------------------------
// 4. ChaCha20-Poly1305 (Libsodium IETF)
// -----------------------------------------------------------------------------
class ChaCha20Poly1305_Libsodium_Runner : public IAlgorithmRunner {
    uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    uint8_t npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    uint64_t counter = 0;
    std::vector<uint8_t> pt;
    std::vector<uint8_t> ct;
public:
    ChaCha20Poly1305_Libsodium_Runner() {
        randombytes_buf(key, sizeof(key));
        memset(npub, 0, sizeof(npub));
    }
    std::string get_name() const override { return "ChaCha20-Poly1305 (Libsodium)"; }
    std::string get_category() const override { return "AEAD"; }
    size_t get_payload_size() const override { return pt.size(); }

    void setup(size_t payload_size) override {
        pt.assign(payload_size, 0x6C);
        ct.resize(sizeof(npub) + payload_size + crypto_aead_chacha20poly1305_ietf_ABYTES);
        counter = 0;
    }

    void run_single_op() override {
        counter++;
        memcpy(npub, &counter, sizeof(counter));
        memcpy(ct.data(), npub, sizeof(npub));

        unsigned long long clen = 0;
        crypto_aead_chacha20poly1305_ietf_encrypt(
            ct.data() + sizeof(npub), &clen,
            pt.data(), pt.size(),
            NULL, 0, NULL, npub, key
        );
        do_not_optimize_away(ct);
    }
};

// -----------------------------------------------------------------------------
// 5. ChaCha20-Poly1305 (OpenSSL)
// -----------------------------------------------------------------------------
class ChaCha20Poly1305_OpenSSL_Runner : public IAlgorithmRunner {
    uint8_t key[32];
    uint8_t iv[12];
    uint64_t counter = 0;
    std::vector<uint8_t> pt;
    std::vector<uint8_t> ct;
public:
    ChaCha20Poly1305_OpenSSL_Runner() {
        RAND_bytes(key, sizeof(key));
        memset(iv, 0, sizeof(iv));
    }
    std::string get_name() const override { return "ChaCha20-Poly1305 (OpenSSL)"; }
    std::string get_category() const override { return "AEAD"; }
    size_t get_payload_size() const override { return pt.size(); }

    void setup(size_t payload_size) override {
        pt.assign(payload_size, 0x6D);
        ct.resize(12 + payload_size + 16);
        counter = 0;
    }

    void run_single_op() override {
        counter++;
        memcpy(iv, &counter, sizeof(counter));
        memcpy(ct.data(), iv, 12);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

        int len = 0;
        int ct_len = 0;
        EVP_EncryptUpdate(ctx, ct.data() + 12, &len, pt.data(), pt.size());
        ct_len = len;
        EVP_EncryptFinal_ex(ctx, ct.data() + 12 + len, &len);
        ct_len += len;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, ct.data() + 12 + ct_len);
        EVP_CIPHER_CTX_free(ctx);

        do_not_optimize_away(ct);
    }
};

// Factory runners
inline std::map<std::string, std::shared_ptr<IAlgorithmRunner>> create_aead_runners() {
    std::map<std::string, std::shared_ptr<IAlgorithmRunner>> map;
    map["ascon"] = std::make_shared<AsconRunner>();
    map["aes128"] = std::make_shared<AES128GCM_OpenSSL_Runner>();
    map["aes256"] = std::make_shared<AES256GCM_OpenSSL_Runner>();
    map["chacha_sodium"] = std::make_shared<ChaCha20Poly1305_Libsodium_Runner>();
    map["chacha_openssl"] = std::make_shared<ChaCha20Poly1305_OpenSSL_Runner>();
    return map;
}

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "Errore inizializzazione sodium!\n";
        return 1;
    }

    auto runners = create_aead_runners();
    const std::vector<size_t> ALLOWED_PAYLOADS = {64, 255, 1024};

    if (argc < 2) {
        std::cout << "Uso:\n"
                  << "  " << argv[0] << " --list\n"
                  << "  " << argv[0] << " --latency <algo_id> <payload_bytes>\n"
                  << "  " << argv[0] << " --burn <algo_id> <payload_bytes> [durata_sec]\n";
        return 0;
    }

    std::string mode = argv[1];

    if (mode == "--list") {
        std::cout << "ALGORITMI DISPONIBILI:\n";
        for (const auto& kv : runners) {
            std::cout << "  " << std::left << std::setw(16) << kv.first << " -> " << kv.second->get_name() << "\n";
        }
        std::cout << "PAYLOAD SUPPORTATI: 64, 255, 1024 bytes\n";
        return 0;
    }

    if (mode == "--latency" && argc >= 4) {
        std::string algo_id = argv[2];
        size_t payload = std::stoul(argv[3]);

        if (runners.find(algo_id) == runners.end()) {
            std::cerr << "Algoritmo sconosciuto: " << algo_id << "\n";
            return 1;
        }

        // Identico a benchmark_core.hpp: 100 warm-up, 5000 iterazioni reali
        auto stats = measure_software_latency(runners[algo_id].get(), payload, 5000, 100);
        // Output strutturato leggibile sia da umano che da script python
        std::cout << "LATENCY_RESULT|" << algo_id << "|" << runners[algo_id]->get_name() << "|"
                  << payload << "|" << std::fixed << std::setprecision(4)
                  << stats.latency_us_mean << "|" << stats.latency_us_std << "|"
                  << stats.cycles_per_op << "\n";
        return 0;
    }

    if (mode == "--burn" && argc >= 4) {
        std::string algo_id = argv[2];
        size_t payload = std::stoul(argv[3]);
        int duration = (argc >= 5) ? std::stoi(argv[4]) : 0;

        if (runners.find(algo_id) == runners.end()) {
            std::cerr << "Algoritmo sconosciuto: " << algo_id << "\n";
            return 1;
        }

        std::cout << ">>> Avvio CARICO ATTIVO STEADY-STATE per " << runners[algo_id]->get_name()
                  << " [Payload: " << payload << " B] <<<\n";
        if (duration > 0) {
            std::cout << ">>> Esecuzione a regime per " << duration << " secondi...\n";
        } else {
            std::cout << ">>> In esecuzione continua. Premi CTRL+C per terminare il test...\n";
        }

        uint64_t ops = run_steady_state_burn(runners[algo_id].get(), payload, duration);
        std::cout << "\n>>> Stop carico. Operazioni totali eseguite: " << ops << "\n";
        return 0;
    }

    std::cerr << "Comando non riconosciuto. Esegui con --list per aiuto.\n";
    return 1;
}

