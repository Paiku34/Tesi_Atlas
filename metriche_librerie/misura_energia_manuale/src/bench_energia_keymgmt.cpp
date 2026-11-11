#include "core_energia.hpp"
#include <sodium.h>
#include <sodium/crypto_kdf_hkdf_sha256.h>
#include <map>
#include <memory>

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

// -----------------------------------------------------------------------------
// 1. PSK + KDF (Libsodium BLAKE2b)
// -----------------------------------------------------------------------------
class PSK_KDF_Runner : public IAlgorithmRunner {
    uint8_t psk[crypto_kdf_KEYBYTES];
    uint8_t session_key[32];
    uint64_t counter = 0;
public:
    PSK_KDF_Runner() {
        randombytes_buf(psk, sizeof(psk));
    }
    std::string get_name() const override { return "PSK + KDF (BLAKE2b)"; }
    std::string get_category() const override { return "KEY_MGMT"; }
    size_t get_payload_size() const override { return 0; } // 0 bytes scambiati (locale)

    void setup(size_t) override {
        counter = 0;
    }

    void run_single_op() override {
        counter++;
        crypto_kdf_derive_from_key(session_key, sizeof(session_key), counter, "ATLAS_KM", psk);
        do_not_optimize_away(session_key);
    }
};

// -----------------------------------------------------------------------------
// 2. Symmetric 2-Way Handshake (HMAC + HKDF-SHA256)
// -----------------------------------------------------------------------------
class SymmetricHandshake_Runner : public IAlgorithmRunner {
    uint8_t psk[SESSION_KEY_BYTES];
    uint8_t nc[HANDSHAKE_NONCE_BYTES];
    uint8_t ns[HANDSHAKE_NONCE_BYTES];
    uint8_t tag[crypto_auth_BYTES];
    uint8_t gs_tag[crypto_auth_BYTES];
    uint8_t session_key[SESSION_KEY_BYTES];
    uint8_t handshake_data[HANDSHAKE_NONCE_BYTES + HANDSHAKE_NONCE_BYTES];
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
public:
    SymmetricHandshake_Runner() {
        randombytes_buf(psk, sizeof(psk));
        randombytes_buf(nc, sizeof(nc));
        memcpy(handshake_data, nc, sizeof(nc));
        memset(handshake_data + sizeof(nc), 0, sizeof(ns));
        crypto_auth(gs_tag, handshake_data, sizeof(handshake_data), psk);
    }
    std::string get_name() const override { return "Symmetric Handshake (2-Way HKDF)"; }
    std::string get_category() const override { return "KEY_MGMT"; }
    size_t get_payload_size() const override { 
        return (HANDSHAKE_NONCE_BYTES + PSK_TAG_BYTES) + 
               (HANDSHAKE_NONCE_BYTES + PSK_TAG_BYTES); 
    }

    void setup(size_t) override {}

    void run_single_op() override {
        uint8_t expected_tag[crypto_auth_BYTES];
        memcpy(handshake_data, nc, sizeof(nc));
        memset(handshake_data + sizeof(nc), 0, sizeof(ns));
        crypto_auth(expected_tag, handshake_data, sizeof(handshake_data), psk);
        if (sodium_memcmp(gs_tag, expected_tag, PSK_TAG_BYTES) != 0) return;

        // Buoy-side response
        randombytes_buf(ns, sizeof(ns));
        memcpy(handshake_data, nc, HANDSHAKE_NONCE_BYTES);
        memcpy(handshake_data + HANDSHAKE_NONCE_BYTES, ns, HANDSHAKE_NONCE_BYTES);

        // 3. Tag MAC
        crypto_auth(tag, handshake_data, sizeof(handshake_data), psk);

        // 4. Verifica & HKDF
        if (crypto_auth_verify(tag, handshake_data, sizeof(handshake_data), psk) == 0) {
            crypto_kdf_hkdf_sha256_extract(prk, handshake_data, sizeof(handshake_data), psk, sizeof(psk));
            crypto_kdf_hkdf_sha256_expand(session_key, sizeof(session_key), HKDF_LABEL_SYMM, strlen(HKDF_LABEL_SYMM), prk);
        }
        do_not_optimize_away(session_key);
    }
};

// -----------------------------------------------------------------------------
// 3. One-way authenticated X25519 (buoy side only)
// -----------------------------------------------------------------------------
class ECDH_X25519_Runner : public IAlgorithmRunner {
    uint8_t psk[crypto_auth_KEYBYTES];
    uint8_t gs_pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t gs_nonce[HANDSHAKE_NONCE_BYTES];
    uint8_t gs_auth_data[HANDSHAKE_NONCE_BYTES + crypto_kx_PUBLICKEYBYTES];
    uint8_t gs_tag[crypto_auth_BYTES];
    uint8_t buoy_pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t buoy_sk[crypto_kx_SECRETKEYBYTES];
    uint8_t shared_secret[crypto_scalarmult_BYTES];
    uint8_t response_data[HANDSHAKE_NONCE_BYTES + HANDSHAKE_NONCE_BYTES + crypto_kx_PUBLICKEYBYTES];
    uint8_t response_tag[crypto_auth_BYTES];
    uint8_t session_key[SESSION_KEY_BYTES];
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
public:
    ECDH_X25519_Runner() {
        randombytes_buf(psk, sizeof(psk));
        uint8_t gs_sk[crypto_kx_SECRETKEYBYTES];
        crypto_kx_keypair(gs_pk, gs_sk);
        randombytes_buf(gs_nonce, sizeof(gs_nonce));
        memcpy(gs_auth_data, gs_nonce, sizeof(gs_nonce));
        memcpy(gs_auth_data + sizeof(gs_nonce), gs_pk, sizeof(gs_pk));
        crypto_auth(gs_tag, gs_auth_data, sizeof(gs_auth_data), psk);
    }
    std::string get_name() const override { return "ECDH X25519 One-Way (PSK Auth)"; }
    std::string get_category() const override { return "KEY_MGMT"; }
    size_t get_payload_size() const override { 
        return (HANDSHAKE_NONCE_BYTES + PSK_TAG_BYTES) + 
               (HANDSHAKE_NONCE_BYTES + crypto_kx_PUBLICKEYBYTES + PSK_TAG_BYTES); 
    }

    void setup(size_t) override {}

    void run_single_op() override {
        uint8_t expected_tag[crypto_auth_BYTES];
        crypto_auth(expected_tag, gs_auth_data, sizeof(gs_auth_data), psk);
        if (sodium_memcmp(gs_tag, expected_tag, PSK_TAG_BYTES) != 0) return;

        uint8_t buoy_nonce[HANDSHAKE_NONCE_BYTES];
        randombytes_buf(buoy_nonce, sizeof(buoy_nonce));
        crypto_kx_keypair(buoy_pk, buoy_sk);
        if (crypto_scalarmult_curve25519(shared_secret, buoy_sk, gs_pk) != 0) return;

        memcpy(response_data, gs_nonce, sizeof(gs_nonce));
        memcpy(response_data + HANDSHAKE_NONCE_BYTES, buoy_nonce, sizeof(buoy_nonce));
        memcpy(response_data + 2 * HANDSHAKE_NONCE_BYTES, buoy_pk, sizeof(buoy_pk));
        crypto_auth(response_tag, response_data, sizeof(response_data), psk);
        crypto_kdf_hkdf_sha256_extract(prk, psk, sizeof(psk), shared_secret, sizeof(shared_secret));
        crypto_kdf_hkdf_sha256_expand(session_key, sizeof(session_key), HKDF_LABEL_ECDH, strlen(HKDF_LABEL_ECDH), prk);
        do_not_optimize_away(session_key);
    }
};

// -----------------------------------------------------------------------------
// 4. ML-KEM Post-Quantum (liboqs)
// -----------------------------------------------------------------------------
#ifdef HAVE_LIBOQS
class MLKEM_Runner : public IAlgorithmRunner {
    std::string oqs_name;
    std::string display_name;
    OQS_KEM* kem = nullptr;
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> secret_key;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> ss_sender;
    uint8_t psk[crypto_auth_KEYBYTES];
    uint8_t gs_nonce[HANDSHAKE_NONCE_BYTES];
    std::vector<uint8_t> gs_auth_data;
    uint8_t gs_tag[crypto_auth_BYTES];
    std::vector<uint8_t> response_data;
    uint8_t response_tag[crypto_auth_BYTES];
    uint8_t session_key[SESSION_KEY_BYTES];
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
public:
    MLKEM_Runner(const std::string& name, const std::string& dname) 
        : oqs_name(name), display_name(dname) {
        kem = OQS_KEM_new(oqs_name.c_str());
        if (kem) {
            public_key.resize(kem->length_public_key);
            secret_key.resize(kem->length_secret_key);
            ciphertext.resize(kem->length_ciphertext);
            ss_sender.resize(kem->length_shared_secret);
            gs_auth_data.resize(HANDSHAKE_NONCE_BYTES + kem->length_public_key);
            response_data.resize(HANDSHAKE_NONCE_BYTES + HANDSHAKE_NONCE_BYTES + kem->length_ciphertext);
            randombytes_buf(psk, sizeof(psk));
            OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
            randombytes_buf(gs_nonce, sizeof(gs_nonce));
            memcpy(gs_auth_data.data(), gs_nonce, sizeof(gs_nonce));
            memcpy(gs_auth_data.data() + sizeof(gs_nonce), public_key.data(), kem->length_public_key);
            crypto_auth(gs_tag, gs_auth_data.data(), gs_auth_data.size(), psk);
        }
    }
    ~MLKEM_Runner() {
        if (kem) OQS_KEM_free(kem);
    }
    bool is_valid() const { return kem != nullptr; }
    std::string get_name() const override { return display_name; }
    std::string get_category() const override { return "KEY_MGMT"; }
    size_t get_payload_size() const override { 
        return kem ? ((HANDSHAKE_NONCE_BYTES + PSK_TAG_BYTES) + 
                      (HANDSHAKE_NONCE_BYTES + kem->length_ciphertext + PSK_TAG_BYTES)) : 0;
    }

    void setup(size_t) override {}

    void run_single_op() override {
        if (!kem) return;
        uint8_t expected_tag[crypto_auth_BYTES];
        crypto_auth(expected_tag, gs_auth_data.data(), gs_auth_data.size(), psk);
        if (sodium_memcmp(gs_tag, expected_tag, PSK_TAG_BYTES) != 0) return;

        OQS_KEM_encaps(kem, ciphertext.data(), ss_sender.data(), public_key.data());
        uint8_t buoy_nonce[HANDSHAKE_NONCE_BYTES];
        randombytes_buf(buoy_nonce, sizeof(buoy_nonce));
        memcpy(response_data.data(), gs_nonce, sizeof(gs_nonce));
        memcpy(response_data.data() + HANDSHAKE_NONCE_BYTES, buoy_nonce, sizeof(buoy_nonce));
        memcpy(response_data.data() + 2 * HANDSHAKE_NONCE_BYTES, ciphertext.data(), ciphertext.size());
        crypto_auth(response_tag, response_data.data(), response_data.size(), psk);
        crypto_kdf_hkdf_sha256_extract(prk, psk, sizeof(psk), ss_sender.data(), ss_sender.size());
        crypto_kdf_hkdf_sha256_expand(session_key, sizeof(session_key), HKDF_LABEL_MLKEM, strlen(HKDF_LABEL_MLKEM), prk);
        do_not_optimize_away(session_key);
    }
};
#endif

// Factory
inline std::map<std::string, std::shared_ptr<IAlgorithmRunner>> create_km_runners() {
    std::map<std::string, std::shared_ptr<IAlgorithmRunner>> map;
    map["psk"] = std::make_shared<PSK_KDF_Runner>();
    map["symm_handshake"] = std::make_shared<SymmetricHandshake_Runner>();
    map["x25519"] = std::make_shared<ECDH_X25519_Runner>();

#ifdef HAVE_LIBOQS
    auto k512 = std::make_shared<MLKEM_Runner>("ML-KEM-512", "ML-KEM-512 (Kyber512)");
    if (k512->is_valid()) map["mlkem512"] = k512;

    auto k768 = std::make_shared<MLKEM_Runner>("ML-KEM-768", "ML-KEM-768 (Kyber768)");
    if (k768->is_valid()) map["mlkem768"] = k768;

    auto k1024 = std::make_shared<MLKEM_Runner>("ML-KEM-1024", "ML-KEM-1024 (Kyber1024)");
    if (k1024->is_valid()) map["mlkem1024"] = k1024;
#endif

    return map;
}

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "Errore inizializzazione sodium!\n";
        return 1;
    }

    auto runners = create_km_runners();

    if (argc < 2) {
        std::cout << "Uso:\n"
                  << "  " << argv[0] << " --list\n"
                  << "  " << argv[0] << " --burn <scheme_id> [durata_sec]\n";
        return 0;
    }

    std::string mode = argv[1];

    if (mode == "--list") {
        std::cout << "SCHEMI KEY MANAGEMENT DISPONIBILI:\n";
        for (const auto& kv : runners) {
            std::cout << "  " << std::left << std::setw(16) << kv.first << " -> " 
                      << kv.second->get_name() << " (" << kv.second->get_payload_size() << " B)\n";
        }
        return 0;
    }

    if (mode == "--burn" && argc >= 3) {
        std::string scheme_id = argv[2];
        int duration = (argc >= 4) ? std::stoi(argv[3]) : 0;

        if (runners.find(scheme_id) == runners.end()) {
            std::cerr << "Schema sconosciuto: " << scheme_id << "\n";
            return 1;
        }

        std::cout << ">>> Avvio CARICO ATTIVO STEADY-STATE per Key Management: " 
                  << runners[scheme_id]->get_name() << " <<<\n";
        if (duration > 0) {
            std::cout << ">>> Esecuzione a regime per " << duration << " secondi...\n";
        } else {
            std::cout << ">>> In esecuzione continua. Premi CTRL+C per terminare il test...\n";
        }

        uint64_t ops = run_steady_state_burn(runners[scheme_id].get(), runners[scheme_id]->get_payload_size(), duration);
        std::cout << "\n>>> Stop carico. Operazioni totali eseguite: " << ops << "\n";
        return 0;
    }

    std::cerr << "Comando non riconosciuto. Esegui con --list per aiuto.\n";
    return 1;
}

