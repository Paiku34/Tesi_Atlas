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
    uint8_t psk[32];
    uint8_t nc[32], ns[32], tag[16], session_key[32];
    uint8_t handshake_data[64];
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
public:
    SymmetricHandshake_Runner() {
        randombytes_buf(psk, sizeof(psk));
    }
    std::string get_name() const override { return "Symmetric Handshake (2-Way HKDF)"; }
    std::string get_category() const override { return "KEY_MGMT"; }
    size_t get_payload_size() const override { return 80; } // 80 bytes scambiati

    void setup(size_t) override {}

    void run_single_op() override {
        // 1. Client nonce
        randombytes_buf(nc, sizeof(nc));
        // 2. Server nonce & concat
        randombytes_buf(ns, sizeof(ns));
        memcpy(handshake_data, nc, 32);
        memcpy(handshake_data + 32, ns, 32);

        // 3. Tag MAC
        crypto_auth(tag, handshake_data, sizeof(handshake_data), psk);

        // 4. Verifica & HKDF
        if (crypto_auth_verify(tag, handshake_data, sizeof(handshake_data), psk) == 0) {
            crypto_kdf_hkdf_sha256_extract(prk, handshake_data, sizeof(handshake_data), psk, sizeof(psk));
            crypto_kdf_hkdf_sha256_expand(session_key, sizeof(session_key), "ATLAS_SH", 8, prk);
        }
        do_not_optimize_away(session_key);
    }
};

// -----------------------------------------------------------------------------
// 3. ECDH X25519 (Libsodium crypto_kx)
// -----------------------------------------------------------------------------
class ECDH_X25519_Runner : public IAlgorithmRunner {
    uint8_t client_pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t client_sk[crypto_kx_SECRETKEYBYTES];
    uint8_t server_pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t server_sk[crypto_kx_SECRETKEYBYTES];
    uint8_t session_key[crypto_kx_SESSIONKEYBYTES];
public:
    ECDH_X25519_Runner() {}
    std::string get_name() const override { return "ECDH X25519"; }
    std::string get_category() const override { return "KEY_MGMT"; }
    size_t get_payload_size() const override { return 64; } // 32 + 32 pk bytes

    void setup(size_t) override {}

    void run_single_op() override {
        crypto_kx_keypair(client_pk, client_sk);
        crypto_kx_keypair(server_pk, server_sk);
        if (crypto_kx_client_session_keys(session_key, NULL, client_pk, client_sk, server_pk) == 0) {
            do_not_optimize_away(session_key);
        }
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
    std::vector<uint8_t> ss_receiver;
public:
    MLKEM_Runner(const std::string& name, const std::string& dname) 
        : oqs_name(name), display_name(dname) {
        kem = OQS_KEM_new(oqs_name.c_str());
        if (kem) {
            public_key.resize(kem->length_public_key);
            secret_key.resize(kem->length_secret_key);
            ciphertext.resize(kem->length_ciphertext);
            ss_sender.resize(kem->length_shared_secret);
            ss_receiver.resize(kem->length_shared_secret);
        }
    }
    ~MLKEM_Runner() {
        if (kem) OQS_KEM_free(kem);
    }
    bool is_valid() const { return kem != nullptr; }
    std::string get_name() const override { return display_name; }
    std::string get_category() const override { return "KEY_MGMT"; }
    size_t get_payload_size() const override { 
        return kem ? (kem->length_public_key + kem->length_ciphertext) : 0; 
    }

    void setup(size_t) override {}

    void run_single_op() override {
        if (!kem) return;
        // Full Ephemeral Handshake (KeyGen + Encaps + Decaps)
        OQS_KEM_keypair(kem, public_key.data(), secret_key.data());
        do_not_optimize_away(public_key);
        do_not_optimize_away(secret_key);

        OQS_KEM_encaps(kem, ciphertext.data(), ss_sender.data(), public_key.data());
        do_not_optimize_away(ciphertext);
        do_not_optimize_away(ss_sender);

        OQS_KEM_decaps(kem, ss_receiver.data(), ciphertext.data(), secret_key.data());
        do_not_optimize_away(ss_receiver);
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
                  << "  " << argv[0] << " --latency <scheme_id>\n"
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

    if (mode == "--latency" && argc >= 3) {
        std::string scheme_id = argv[2];
        if (runners.find(scheme_id) == runners.end()) {
            std::cerr << "Schema sconosciuto: " << scheme_id << "\n";
            return 1;
        }

        // Parametri identici a src/bench_key_management.cpp e src/bench_mlkem.cpp:
        // - PSK / Handshake: 50 warm-up, 1000 iterazioni reali
        // - X25519: 20 warm-up, 1000 iterazioni reali
        // - ML-KEM: 20 warm-up, 1000 iterazioni reali
        int warmup = 50;
        int iters = 1000;
        if (scheme_id == "x25519" || scheme_id.find("mlkem") != std::string::npos) {
            warmup = 20;
        }

        auto stats = measure_software_latency(runners[scheme_id].get(), runners[scheme_id]->get_payload_size(), iters, warmup);
        
        std::cout << "LATENCY_RESULT|" << scheme_id << "|" << runners[scheme_id]->get_name() << "|"
                  << runners[scheme_id]->get_payload_size() << "|" << std::fixed << std::setprecision(4)
                  << stats.latency_us_mean << "|" << stats.latency_us_std << "|"
                  << stats.cycles_per_op << "\n";
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

