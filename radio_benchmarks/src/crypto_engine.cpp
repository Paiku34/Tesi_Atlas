#include "crypto_engine.hpp"

#include <cstring>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <sodium.h>
#include <sodium/crypto_kdf_hkdf_sha256.h>

#if __has_include(<oqs/oqs.h>)
#include <oqs/oqs.h>
#define HAS_LIBOQS 1
#else
#define HAS_LIBOQS 0
#endif

// Ascon-C declarations
extern "C" {
    int crypto_aead_encrypt(
        unsigned char *c, unsigned long long *clen,
        const unsigned char *m, unsigned long long mlen,
        const unsigned char *ad, unsigned long long adlen,
        const unsigned char *nsec,
        const unsigned char *npub,
        const unsigned char *k
    );

    int crypto_aead_decrypt(
        unsigned char *m, unsigned long long *mlen,
        unsigned char *nsec,
        const unsigned char *c, unsigned long long clen,
        const unsigned char *ad, unsigned long long adlen,
        const unsigned char *npub,
        const unsigned char *k
    );
}

namespace radio {

static bool read_binary_file(const std::string& path, uint8_t* out, size_t expected_len) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    ifs.read(reinterpret_cast<char*>(out), expected_len);
    return ifs.gcount() == static_cast<std::streamsize>(expected_len);
}

static bool read_binary_vector(const std::string& path, std::vector<uint8_t>& out, size_t expected_len) {
    out.resize(expected_len);
    return read_binary_file(path, out.data(), expected_len);
}

static EVP_PKEY* load_rsa_pub(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return nullptr;
    EVP_PKEY* pkey = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    std::fclose(f);
    return pkey;
}

static EVP_PKEY* load_rsa_sec(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return nullptr;
    EVP_PKEY* pkey = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    std::fclose(f);
    return pkey;
}

CryptoEngine::CryptoEngine() {
    if (sodium_init() < 0) {
        std::cerr << "[CryptoEngine] Fallimento sodium_init()\n";
    }
    std::memset(psk_, 0, sizeof(psk_));
    std::memset(session_key_, 0, sizeof(session_key_));
    std::memset(session_salt_, 0, sizeof(session_salt_));
    std::memset(gs_x25519_pk_, 0, sizeof(gs_x25519_pk_));
    std::memset(gs_x25519_sk_, 0, sizeof(gs_x25519_sk_));
}

CryptoEngine::~CryptoEngine() {
    sodium_memzero(psk_, sizeof(psk_));
    sodium_memzero(session_key_, sizeof(session_key_));
    sodium_memzero(session_salt_, sizeof(session_salt_));
    sodium_memzero(gs_x25519_sk_, sizeof(gs_x25519_sk_));
    if (!gs_mlkem512_sk_.empty()) sodium_memzero(gs_mlkem512_sk_.data(), gs_mlkem512_sk_.size());
    if (!gs_mlkem768_sk_.empty()) sodium_memzero(gs_mlkem768_sk_.data(), gs_mlkem768_sk_.size());
    if (!gs_mlkem1024_sk_.empty()) sodium_memzero(gs_mlkem1024_sk_.data(), gs_mlkem1024_sk_.size());
    if (gs_rsa1024_pk_) EVP_PKEY_free(gs_rsa1024_pk_);
    if (gs_rsa1024_sk_) EVP_PKEY_free(gs_rsa1024_sk_);
    if (gs_rsa2048_pk_) EVP_PKEY_free(gs_rsa2048_pk_);
    if (gs_rsa2048_sk_) EVP_PKEY_free(gs_rsa2048_sk_);
}

bool CryptoEngine::load_provisioning(const std::string& prov_dir, bool is_ground_station) {
    is_gs_ = is_ground_station;

    // 1. Carica la PSK comune (32 byte)
    if (!read_binary_file(prov_dir + "/psk.key", psk_, sizeof(psk_))) {
        std::cerr << "[CryptoEngine] Errore caricamento " << prov_dir << "/psk.key\n";
        return false;
    }

    // Default iniziale per session_key e session_salt derivati direttamente da PSK
    // (usato nella baseline o prima del primo handshake KEM)
    crypto_kdf_hkdf_sha256_extract(session_key_, nullptr, 0, psk_, sizeof(psk_));
    std::memcpy(session_salt_, session_key_ + 20, sizeof(session_salt_));

    // 2. Carica chiavi statiche GS X25519
    if (!read_binary_file(prov_dir + "/gs_x25519.pub", gs_x25519_pk_, sizeof(gs_x25519_pk_))) {
        std::cerr << "[CryptoEngine] Errore caricamento " << prov_dir << "/gs_x25519.pub\n";
        return false;
    }
    if (is_gs_) {
        if (!read_binary_file(prov_dir + "/gs_x25519.sec", gs_x25519_sk_, sizeof(gs_x25519_sk_))) {
            std::cerr << "[CryptoEngine] Errore caricamento " << prov_dir << "/gs_x25519.sec\n";
            return false;
        }
    }

#if HAS_LIBOQS
    auto load_kem = [&](const char* alg, const std::string& prefix,
                        std::vector<uint8_t>& pk, std::vector<uint8_t>& sk) {
        OQS_KEM* k = OQS_KEM_new(alg);
        if (!k) return false;
        bool ok = read_binary_vector(prov_dir + "/" + prefix + ".pub", pk, k->length_public_key);
        if (ok && is_gs_) {
            ok = read_binary_vector(prov_dir + "/" + prefix + ".sec", sk, k->length_secret_key);
        }
        OQS_KEM_free(k);
        return ok;
    };

    load_kem(OQS_KEM_alg_ml_kem_512, "gs_mlkem512", gs_mlkem512_pk_, gs_mlkem512_sk_);
    load_kem(OQS_KEM_alg_ml_kem_768, "gs_mlkem768", gs_mlkem768_pk_, gs_mlkem768_sk_);
    load_kem(OQS_KEM_alg_ml_kem_1024, "gs_mlkem1024", gs_mlkem1024_pk_, gs_mlkem1024_sk_);
#endif

    // 3. Carica chiavi statiche GS RSA (1024 e 2048 bit, e=3)
    gs_rsa1024_pk_ = load_rsa_pub(prov_dir + "/gs_rsa1024.pub");
    gs_rsa2048_pk_ = load_rsa_pub(prov_dir + "/gs_rsa2048.pub");
    if (!gs_rsa1024_pk_ || !gs_rsa2048_pk_) {
        std::cerr << "[CryptoEngine] [WARN] Chiavi pubbliche RSA non trovate in '" << prov_dir << "'\n";
    }
    if (is_gs_) {
        gs_rsa1024_sk_ = load_rsa_sec(prov_dir + "/gs_rsa1024.sec");
        gs_rsa2048_sk_ = load_rsa_sec(prov_dir + "/gs_rsa2048.sec");
        if (!gs_rsa1024_sk_ || !gs_rsa2048_sk_) {
            std::cerr << "[CryptoEngine] [WARN] Chiavi private RSA non trovate in '" << prov_dir << "'\n";
        }
    }

    std::cout << "[CryptoEngine] Provisioning caricato da '" << prov_dir
              << "' (Ruolo: " << (is_gs_ ? "Ground Station" : "Boa") << ")\n";
    return true;
}

void CryptoEngine::compute_psk_mac(const uint8_t* data, size_t data_len, uint8_t out_tag[PSK_TAG_BYTES]) {
    // Calcola HMAC/crypto_auth standard con Libsodium (conforme a bench_key_management.cpp)
    uint8_t full_tag[crypto_auth_BYTES];
    crypto_auth(full_tag, data, data_len, psk_);
    std::memcpy(out_tag, full_tag, PSK_TAG_BYTES);
}

bool CryptoEngine::verify_psk_mac(const uint8_t* data, size_t data_len, const uint8_t in_tag[PSK_TAG_BYTES]) {
    uint8_t expected[PSK_TAG_BYTES];
    compute_psk_mac(data, data_len, expected);
    return (sodium_memcmp(in_tag, expected, PSK_TAG_BYTES) == 0);
}

bool CryptoEngine::derive_session_keys(const char* label,
                                       const uint8_t* shared_secret, size_t ss_len) {
    if (!shared_secret || ss_len == 0) return false;

    // Identico 1-to-1 a bench_key_management.cpp e bench_mlkem.cpp:
    // HKDF-Extract: Salt = PSK (32B), IKM = Shared Secret (32B o KEM SS)
    uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    if (crypto_kdf_hkdf_sha256_extract(prk, psk_, sizeof(psk_), shared_secret, ss_len) != 0) {
        return false;
    }

    // HKDF-Expand: session_key (32 byte) con label di dominio
    if (crypto_kdf_hkdf_sha256_expand(session_key_, sizeof(session_key_),
                                      label, std::strlen(label), prk) != 0) {
        sodium_memzero(prk, sizeof(prk));
        return false;
    }

    // HKDF-Expand: session_salt (12 byte) per il contatore AEAD
    std::string salt_label = std::string(label) + "_SALT";
    if (crypto_kdf_hkdf_sha256_expand(session_salt_, sizeof(session_salt_),
                                      salt_label.c_str(), salt_label.length(), prk) != 0) {
        sodium_memzero(prk, sizeof(prk));
        return false;
    }

    sodium_memzero(prk, sizeof(prk));
    return true;
}

bool CryptoEngine::encrypt(CryptoAlgorithm algo,
                           uint32_t seq_num,
                           const uint8_t* plaintext,
                           size_t pt_len,
                           std::vector<uint8_t>& out_ciphertext,
                           uint8_t out_tag[AEAD_TAG_LEN]) {
    if (algo == CryptoAlgorithm::BASELINE_CLEAR) {
        out_ciphertext.assign(plaintext, plaintext + pt_len);
        std::memset(out_tag, 0, AEAD_TAG_LEN);
        return true;
    }

    if (algo == CryptoAlgorithm::ASCON_128) {
        uint8_t nonce[16];
        derive_nonce(algo, seq_num, session_salt_, nonce);

        std::vector<uint8_t> ct_buf(pt_len + 16);
        unsigned long long clen = 0;

        int ret = crypto_aead_encrypt(
            ct_buf.data(), &clen,
            plaintext, pt_len,
            nullptr, 0,
            nullptr, nonce, session_key_
        );
        if (ret != 0 || clen < 16) return false;

        out_ciphertext.assign(ct_buf.begin(), ct_buf.begin() + pt_len);
        std::memcpy(out_tag, ct_buf.data() + pt_len, AEAD_TAG_LEN);
        return true;
    }

    if (algo == CryptoAlgorithm::AES_256_GCM) {
        uint8_t nonce[12];
        derive_nonce(algo, seq_num, session_salt_, nonce);

        out_ciphertext.resize(pt_len);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        bool ok = true;
        int len = 0;
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, session_key_, nonce) != 1 ||
            EVP_EncryptUpdate(ctx, out_ciphertext.data(), &len, plaintext, static_cast<int>(pt_len)) != 1 ||
            EVP_EncryptFinal_ex(ctx, out_ciphertext.data() + len, &len) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_LEN, out_tag) != 1) {
            ok = false;
        }
        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    if (algo == CryptoAlgorithm::CHACHA20_SODIUM) {
        uint8_t nonce[12];
        derive_nonce(algo, seq_num, session_salt_, nonce);

        out_ciphertext.resize(pt_len);
        unsigned long long clen = 0;
        int ret = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            out_ciphertext.data(),
            out_tag,
            &clen,
            plaintext,
            pt_len,
            nullptr, 0,
            nullptr,
            nonce,
            session_key_
        );
        return (ret == 0);
    }

    if (algo == CryptoAlgorithm::CHACHA20_OPENSSL) {
        uint8_t nonce[12];
        derive_nonce(algo, seq_num, session_salt_, nonce);

        out_ciphertext.resize(pt_len);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        bool ok = true;
        int len = 0;
        if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1 ||
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, session_key_, nonce) != 1 ||
            EVP_EncryptUpdate(ctx, out_ciphertext.data(), &len, plaintext, static_cast<int>(pt_len)) != 1 ||
            EVP_EncryptFinal_ex(ctx, out_ciphertext.data() + len, &len) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AEAD_TAG_LEN, out_tag) != 1) {
            ok = false;
        }
        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    if (algo == CryptoAlgorithm::RSA_1024_E3 || algo == CryptoAlgorithm::RSA_2048_E3) {
        EVP_PKEY* pk = (algo == CryptoAlgorithm::RSA_1024_E3) ? gs_rsa1024_pk_ : gs_rsa2048_pk_;
        if (!pk) return false;

        std::memset(out_tag, 0, AEAD_TAG_LEN);
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pk, nullptr);
        if (!ctx) return false;

        size_t outlen = 0;
        bool ok = (EVP_PKEY_encrypt_init(ctx) == 1 &&
                   EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == 1 &&
                   EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) == 1 &&
                   EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext, pt_len) == 1);
        if (ok) {
            out_ciphertext.resize(outlen);
            ok = (EVP_PKEY_encrypt(ctx, out_ciphertext.data(), &outlen, plaintext, pt_len) == 1);
            if (ok) out_ciphertext.resize(outlen);
        }
        EVP_PKEY_CTX_free(ctx);
        return ok;
    }

    return false;
}

bool CryptoEngine::decrypt(CryptoAlgorithm algo,
                           uint32_t seq_num,
                           const uint8_t* ciphertext,
                           size_t ct_len,
                           const uint8_t in_tag[AEAD_TAG_LEN],
                           std::vector<uint8_t>& out_plaintext) {
    if (algo == CryptoAlgorithm::BASELINE_CLEAR) {
        out_plaintext.assign(ciphertext, ciphertext + ct_len);
        return true;
    }

    if (algo == CryptoAlgorithm::ASCON_128) {
        uint8_t nonce[16];
        derive_nonce(algo, seq_num, session_salt_, nonce);

        std::vector<uint8_t> ct_and_tag(ct_len + AEAD_TAG_LEN);
        std::memcpy(ct_and_tag.data(), ciphertext, ct_len);
        std::memcpy(ct_and_tag.data() + ct_len, in_tag, AEAD_TAG_LEN);

        out_plaintext.resize(ct_len);
        unsigned long long mlen = 0;

        int ret = crypto_aead_decrypt(
            out_plaintext.data(), &mlen,
            nullptr,
            ct_and_tag.data(), ct_and_tag.size(),
            nullptr, 0,
            nonce, session_key_
        );
        return (ret == 0 && mlen == ct_len);
    }

    if (algo == CryptoAlgorithm::AES_256_GCM) {
        uint8_t nonce[12];
        derive_nonce(algo, seq_num, session_salt_, nonce);

        out_plaintext.resize(ct_len);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        bool ok = true;
        int len = 0;
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, session_key_, nonce) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_LEN, const_cast<uint8_t*>(in_tag)) != 1 ||
            EVP_DecryptUpdate(ctx, out_plaintext.data(), &len, ciphertext, static_cast<int>(ct_len)) != 1 ||
            EVP_DecryptFinal_ex(ctx, out_plaintext.data() + len, &len) != 1) {
            ok = false;
        }
        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    if (algo == CryptoAlgorithm::CHACHA20_SODIUM) {
        uint8_t nonce[12];
        derive_nonce(algo, seq_num, session_salt_, nonce);

        out_plaintext.resize(ct_len);
        int ret = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            out_plaintext.data(),
            nullptr,
            ciphertext,
            ct_len,
            in_tag,
            nullptr, 0,
            nonce,
            session_key_
        );
        return (ret == 0);
    }

    if (algo == CryptoAlgorithm::CHACHA20_OPENSSL) {
        uint8_t nonce[12];
        derive_nonce(algo, seq_num, session_salt_, nonce);

        out_plaintext.resize(ct_len);
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;

        bool ok = true;
        int len = 0;
        if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1 ||
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, session_key_, nonce) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AEAD_TAG_LEN, const_cast<uint8_t*>(in_tag)) != 1 ||
            EVP_DecryptUpdate(ctx, out_plaintext.data(), &len, ciphertext, static_cast<int>(ct_len)) != 1 ||
            EVP_DecryptFinal_ex(ctx, out_plaintext.data() + len, &len) != 1) {
            ok = false;
        }
        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    if (algo == CryptoAlgorithm::RSA_1024_E3 || algo == CryptoAlgorithm::RSA_2048_E3) {
        if (!is_gs_) return false;
        EVP_PKEY* sk = (algo == CryptoAlgorithm::RSA_1024_E3) ? gs_rsa1024_sk_ : gs_rsa2048_sk_;
        if (!sk) return false;

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(sk, nullptr);
        if (!ctx) return false;

        size_t outlen = 0;
        bool ok = (EVP_PKEY_decrypt_init(ctx) == 1 &&
                   EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == 1 &&
                   EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) == 1 &&
                   EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext, ct_len) == 1);
        if (ok) {
            out_plaintext.resize(outlen);
            ok = (EVP_PKEY_decrypt(ctx, out_plaintext.data(), &outlen, ciphertext, ct_len) == 1);
            if (ok) out_plaintext.resize(outlen);
        }
        EVP_PKEY_CTX_free(ctx);
        return ok;
    }

    return false;
}

bool CryptoEngine::kem_encapsulate(KemAlgorithm algo,
                                   std::vector<uint8_t>& out_ciphertext,
                                   std::vector<uint8_t>& out_shared_secret) {
    if (algo == KemAlgorithm::X25519) {
        // Conforme a bench_key_management.cpp:
        // Boa genera chiave effimera, moltiplica per la PK statica di GS.
        uint8_t eph_pk[crypto_kx_PUBLICKEYBYTES];
        uint8_t eph_sk[crypto_kx_SECRETKEYBYTES];
        crypto_kx_keypair(eph_pk, eph_sk);

        out_shared_secret.resize(crypto_scalarmult_BYTES);
        if (crypto_scalarmult_curve25519(out_shared_secret.data(), eph_sk, gs_x25519_pk_) != 0) {
            sodium_memzero(eph_sk, sizeof(eph_sk));
            return false;
        }

        sodium_memzero(eph_sk, sizeof(eph_sk));
        out_ciphertext.assign(eph_pk, eph_pk + sizeof(eph_pk));
        return true;
    }

#if HAS_LIBOQS
    const char* oqs_alg = nullptr;
    const std::vector<uint8_t>* pk_ptr = nullptr;
    if (algo == KemAlgorithm::ML_KEM_512)  { oqs_alg = OQS_KEM_alg_ml_kem_512;  pk_ptr = &gs_mlkem512_pk_; }
    if (algo == KemAlgorithm::ML_KEM_768)  { oqs_alg = OQS_KEM_alg_ml_kem_768;  pk_ptr = &gs_mlkem768_pk_; }
    if (algo == KemAlgorithm::ML_KEM_1024) { oqs_alg = OQS_KEM_alg_ml_kem_1024; pk_ptr = &gs_mlkem1024_pk_; }

    if (oqs_alg && pk_ptr && !pk_ptr->empty()) {
        OQS_KEM* kem = OQS_KEM_new(oqs_alg);
        if (!kem) return false;

        out_ciphertext.resize(kem->length_ciphertext);
        out_shared_secret.resize(kem->length_shared_secret);

        OQS_STATUS st = OQS_KEM_encaps(kem, out_ciphertext.data(), out_shared_secret.data(), pk_ptr->data());
        OQS_KEM_free(kem);
        return (st == OQS_SUCCESS);
    }
#endif

    return false;
}

bool CryptoEngine::kem_decapsulate(KemAlgorithm algo,
                                   const uint8_t* ciphertext,
                                   size_t ct_len,
                                   std::vector<uint8_t>& out_shared_secret) {
    if (!is_gs_) return false;

    if (algo == KemAlgorithm::X25519) {
        if (ct_len != crypto_kx_PUBLICKEYBYTES) return false;
        out_shared_secret.resize(crypto_scalarmult_BYTES);
        return (crypto_scalarmult_curve25519(out_shared_secret.data(), gs_x25519_sk_, ciphertext) == 0);
    }

#if HAS_LIBOQS
    const char* oqs_alg = nullptr;
    const std::vector<uint8_t>* sk_ptr = nullptr;
    if (algo == KemAlgorithm::ML_KEM_512)  { oqs_alg = OQS_KEM_alg_ml_kem_512;  sk_ptr = &gs_mlkem512_sk_; }
    if (algo == KemAlgorithm::ML_KEM_768)  { oqs_alg = OQS_KEM_alg_ml_kem_768;  sk_ptr = &gs_mlkem768_sk_; }
    if (algo == KemAlgorithm::ML_KEM_1024) { oqs_alg = OQS_KEM_alg_ml_kem_1024; sk_ptr = &gs_mlkem1024_sk_; }

    if (oqs_alg && sk_ptr && !sk_ptr->empty()) {
        OQS_KEM* kem = OQS_KEM_new(oqs_alg);
        if (!kem) return false;

        if (ct_len != kem->length_ciphertext) {
            OQS_KEM_free(kem);
            return false;
        }

        out_shared_secret.resize(kem->length_shared_secret);
        OQS_STATUS st = OQS_KEM_decaps(kem, out_shared_secret.data(), ciphertext, sk_ptr->data());
        OQS_KEM_free(kem);
        return (st == OQS_SUCCESS);
    }
#endif

    return false;
}

} // namespace radio
