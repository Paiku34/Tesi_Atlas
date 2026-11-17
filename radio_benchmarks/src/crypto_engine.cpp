#include "crypto_engine.hpp"

#include <cstring>
#include <stdexcept>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <sodium.h>

#if __has_include(<oqs/oqs.h>)
#include <oqs/oqs.h>
#define HAS_LIBOQS 1
#else
#define HAS_LIBOQS 0
#endif

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

CryptoEngine::CryptoEngine() {
    if (sodium_init() < 0) {
        std::cerr << "[CryptoEngine] Fallimento sodium_init()\n";
    }
    setup_keys();
}

CryptoEngine::~CryptoEngine() {}

void CryptoEngine::setup_keys() {
    const uint8_t default_key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };
    const uint8_t default_salt[12] = {
        0xA0, 0xA1, 0xA2, 0xA3, 0xB0, 0xB1, 0xB2, 0xB3, 0xC0, 0xC1, 0xC2, 0xC3
    };
    std::memcpy(session_key_, default_key, sizeof(session_key_));
    std::memcpy(session_salt_, default_salt, sizeof(session_salt_));
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

    return false;
}

static const uint8_t GS_STATIC_X25519_PK[32] = {
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
    0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x15, 0xe4,
    0x25, 0xb0, 0x11, 0x82, 0x80, 0xa2, 0xf4, 0x28
};
static const uint8_t GS_STATIC_X25519_SK[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};

#if HAS_LIBOQS
struct MlKemStaticKeys {
    bool initialized = false;
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
};

static MlKemStaticKeys g_mlkem_keys[3];

static int mlkem_algo_index(KemAlgorithm algo) {
    switch (algo) {
        case KemAlgorithm::ML_KEM_512:  return 0;
        case KemAlgorithm::ML_KEM_768:  return 1;
        case KemAlgorithm::ML_KEM_1024: return 2;
        default: return -1;
    }
}

static bool ensure_mlkem_keys(KemAlgorithm algo, OQS_KEM* kem,
                              const uint8_t*& out_pk, const uint8_t*& out_sk) {
    int idx = mlkem_algo_index(algo);
    if (idx < 0) return false;

    MlKemStaticKeys& keys = g_mlkem_keys[idx];
    if (!keys.initialized) {
        keys.pk.resize(kem->length_public_key);
        keys.sk.resize(kem->length_secret_key);

        static const char* key_files_pk[3] = { "gs_mlkem512.pk", "gs_mlkem768.pk", "gs_mlkem1024.pk" };
        static const char* key_files_sk[3] = { "gs_mlkem512.sk", "gs_mlkem768.sk", "gs_mlkem1024.sk" };

        FILE* fpk = fopen(key_files_pk[idx], "rb");
        FILE* fsk = fopen(key_files_sk[idx], "rb");
        if (fpk && fsk) {
            size_t r1 = fread(keys.pk.data(), 1, keys.pk.size(), fpk);
            size_t r2 = fread(keys.sk.data(), 1, keys.sk.size(), fsk);
            fclose(fpk);
            fclose(fsk);
            if (r1 == keys.pk.size() && r2 == keys.sk.size()) {
                keys.initialized = true;
                out_pk = keys.pk.data();
                out_sk = keys.sk.data();
                return true;
            }
        }
        if (fpk) fclose(fpk);
        if (fsk) fclose(fsk);

        if (OQS_KEM_keypair(kem, keys.pk.data(), keys.sk.data()) != OQS_SUCCESS) {
            return false;
        }

        fpk = fopen(key_files_pk[idx], "wb");
        fsk = fopen(key_files_sk[idx], "wb");
        if (fpk && fsk) {
            fwrite(keys.pk.data(), 1, keys.pk.size(), fpk);
            fwrite(keys.sk.data(), 1, keys.sk.size(), fsk);
        }
        if (fpk) fclose(fpk);
        if (fsk) fclose(fsk);

        keys.initialized = true;
    }
    out_pk = keys.pk.data();
    out_sk = keys.sk.data();
    return true;
}
#endif

bool CryptoEngine::kem_encapsulate(KemAlgorithm algo,
                                   std::vector<uint8_t>& out_ciphertext,
                                   std::vector<uint8_t>& out_shared_secret) {
    if (algo == KemAlgorithm::X25519) {
        uint8_t eph_pk[crypto_kx_PUBLICKEYBYTES];
        uint8_t eph_sk[crypto_kx_SECRETKEYBYTES];
        crypto_kx_keypair(eph_pk, eph_sk);

        out_shared_secret.resize(crypto_scalarmult_BYTES);
        if (crypto_scalarmult_curve25519(out_shared_secret.data(), eph_sk, GS_STATIC_X25519_PK) != 0) {
            return false;
        }

        out_ciphertext.assign(eph_pk, eph_pk + sizeof(eph_pk));
        return true;
    }

#if HAS_LIBOQS
    const char* oqs_alg = nullptr;
    if (algo == KemAlgorithm::ML_KEM_512)  oqs_alg = OQS_KEM_alg_ml_kem_512;
    if (algo == KemAlgorithm::ML_KEM_768)  oqs_alg = OQS_KEM_alg_ml_kem_768;
    if (algo == KemAlgorithm::ML_KEM_1024) oqs_alg = OQS_KEM_alg_ml_kem_1024;

    if (oqs_alg) {
        OQS_KEM* kem = OQS_KEM_new(oqs_alg);
        if (!kem) return false;

        const uint8_t* gs_pk = nullptr;
        const uint8_t* gs_sk = nullptr;
        if (!ensure_mlkem_keys(algo, kem, gs_pk, gs_sk)) {
            OQS_KEM_free(kem);
            return false;
        }

        out_ciphertext.resize(kem->length_ciphertext);
        out_shared_secret.resize(kem->length_shared_secret);

        OQS_STATUS st = OQS_KEM_encaps(kem, out_ciphertext.data(), out_shared_secret.data(), gs_pk);
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
    if (algo == KemAlgorithm::X25519) {
        if (ct_len != 32) return false;
        out_shared_secret.resize(crypto_scalarmult_BYTES);
        return (crypto_scalarmult_curve25519(out_shared_secret.data(), GS_STATIC_X25519_SK, ciphertext) == 0);
    }

#if HAS_LIBOQS
    const char* oqs_alg = nullptr;
    if (algo == KemAlgorithm::ML_KEM_512)  oqs_alg = OQS_KEM_alg_ml_kem_512;
    if (algo == KemAlgorithm::ML_KEM_768)  oqs_alg = OQS_KEM_alg_ml_kem_768;
    if (algo == KemAlgorithm::ML_KEM_1024) oqs_alg = OQS_KEM_alg_ml_kem_1024;

    if (oqs_alg) {
        OQS_KEM* kem = OQS_KEM_new(oqs_alg);
        if (!kem) return false;

        const uint8_t* gs_pk = nullptr;
        const uint8_t* gs_sk = nullptr;
        if (!ensure_mlkem_keys(algo, kem, gs_pk, gs_sk)) {
            OQS_KEM_free(kem);
            return false;
        }

        if (ct_len != kem->length_ciphertext) {
            std::cerr << "[CryptoEngine] ML-KEM decaps: ciphertext size mismatch ("
                      << ct_len << " vs " << kem->length_ciphertext << ")\n";
            OQS_KEM_free(kem);
            return false;
        }

        out_shared_secret.resize(kem->length_shared_secret);
        OQS_STATUS st = OQS_KEM_decaps(kem, out_shared_secret.data(), ciphertext, gs_sk);
        OQS_KEM_free(kem);
        return (st == OQS_SUCCESS);
    }
#endif

    return false;
}

static bool derive_hkdf_sub(const uint8_t* secret, size_t secret_len,
                            const char* info, uint8_t* out, size_t out_len) {
    static const uint8_t hkdf_salt[] = "ZENO-ATLAS-KEM-HKDF-SALT-V1";
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) return false;

    bool ok = (EVP_PKEY_derive_init(pctx) > 0) &&
              (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) > 0) &&
              (EVP_PKEY_CTX_set1_hkdf_salt(pctx, hkdf_salt, sizeof(hkdf_salt) - 1) > 0) &&
              (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, static_cast<int>(secret_len)) > 0) &&
              (EVP_PKEY_CTX_add1_hkdf_info(pctx, reinterpret_cast<const unsigned char*>(info),
                                            static_cast<int>(std::strlen(info))) > 0) &&
              (EVP_PKEY_derive(pctx, out, &out_len) > 0);

    EVP_PKEY_CTX_free(pctx);
    return ok;
}

bool CryptoEngine::set_session_key_from_kem(const uint8_t* shared_secret, size_t ss_len) {
    if (!shared_secret || ss_len == 0) return false;

    uint8_t derived_key[32];
    uint8_t derived_salt[12];

    if (!derive_hkdf_sub(shared_secret, ss_len, "atlas-session-key", derived_key, sizeof(derived_key)) ||
        !derive_hkdf_sub(shared_secret, ss_len, "atlas-session-salt", derived_salt, sizeof(derived_salt))) {
        return false;
    }

    std::memcpy(session_key_, derived_key, sizeof(session_key_));
    std::memcpy(session_salt_, derived_salt, sizeof(session_salt_));
    OPENSSL_cleanse(derived_key, sizeof(derived_key));
    OPENSSL_cleanse(derived_salt, sizeof(derived_salt));

    std::cout << "[CryptoEngine] Session key aggiornata da KEM shared secret ("
              << ss_len << " B) via HKDF-SHA256\n";
    return true;
}

} // namespace radio
