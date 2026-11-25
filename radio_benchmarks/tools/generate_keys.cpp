#include <iostream>
#include <fstream>
#include <cstdio>
#include <vector>
#include <sodium.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#if __has_include(<oqs/oqs.h>)
#include <oqs/oqs.h>
#define HAS_LIBOQS 1
#else
#define HAS_LIBOQS 0
#endif

bool write_file(const std::string& path, const uint8_t* data, size_t len) {
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) {
        std::cerr << "Errore apertura file in scrittura: " << path << "\n";
        return false;
    }
    ofs.write(reinterpret_cast<const char*>(data), len);
    return ofs.good();
}

int main(int argc, char* argv[]) {
    std::string out_dir = "provisioning";
    if (argc > 1) out_dir = argv[1];

    if (sodium_init() < 0) {
        std::cerr << "Errore inizializzazione libsodium\n";
        return 1;
    }

    std::cout << "========================================================\n";
    std::cout << "  ZENO ATLAS - MISSION PROVISIONING KEY GENERATOR\n";
    std::cout << "  Output dir: " << out_dir << "\n";
    std::cout << "========================================================\n\n";

    // 1. Pre-Shared Key (PSK) a 256 bit per autenticazione canale
    uint8_t psk[crypto_auth_KEYBYTES];
    randombytes_buf(psk, sizeof(psk));
    write_file(out_dir + "/psk.key", psk, sizeof(psk));
    std::cout << "[OK] Generata PSK (32 B) -> " << out_dir << "/psk.key\n";

    // 2. Chiavi Statiche Ground Station X25519 (ECDH)
    uint8_t gs_x25519_pk[crypto_kx_PUBLICKEYBYTES];
    uint8_t gs_x25519_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(gs_x25519_pk, gs_x25519_sk);
    write_file(out_dir + "/gs_x25519.pub", gs_x25519_pk, sizeof(gs_x25519_pk));
    write_file(out_dir + "/gs_x25519.sec", gs_x25519_sk, sizeof(gs_x25519_sk));
    std::cout << "[OK] Generate chiavi GS X25519 (PK: 32 B, SK: 32 B)\n";

#if HAS_LIBOQS
    auto gen_oqs_keypair = [&](const char* alg_name, const std::string& prefix) {
        OQS_KEM* kem = OQS_KEM_new(alg_name);
        if (!kem) {
            std::cerr << "Errore creazione KEM: " << alg_name << "\n";
            return;
        }
        std::vector<uint8_t> pk(kem->length_public_key);
        std::vector<uint8_t> sk(kem->length_secret_key);
        if (OQS_KEM_keypair(kem, pk.data(), sk.data()) == OQS_SUCCESS) {
            write_file(out_dir + "/" + prefix + ".pub", pk.data(), pk.size());
            write_file(out_dir + "/" + prefix + ".sec", sk.data(), sk.size());
            std::cout << "[OK] Generate chiavi GS " << alg_name 
                      << " (PK: " << pk.size() << " B, SK: " << sk.size() << " B)\n";
        }
        OQS_KEM_free(kem);
    };

    gen_oqs_keypair(OQS_KEM_alg_ml_kem_512, "gs_mlkem512");
    gen_oqs_keypair(OQS_KEM_alg_ml_kem_768, "gs_mlkem768");
    gen_oqs_keypair(OQS_KEM_alg_ml_kem_1024, "gs_mlkem1024");
#else
    std::cout << "[WARN] liboqs non disponibile, ML-KEM saltato.\n";
#endif

    // 4. Chiavi Statiche Ground Station RSA (1024 e 2048 bit, esponente pubblico e = 3)
    auto gen_rsa_keypair = [&](int bits, const std::string& prefix) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) {
            std::cerr << "[ERR] EVP_PKEY_CTX_new_id fallito per RSA-" << bits << "\n";
            return;
        }
        BIGNUM* e_bn = BN_new();
        BN_set_word(e_bn, 3);

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0 ||
            EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e_bn) <= 0 ||
            EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            std::cerr << "[ERR] Generazione RSA-" << bits << " (e=3) fallita\n";
            BN_free(e_bn);
            EVP_PKEY_CTX_free(ctx);
            return;
        }
        BN_free(e_bn);
        EVP_PKEY_CTX_free(ctx);

        std::string pub_path = out_dir + "/" + prefix + ".pub";
        std::string sec_path = out_dir + "/" + prefix + ".sec";

        FILE* f_pub = std::fopen(pub_path.c_str(), "wb");
        if (f_pub) {
            PEM_write_PUBKEY(f_pub, pkey);
            std::fclose(f_pub);
        }
        FILE* f_sec = std::fopen(sec_path.c_str(), "wb");
        if (f_sec) {
            PEM_write_PrivateKey(f_sec, pkey, nullptr, nullptr, 0, nullptr, nullptr);
            std::fclose(f_sec);
        }
        EVP_PKEY_free(pkey);
        std::cout << "[OK] Generate chiavi GS RSA-" << bits << " (e=3) -> " << prefix << ".pub/.sec\n";
    };

    gen_rsa_keypair(1024, "gs_rsa1024");
    gen_rsa_keypair(2048, "gs_rsa2048");

    std::cout << "\n[PROVISIONING COMPLETATO CON SUCCESSO]\n";
    std::cout << "Nota: Copiare i file .pub e psk.key sul Raspberry Pi (Boa).\n";
    std::cout << "      Mantenere i file .sec, .pub e psk.key su Zeno (Ground Station).\n";

    return 0;
}
