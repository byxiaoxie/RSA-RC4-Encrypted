#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fstream>

#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

class RSAWrapper {
public:
    RSAWrapper(int bits = 2048) {
        generateRSAKeyPair(bits);
    }

    ~RSAWrapper() {
        if (keypair) {
            EVP_PKEY_free(keypair);
        }
    }

    std::string encrypt(const std::string& plaintext) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(keypair, nullptr);
        if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
            handleOpenSSLErrors();
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            handleOpenSSLErrors();
        }

        size_t outlen;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, (const unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) {
            handleOpenSSLErrors();
        }

        std::string encrypted(outlen, '\0');
        if (EVP_PKEY_encrypt(ctx, (unsigned char*)encrypted.data(), &outlen, (const unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) {
            handleOpenSSLErrors();
        }

        EVP_PKEY_CTX_free(ctx);
        encrypted.resize(outlen);
        return encrypted;
    }

    std::string decrypt(const std::string& ciphertext) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(keypair, nullptr);
        if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
            handleOpenSSLErrors();
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            handleOpenSSLErrors();
        }

        size_t outlen;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, (const unsigned char*)ciphertext.c_str(), ciphertext.size()) <= 0) {
            handleOpenSSLErrors();
        }

        std::string decrypted(outlen, '\0');
        if (EVP_PKEY_decrypt(ctx, (unsigned char*)decrypted.data(), &outlen, (const unsigned char*)ciphertext.c_str(), ciphertext.size()) <= 0) {
            handleOpenSSLErrors();
        }

        EVP_PKEY_CTX_free(ctx);
        decrypted.resize(outlen);
        return decrypted;
    }

    std::string encryptWithPublicKeyFromFile(const std::string& plaintext, const std::string& publicKeyFile) {
        if (!fileExists(publicKeyFile)) {
            std::cerr << "Public key file not found: " << publicKeyFile << std::endl;
            return "";
        }

        EVP_PKEY* publicKey = loadPublicKeyFromFile(publicKeyFile);
        if (!publicKey) {
            handleOpenSSLErrors();
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, nullptr);
        if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
            handleOpenSSLErrors();
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            handleOpenSSLErrors();
        }

        size_t outlen;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, (const unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) {
            handleOpenSSLErrors();
        }

        std::string encrypted(outlen, '\0');
        if (EVP_PKEY_encrypt(ctx, (unsigned char*)encrypted.data(), &outlen, (const unsigned char*)plaintext.c_str(), plaintext.size()) <= 0) {
            handleOpenSSLErrors();
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        encrypted.resize(outlen);
        return encrypted;
    }

    std::string decryptWithPrivateKeyFromFile(const std::string& ciphertext, const std::string& privateKeyFile) {
        if (!fileExists(privateKeyFile)) {
            std::cerr << "Private key file not found: " << privateKeyFile << std::endl;
            return "";
        }

        EVP_PKEY* privateKey = loadPrivateKeyFromFile(privateKeyFile);
        if (!privateKey) {
            handleOpenSSLErrors();
        }

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
        if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
            handleOpenSSLErrors();
        }

        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            handleOpenSSLErrors();
        }

        size_t outlen;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, (const unsigned char*)ciphertext.c_str(), ciphertext.size()) <= 0) {
            handleOpenSSLErrors();
        }

        std::string decrypted(outlen, '\0');
        if (EVP_PKEY_decrypt(ctx, (unsigned char*)decrypted.data(), &outlen, (const unsigned char*)ciphertext.c_str(), ciphertext.size()) <= 0) {
            handleOpenSSLErrors();
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        decrypted.resize(outlen);
        return decrypted;
    }

private:
    EVP_PKEY* keypair = nullptr;

    void generateRSAKeyPair(int bits) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0) {
            handleOpenSSLErrors();
        }
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
            handleOpenSSLErrors();
        }
        if (EVP_PKEY_keygen(ctx, &keypair) <= 0) {
            handleOpenSSLErrors();
        }
        EVP_PKEY_CTX_free(ctx);
    }

    EVP_PKEY* loadPublicKeyFromFile(const std::string& publicKeyFile) {
        FILE* file = fopen(publicKeyFile.c_str(), "r");
        if (!file) {
            perror("Unable to open public key file");
            return nullptr;
        }
        EVP_PKEY* publicKey = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
        fclose(file);
        return publicKey;
    }

    EVP_PKEY* loadPrivateKeyFromFile(const std::string& privateKeyFile) {
        FILE* file = fopen(privateKeyFile.c_str(), "r");
        if (!file) {
            perror("Unable to open private key file");
            return nullptr;
        }
        EVP_PKEY* privateKey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
        fclose(file);
        return privateKey;
    }

    bool fileExists(const std::string& fileName) {
        std::ifstream infile(fileName);
        return infile.good();
    }

    void handleOpenSSLErrors() {
        ERR_print_errors_fp(stderr);
        abort();
    }
};