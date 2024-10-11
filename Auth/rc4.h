#ifndef RC4_H
#define RC4_H

#include <vector>
#include <string>

class RC4 {
public:
    // 构造密钥
    RC4(const std::string& key) : key(key) {}

    // 公钥加密
    std::string encrypt(const std::string& plaintext) {
        initialize();
        return process(plaintext);
    }

    // 私钥解密
    std::string decrypt(const std::string& ciphertext) {
        initialize();
        return process(ciphertext);
    }

private:
    std::vector<unsigned char> S;
    int i = 0, j = 0;
    std::string key;

    void initialize() {
        int keyLength = key.size();
        S.resize(256);
        for (int i = 0; i < 256; ++i) {
            S[i] = i;
        }

        j = 0;
        for (int i = 0; i < 256; ++i) {
            j = (j + S[i] + key[i % keyLength]) % 256;
            std::swap(S[i], S[j]);
        }

        i = 0;
        j = 0;
    }

    std::string process(const std::string& data) {
        std::string output(data.size(), '\0');

        for (size_t n = 0; n < data.size(); ++n) {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;

            std::swap(S[i], S[j]);
            unsigned char rnd = S[(S[i] + S[j]) % 256];
            output[n] = data[n] ^ rnd;
        }
        return output;
    }
};

#endif // RC4_H