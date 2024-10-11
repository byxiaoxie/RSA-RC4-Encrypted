#define _CRT_SECURE_NO_WARNINGS

#include <iostream>

#include "rc4.h"
#include "rsa.h"

using namespace std;

void main()
{
	cout << "Gary Auth Demo" << endl;

    RSAWrapper rsa;

    // Rsa + RC4 ¼ÓÃÜ½âÃÜ
    std::string rc4Key = "Gary";
    std::string plaintext = "Hello, World!";

    RC4 rc4(rc4Key);
    std::string rc4Encrypted = rc4.encrypt(plaintext);
    std::string rsaEncrypted = rsa.encrypt(rc4Encrypted);

    std::string rsaDecrypted = rsa.decrypt(rsaEncrypted);
    std::string rc4Decrypted = rc4.decrypt(rsaDecrypted);


    std::cout << "Original: " << plaintext << " | Length:" << plaintext.size() << std::endl;
    // std::cout << "Encrypted: " << rsaEncrypted << "Length:" << rsaEncrypted.size() << std::endl;
    std::cout << "Decrypted: " << rc4Decrypted << " | Length:" << rsaDecrypted.size() << std::endl << std::endl;

    std::string publicKeyFile = "public.pem";
    std::string privateKeyFile = "private.pem";

    std::string fileEncrypted = rsa.encryptWithPublicKeyFromFile(plaintext, publicKeyFile);
    std::string fileDecrypted = rsa.decryptWithPrivateKeyFromFile(fileEncrypted, privateKeyFile);

    std::cout << "Encrypted: " << fileEncrypted << " | Length: " << fileEncrypted.size() << std::endl;
    std::cout << "Decrypted: " << fileDecrypted << " | Length: " << fileDecrypted.size() << std::endl;


	system("pause");
	return;
}