
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <iostream>

int main() {
    // Generate RSA Key
    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4);
    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) != 1) {
        std::cerr << "Error generating RSA key." << std::endl;
        return 1;
    }

    // Save private key
    FILE *privateFile = fopen("private_key.pem", "wb");
    if (!privateFile) {
        std::cerr << "Unable to open file for writing private key" << std::endl;
        return 1;
    }
    PEM_write_RSAPrivateKey(privateFile, rsa, NULL, NULL, 0, NULL, NULL);
    fclose(privateFile);

    // Save public key
    FILE *publicFile = fopen("public_key.pem", "wb");
    if (!publicFile) {
        std::cerr << "Unable to open file for writing public key" << std::endl;
        return 1;
    }
    PEM_write_RSA_PUBKEY(publicFile, rsa);
    fclose(publicFile);

    // Clean up
    RSA_free(rsa);
    BN_free(bn);

    return 0;
}