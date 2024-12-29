#include <openssl/base.h>
#include <openssl/aes.h>
#include <ossl.h>

struct AES_KEY {
    uint32_t rd_key[60];
    int rounds;
};

extern "C" int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key) {
    return ossl.ossl_AES_set_encrypt_key(userKey, bits, reinterpret_cast<ossl_AES_KEY*>(key));
}

extern "C" int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key) {
    return ossl.ossl_AES_set_decrypt_key(userKey, bits, reinterpret_cast<ossl_AES_KEY*>(key));
}

extern "C" void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key) {
    ossl.ossl_AES_encrypt(in, out, reinterpret_cast<const ossl_AES_KEY*>(key));
}

extern "C" void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key) {
    ossl.ossl_AES_decrypt(in, out, reinterpret_cast<const ossl_AES_KEY*>(key));
}

extern "C" void AES_ecb_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key, const int enc) {
    ossl.ossl_AES_ecb_encrypt(in, out, reinterpret_cast<const ossl_AES_KEY*>(key), enc);
}

extern "C" void AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, 
                               const AES_KEY *key, unsigned char *ivec, const int enc) {
    ossl.ossl_AES_cbc_encrypt(in, out, length, reinterpret_cast<const ossl_AES_KEY*>(key), ivec, enc);
}