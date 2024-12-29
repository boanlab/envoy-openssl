#include <openssl/sha.h>
#include <ossl.h>

extern "C" int SHA224_Init(SHA256_CTX *c) {
    return ossl.ossl_SHA224_Init(c);
}

extern "C" int SHA224_Update(SHA256_CTX *ctx, const void *data, size_t len) {
    return ossl.ossl_SHA224_Update(ctx, data, len);
}

extern "C" int SHA224_Final(unsigned char *md, SHA256_CTX *ctx) {
    return ossl.ossl_SHA224_Final(md, ctx);
}