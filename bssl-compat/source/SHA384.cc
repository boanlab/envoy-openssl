#include <openssl/base.h>
#include <openssl/sha.h>
#include <ossl.h>

extern "C" int SHA384_Init(ossl_SHA512_CTX *ctx) {
    return ossl.ossl_SHA384_Init(ctx);
}

extern "C" int SHA384_Update(ossl_SHA512_CTX *ctx, const void *data, size_t len) {
    return ossl.ossl_SHA384_Update(ctx, data, len);
}

extern "C" int SHA384_Final(unsigned char *md, ossl_SHA512_CTX *ctx) {
    return ossl.ossl_SHA384_Final(md, ctx);
}

// extern "C" void SHA384_Transform(SHA512_CTX *ctx, const unsigned char *data) {
//     return ossl.ossl_SHA384_Transform(ctx, data);
// }