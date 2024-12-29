#include <openssl/base.h>
#include <openssl/sha.h>
#include <ossl.h>

extern "C" int SHA512_Init(ossl_SHA512_CTX *ctx) {
   return ossl.ossl_SHA512_Init(ctx);
}

extern "C" int SHA512_Update(ossl_SHA512_CTX *ctx, const void *data, size_t len) {
   return ossl.ossl_SHA512_Update(ctx, data, len);
}

extern "C" int SHA512_Final(unsigned char *md, ossl_SHA512_CTX *ctx) {
   return ossl.ossl_SHA512_Final(md, ctx);
}

extern "C" void SHA512_Transform(ossl_SHA512_CTX *ctx, const unsigned char *data) {
   ossl.ossl_SHA512_Transform(ctx, data);
}