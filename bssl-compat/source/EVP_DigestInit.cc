#include <openssl/digest.h>
#include <ossl.h>
#include "log.h"

extern "C" int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type) {
    bssl_compat_info("[+] SSL_METHOD::EVP_DigestInit");
    if (!ctx || !type) {
        bssl_compat_info("[-] SSL_METHOD::EVP_DigestInit failed: invalid parameters");
        return 0;
    }
    return ossl.ossl_EVP_DigestInit(ctx, type);
}