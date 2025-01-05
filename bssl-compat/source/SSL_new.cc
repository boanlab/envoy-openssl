#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"

extern "C" SSL* SSL_new(SSL_CTX *ctx) {
    bssl_compat_info("[+]SSL_METHOD::SSL_new");

    SSL* ssl = ossl.ossl_SSL_new(ctx);
    if (!ssl) {
        return NULL;
    }
    return ssl;
}

