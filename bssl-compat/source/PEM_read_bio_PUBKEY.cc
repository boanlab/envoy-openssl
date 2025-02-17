#include <openssl/pem.h>
#include <ossl/openssl/pem.h>
#include <ossl.h>
#include "log.h"

// BoringSSL function decl is described in pem.h as *PEM_read_bio_##name
extern "C" EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u) {
    // bssl_compat_info("[+]SSL_METHOD::PEM_read_bio_PUBKEY");
    // OpenSSL function is in crypto/pem/pem_pkey.c for comparison
    return ossl.ossl_PEM_read_bio_PUBKEY(bp, x, cb, u);
}
