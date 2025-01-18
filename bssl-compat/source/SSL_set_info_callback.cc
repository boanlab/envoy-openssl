#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


void SSL_set_info_callback( SSL *ssl, void (*cb)(const SSL *ssl, int type, int value)) {
    // bssl_compat_info("[+]SSL_METHOD::SSL_set_info_callback");
#ifdef ossl_SSL_set_info_callback
    return ossl_SSL_set_info_callback(ssl, ssl, cb);
#else
    return ossl.ossl_SSL_set_info_callback(ssl, cb);
#endif
}
