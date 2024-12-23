#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"

extern "C" {
    __attribute__((weak)) void SSL_set_enforce_rsa_key_usage(SSL *ssl, int enabled) {
    //   if (!ssl->config) {
    //     return;
    //   }
    //   ssl->config->enforce_rsa_key_usage = !!enabled;
    bssl_compat_info("[-] SSL_set_enforce_rsa_key_usage() is not implemented");
  }
}