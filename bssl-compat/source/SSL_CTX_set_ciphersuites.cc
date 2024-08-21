#include <openssl/ssl.h> // boringssl 헤더 지정이 되어 있지 않음
#include <ossl.h>
#include "iana_2_ossl_names.h"

extern "C" int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str) {
  std::string osslstr {iana_2_ossl_names(str)};

  // OpenSSL's SSL_CTX_set_ciphersuites() performs virtually no checking on str.
  // It only returns 0 (fail) if no cipher could be selected from the list at
  // all. Otherwise it returns 1 (pass) even if there is only one cipher in the
  // string that makes sense, and the rest are unsupported or even just rubbish.
  if (ossl.ossl_SSL_CTX_set_ciphersuites(ctx, osslstr.c_str()) == 0) {
    return 0;
  }

  STACK_OF(SSL_CIPHER)* ciphers = reinterpret_cast<STACK_OF(SSL_CIPHER)*>(ossl.ossl_SSL_CTX_get_ciphers(ctx));
  char* dup = strdup(osslstr.c_str());
  char* token = strtok(dup, ":+![|]");
  while (token != NULL) {
    std::string str1(token);
    bool found = false;
    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
      const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
      std::string str2(SSL_CIPHER_get_name(cipher));
      if (str1.compare(str2) == 0) {
        found = true;
      }
    }

    if (!found && str1.compare("-ALL") && str1.compare("ALL")) {
      free(dup);
      return 0;
    }

    token = strtok(NULL, ":[]|");
  }

  free(dup);
  return 1;
}