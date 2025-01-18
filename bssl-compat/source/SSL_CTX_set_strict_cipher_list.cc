#include <string>
#include <cstring>
#include <openssl/ssl.h>
#include <ossl.h>
#include "iana_2_ossl_names.h"
#include "log.h"


/*
 * https://github.com/google/boringssl/blob/098695591f3a2665fccef83a3732ecfc99acdcdd/src/include/openssl/ssl.h#L1508
 *
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_cipher_list.html
 * https://www.openssl.org/docs/man3.0/man3/SSL_CTX_get_ciphers.html
 * https://www.openssl.org/docs/man3.0/man3/SSL_CIPHER_get_name.html
 */
// extern "C" int SSL_CTX_set_strict_cipher_list(SSL_CTX *ctx, const char *str) {
//   if(!ossl.ossl_SSL_CTX_set_ciphersuites(ctx, str))
//     // // bssl_compat_info("[-]call SSL_METHOD::SSL_CTX_set_ciphersuites fail.. %s", str);

//   std::string osslstr {iana_2_ossl_names(str)};
//   // // bssl_compat_info("[+]call SSL_METHOD::SSL_CTX_set_strict_cipher_list");
//   // OpenSSL's SSL_CTX_set_cipher_list() performs virtually no checking on str.
//   // It only returns 0 (fail) if no cipher could be selected from the list at
//   // all. Otherwise it returns 1 (pass) even if there is only one cipher in the
//   // string that makes sense, and the rest are unsupported or even just rubbish.

//   if (ossl.ossl_SSL_CTX_set_cipher_list(ctx, osslstr.c_str()) == 0) {
//     return 0;
//   }

//   // // bssl_compat_info("[+]call SSL_METHOD::SSL_CTX_set_strict_cipher_list - ossl_SSL_CTX_get_ciphers");
//   STACK_OF(SSL_CIPHER)* ciphers = reinterpret_cast<STACK_OF(SSL_CIPHER)*>(ossl.ossl_SSL_CTX_get_ciphers(ctx));
//   char* dup = strdup(osslstr.c_str());
//   char* token = strtok(dup, ":+![|]");
//   while (token != NULL) {
//      std::string str1(token);
//      bool found = false;
//      for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
//        const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
//        // // bssl_compat_info("[+]call SSL_METHOD::SSL_CTX_set_strict_cipher_list - loop: %s", cipher);
//        std::string str2(SSL_CIPHER_get_name(cipher));
//        if (str1.compare(str2) == 0) {
//          found = true;
//        }
//      }

//      if (!found && str1.compare("-ALL") && str1.compare("ALL")) {
//        free(dup);
//        return 0;
//      }

//      token = strtok(NULL, ":[]|");
//    }
//    free(dup);
//    return 1;
// }

extern "C" int SSL_CTX_set_strict_cipher_list(SSL_CTX *ctx, const char *str) {
    if (!ctx || !str) return 0;

    // TLSv1.3 ciphersuites strings
    char *tmp = strdup(str);
    char *tls13_suites = nullptr;
    char *legacy_suites = nullptr;
    char *token = strtok(tmp, ":");
    
    std::string tls13_str;
    std::string legacy_str;

    while (token) {
        std::string current_token(token);
        // TLSv1.3 cipher suites
        if (current_token.find("TLS_") == 0 || current_token.find("TLS13_") == 0) {
            if (!tls13_str.empty()) tls13_str += ":";
            tls13_str += current_token;
        } else {
            if (!legacy_str.empty()) legacy_str += ":";
            legacy_str += current_token;
        }
        token = strtok(nullptr, ":");
    }
    free(tmp);

    // TLSv1.3 cipher suites handling
    if (!tls13_str.empty()) {
        if (!ossl.ossl_SSL_CTX_set_ciphersuites(ctx, tls13_str.c_str())) {
            // // bssl_compat_info("[-]call SSL_METHOD::SSL_CTX_set_ciphersuites fail.. %s", tls13_str.c_str());
        }
    }

    // Legacy cipher suites handling
    std::string osslstr{iana_2_ossl_names(legacy_str.c_str())};
    // bssl_compat_info("[+]call SSL_METHOD::SSL_CTX_set_strict_cipher_list");

    if (ossl.ossl_SSL_CTX_set_cipher_list(ctx, osslstr.c_str()) == 0) {
        return 0;
    }

    // // bssl_compat_info("[+]call SSL_METHOD::SSL_CTX_set_strict_cipher_list - ossl_SSL_CTX_get_ciphers");
    STACK_OF(SSL_CIPHER)* ciphers = reinterpret_cast<STACK_OF(SSL_CIPHER)*>(ossl.ossl_SSL_CTX_get_ciphers(ctx));
    
    char* dup = strdup(osslstr.c_str());
    char* cipher_token = strtok(dup, ":+![|]");
    while (cipher_token != nullptr) {
        std::string str1(cipher_token);
        bool found = false;
        for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
            const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
            std::string str2(SSL_CIPHER_get_name(cipher));
            if (str1.compare(str2) == 0) {
                found = true;
                break;
            }
        }

        if (!found && str1.compare("-ALL") && str1.compare("ALL")) {
            free(dup);
            return 0;
        }

        cipher_token = strtok(nullptr, ":+![|]");
    }
    free(dup);
    return 1;
}