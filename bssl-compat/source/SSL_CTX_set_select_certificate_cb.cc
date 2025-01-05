#include <openssl/ssl.h>
#include <ossl.h>
#include "log.h"


// /**
//  * This is the callback type for BoringSSL's SSL_CTX_set_select_certificate_cb()
//  */
// typedef enum ssl_select_cert_result_t (*select_certificate_cb_t)(const SSL_CLIENT_HELLO *);


// /**
//  * We construct an instance of this class on the stack in a scope that surrounds
//  * the invocation of the user's callback. It is then possible to use the
//  * in_select_certificate_cb(ssl) function to query whether or not we are
//  * executing within a SSL_CTX_set_select_certificate_cb() callback for that SSL
//  * object, or not.
//  * 
//  * This mechanism is used by the SSL_get_servername() function to provide a
//  * different implementation depending on it's invocation context.
//  */
// class ActiveSelectCertificateCb {
//   public:
//     ActiveSelectCertificateCb(SSL *ssl) : ssl_(ssl) {
//       bssl_compat_info("[+]call SSL_METHOD::ssl_ctx_client_hello_cb1 - SSL_set_ex_data");
//       SSL_set_ex_data(ssl_, index(), this);
//     }
//     ~ActiveSelectCertificateCb() {
//       bssl_compat_info("[+]call SSL_METHOD::ssl_ctx_client_hello_cb2 - SSL_set_ex_data");
//       SSL_set_ex_data(ssl_, index(), nullptr);
//     }
//     static int index() {
//       bssl_compat_info("[+]call SSL_METHOD::ssl_ctx_client_hello_cb3 - SSL_get_ex_new_index");
//       static int index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr,
//                               +[](void *, void *ptr, CRYPTO_EX_DATA *, int, long, void*) {
//                                 if (ptr) ossl_OPENSSL_free(ptr);
//                               });
//       return index;
//     }
//   private:
//     SSL *ssl_;
// };

// /**
//  * Returns true if we are currently in a SSL_CTX_set_select_certificate_cb()
//  * callback invocation for the specified SSL object.
//  */
// bool in_select_certificate_cb(const SSL *ssl) {
//   bssl_compat_info("[+]call SSL_METHOD::ssl_ctx_client_hello_cb-SSL_get_ex_data");
//   return SSL_get_ex_data(ssl, ActiveSelectCertificateCb::index()) != nullptr;
// }


// /*
//  * This callback function is plugged into OpenSSL using
//  * ossl_SSL_CTX_set_client_hello_cb(). When it is invoked, we create an instance
//  * of BoringSSL's SSL_CLIENT_HELLO struct, and fill it in the best we can, and
//  * then invoke the caller's actual BoringSSL style callback function (arg),
//  * passing it the SSL_CLIENT_HELLO.
//  */
// static int ssl_ctx_client_hello_cb(SSL *ssl, int *alert, void *arg) {
//   bssl_compat_info("[+]call SSL_METHOD::ssl_ctx_client_hello_cb - ssl_ctx_client_hello_cb");
//   select_certificate_cb_t callback {reinterpret_cast<select_certificate_cb_t>(arg)};

//   SSL_CLIENT_HELLO client_hello;
//   memset(&client_hello, 0, sizeof(client_hello));

//   client_hello.ssl = ssl;
//   client_hello.version = ossl.ossl_SSL_client_hello_get0_legacy_version(ssl);
//   client_hello.random_len = ossl.ossl_SSL_client_hello_get0_random(ssl, &client_hello.random);
//   client_hello.session_id_len = ossl.ossl_SSL_client_hello_get0_session_id(ssl, &client_hello.session_id);
//   client_hello.cipher_suites_len = ossl.ossl_SSL_client_hello_get0_ciphers(ssl, &client_hello.cipher_suites);
//   client_hello.compression_methods_len = ossl.ossl_SSL_client_hello_get0_compression_methods(ssl, &client_hello.compression_methods);

//   int *extension_ids;
//   size_t extension_ids_len;

//   if (!ossl.ossl_SSL_client_hello_get1_extensions_present(ssl, &extension_ids, &extension_ids_len)) {
//     *alert = SSL_AD_INTERNAL_ERROR;
//     return ossl_SSL_CLIENT_HELLO_ERROR;
//   }

//   CBB extensions;
//   CBB_init(&extensions, 1024);

//   for (size_t i = 0; i < extension_ids_len; i++) {
//     const unsigned char *extension_data;
//     size_t extension_len;

//     if (!ossl.ossl_SSL_client_hello_get0_ext(ssl, extension_ids[i], &extension_data, &extension_len) ||
//         !CBB_add_u16(&extensions, extension_ids[i]) ||
//         !CBB_add_u16(&extensions, extension_len) ||
//         !CBB_add_bytes(&extensions, extension_data, extension_len)) {
//       OPENSSL_free(extension_ids);
//       CBB_cleanup(&extensions);
//       *alert = SSL_AD_INTERNAL_ERROR;
//       return ossl_SSL_CLIENT_HELLO_ERROR;
//     }
//   }

//   OPENSSL_free(extension_ids);

//   if (!CBB_finish(&extensions, (uint8_t**)&client_hello.extensions, &client_hello.extensions_len)) {
//     CBB_cleanup(&extensions);
//     *alert = SSL_AD_INTERNAL_ERROR;
//     return ossl_SSL_CLIENT_HELLO_ERROR;
//   }

//   enum ssl_select_cert_result_t result;

//   {
//     ActiveSelectCertificateCb active(ssl);
//     result = callback(&client_hello);
//   }

//   OPENSSL_free((void*)client_hello.extensions);

//   switch (result) {
//     case ssl_select_cert_success: return ossl_SSL_CLIENT_HELLO_SUCCESS;
//     case ssl_select_cert_retry:   return ossl_SSL_CLIENT_HELLO_RETRY;
//     case ssl_select_cert_error:   return ossl_SSL_CLIENT_HELLO_ERROR;
//   };
// }

// extern "C" void SSL_CTX_set_select_certificate_cb(SSL_CTX *ctx, select_certificate_cb_t cb) {
//   bssl_compat_info("[+]call SSL_METHOD::ssl_ctx_client_hello_cb start!");
//   ossl.ossl_SSL_CTX_set_client_hello_cb(ctx, ssl_ctx_client_hello_cb, reinterpret_cast<void*>(cb));
// }
typedef enum ssl_select_cert_result_t (*select_certificate_cb_t)(const SSL_CLIENT_HELLO *);

class ActiveSelectCertificateCb {
public:
    ActiveSelectCertificateCb(SSL *ssl) : ssl_(ssl) {
        bssl_compat_info("[+]call SSL_METHOD::ssl_ctx_client_hello_cb1 - SSL_set_ex_data");
        if (ssl_) {  
            SSL_set_ex_data(ssl_, index(), this);
        }
    }
    ~ActiveSelectCertificateCb() {
        bssl_compat_info("[+]call SSL_METHOD::ssl_ctx_client_hello_cb2 - SSL_set_ex_data");
        if (ssl_) {  
            SSL_set_ex_data(ssl_, index(), nullptr);
        }
    }
    static int index() {
        bssl_compat_info("[+]call SSL_METHOD::ssl_ctx_client_hello_cb3 - SSL_get_ex_new_index");
        static int idx = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr,
                              +[](void *, void *ptr, CRYPTO_EX_DATA *, int, long, void*) {
                                if (ptr) ossl_OPENSSL_free(ptr);
                              });
        return idx;
    }
private:
    SSL *ssl_;
};

bool in_select_certificate_cb(const SSL *ssl) {
    bssl_compat_info("[+]call SSL_METHOD::ssl_ctx_client_hello_cb-SSL_get_ex_data");
    return ssl && SSL_get_ex_data(ssl, ActiveSelectCertificateCb::index()) != nullptr;
}

static int ssl_ctx_client_hello_cb(SSL *ssl, int *alert, void *arg) {
    bssl_compat_info("[+]call SSL_METHOD::ssl_ctx_client_hello_cb - ssl_ctx_client_hello_cb");
    if (!ssl || !arg) {
        if (alert) *alert = SSL_AD_INTERNAL_ERROR;
        return ossl_SSL_CLIENT_HELLO_ERROR;
    }

    select_certificate_cb_t callback = reinterpret_cast<select_certificate_cb_t>(arg);

    SSL_CLIENT_HELLO client_hello;
    memset(&client_hello, 0, sizeof(client_hello));

    client_hello.ssl = ssl;
    client_hello.version = ossl.ossl_SSL_client_hello_get0_legacy_version(ssl);
    client_hello.random_len = ossl.ossl_SSL_client_hello_get0_random(ssl, &client_hello.random);
    client_hello.session_id_len = ossl.ossl_SSL_client_hello_get0_session_id(ssl, &client_hello.session_id);
    client_hello.cipher_suites_len = ossl.ossl_SSL_client_hello_get0_ciphers(ssl, &client_hello.cipher_suites);
    client_hello.compression_methods_len = 
        ossl.ossl_SSL_client_hello_get0_compression_methods(ssl, &client_hello.compression_methods);

    
    client_hello.extensions = nullptr;
    client_hello.extensions_len = 0;

    int *extension_ids = nullptr;
    size_t extension_ids_len = 0;

    if (ossl.ossl_SSL_client_hello_get1_extensions_present(ssl, &extension_ids, &extension_ids_len)) {
        CBB extensions;
        if (CBB_init(&extensions, 1024)) {
            bool success = true;
            for (size_t i = 0; i < extension_ids_len && success; i++) {
                const unsigned char *extension_data = nullptr;
                size_t extension_len = 0;

                success = ossl.ossl_SSL_client_hello_get0_ext(ssl, extension_ids[i], 
                    &extension_data, &extension_len) &&
                    CBB_add_u16(&extensions, extension_ids[i]) &&
                    CBB_add_u16(&extensions, extension_len) &&
                    CBB_add_bytes(&extensions, extension_data, extension_len);
            }

            if (success && CBB_finish(&extensions, 
                (uint8_t**)&client_hello.extensions, &client_hello.extensions_len)) {
                
            } else {
                CBB_cleanup(&extensions);
            }
        }
        OPENSSL_free(extension_ids);
    }

    enum ssl_select_cert_result_t result;
    {
        ActiveSelectCertificateCb active(ssl);
        result = callback(&client_hello);
    }

    if (client_hello.extensions) {
        OPENSSL_free((void*)client_hello.extensions);
    }

    switch (result) {
        case ssl_select_cert_success: return ossl_SSL_CLIENT_HELLO_SUCCESS;
        case ssl_select_cert_retry:   return ossl_SSL_CLIENT_HELLO_RETRY;
        default:
            if (alert) *alert = SSL_AD_INTERNAL_ERROR;
            return ossl_SSL_CLIENT_HELLO_ERROR;
    }
}

extern "C" void SSL_CTX_set_select_certificate_cb(SSL_CTX *ctx, select_certificate_cb_t cb) {
    bssl_compat_info("[+]SSL_CTX_set_select_certificate_cb - start");
    
    if (!ctx || !cb) {
        bssl_compat_info("[-]SSL_CTX_set_select_certificate_cb - null parameters");
        return;
    }


    void* app_data = SSL_CTX_get_app_data(ctx);
    bssl_compat_info("[+]SSL_CTX_set_select_certificate_cb - current app_data: %p", app_data);


    long options = SSL_CTX_get_options(ctx);
    bssl_compat_info("[+]SSL_CTX_set_select_certificate_cb - SSL_CTX options: %ld", options);

    bssl_compat_info("[+]SSL_CTX_set_select_certificate_cb - setting callback");
    ossl.ossl_SSL_CTX_set_client_hello_cb(ctx, ssl_ctx_client_hello_cb, reinterpret_cast<void*>(cb));
    

    app_data = SSL_CTX_get_app_data(ctx);
    bssl_compat_info("[+]SSL_CTX_set_select_certificate_cb - app_data after callback set: %p", app_data);
    
    bssl_compat_info("[+]SSL_CTX_set_select_certificate_cb - complete");
}

// extern "C" void SSL_CTX_set_select_certificate_cb(SSL_CTX *ctx, select_certificate_cb_t cb) {
//     bssl_compat_info("[+]call SSL_METHOD::ssl_ctx_client_hello_cb start!");
//     if (ctx && cb) {  
//         ossl.ossl_SSL_CTX_set_client_hello_cb(ctx, ssl_ctx_client_hello_cb, 
//             reinterpret_cast<void*>(cb));
//     }
// }