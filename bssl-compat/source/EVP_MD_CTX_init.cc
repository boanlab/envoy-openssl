#include <openssl/digest.h>
#include <ossl.h>
#include <malloc.h>
#include "log.h"

#define EVP_MD_CTX_SIZE 80

// int print_ctx_info() {
//     EVP_MD_CTX* ctx = EVP_MD_CTX_new();
//     if (ctx) {
//         bssl_compat_info("Allocated EVP_MD_CTX size: %zu bytes\n", 
//                malloc_usable_size(ctx));  // malloc_usable_size는 glibc 확장
//         EVP_MD_CTX_free(ctx);
//     }
// }

extern "C" void EVP_MD_CTX_init(EVP_MD_CTX *ctx) {
    //print_ctx_info();
    //bssl_compat_info("[+]SSL_METHOS::EVP_MD_CTX_init() implemented other functions..");
    memset(ctx, 0, EVP_MD_CTX_SIZE);
}