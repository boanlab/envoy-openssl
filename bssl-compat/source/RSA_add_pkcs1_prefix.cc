// bssl-compat/source/RSA_add_pkcs1_prefix.cc

#include <openssl/base.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <cassert>

// MD5+SHA1 combined digest length (standard for SSL)
#define SSL_SIG_LENGTH 36

// Define error codes if not already defined
#define RSA_R_TOO_LONG 100
#define RSA_R_UNKNOWN_ALGORITHM_TYPE 101

// 메모리 관리 함수 대체
#define OPENSSL_malloc malloc
#define OPENSSL_memcpy memcpy

// OpenSSL 호환성을 위한 에러 매크로
#define OPENSSL_PUT_ERROR(type, reason) \
    do { /* 에러 로깅 또는 처리 */ } while(0)

// Define the structure for PKCS1 signature prefixes
struct pkcs1_sig_prefix {
    int nid;
    const uint8_t *bytes;
    size_t len;
    size_t hash_len;
};

// Predefined PKCS1 signature prefixes 
static const struct pkcs1_sig_prefix kPKCS1SigPrefixes[] = {
    // SHA-1 prefix
    {NID_sha1, 
     (const uint8_t *)"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14", 
     15, 20},
    
    // SHA-224 prefix
    {NID_sha224, 
     (const uint8_t *)"\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c", 
     19, 28},
    
    // SHA-256 prefix
    {NID_sha256, 
     (const uint8_t *)"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20", 
     19, 32},
    
    // SHA-384 prefix
    {NID_sha384, 
     (const uint8_t *)"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30", 
     19, 48},
    
    // SHA-512 prefix
    {NID_sha512, 
     (const uint8_t *)"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40", 
     19, 64},
    
    // Terminator
    {NID_undef, NULL, 0, 0}
};

// Helper function to check if digest size matches expected size for a hash algorithm
static int rsa_check_digest_size(int hash_nid, size_t digest_len) {
    for (size_t i = 0; kPKCS1SigPrefixes[i].nid != NID_undef; i++) {
        if (kPKCS1SigPrefixes[i].nid == hash_nid) {
            return digest_len == kPKCS1SigPrefixes[i].hash_len;
        }
    }
    return 0;
}

int RSA_add_pkcs1_prefix(uint8_t **out_msg, size_t *out_msg_len,
                         int *is_alloced, int hash_nid, const uint8_t *digest,
                         size_t digest_len) {
    if (!rsa_check_digest_size(hash_nid, digest_len)) {
        return 0;
    }

    if (hash_nid == NID_md5_sha1) {
        // The length should already have been checked.
        assert(digest_len == SSL_SIG_LENGTH);
        *out_msg = (uint8_t *)digest;
        *out_msg_len = digest_len;
        *is_alloced = 0;
        return 1;
    }

    for (size_t i = 0; kPKCS1SigPrefixes[i].nid != NID_undef; i++) {
        const struct pkcs1_sig_prefix *sig_prefix = &kPKCS1SigPrefixes[i];
        if (sig_prefix->nid != hash_nid) {
            continue;
        }
        // The length should already have been checked.
        assert(digest_len == sig_prefix->hash_len);
        const uint8_t *prefix = sig_prefix->bytes;
        size_t prefix_len = sig_prefix->len;
        size_t signed_msg_len = prefix_len + digest_len;

        if (signed_msg_len < prefix_len) {
            OPENSSL_PUT_ERROR(RSA, RSA_R_TOO_LONG);
            return 0;
        }

        uint8_t *signed_msg = reinterpret_cast<uint8_t *>(OPENSSL_malloc(signed_msg_len));
        if (!signed_msg) {
            return 0;
        }

        OPENSSL_memcpy(signed_msg, prefix, prefix_len);
        OPENSSL_memcpy(signed_msg + prefix_len, digest, digest_len);
        *out_msg = signed_msg;
        *out_msg_len = signed_msg_len;
        *is_alloced = 1;
        return 1;
    }

    OPENSSL_PUT_ERROR(RSA, RSA_R_UNKNOWN_ALGORITHM_TYPE);
    return 0;
}