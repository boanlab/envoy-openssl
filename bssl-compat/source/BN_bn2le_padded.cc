#include <openssl/bn.h>
#include <string.h>

#define OPENSSL_free free

static unsigned BN_num_bytes(const BIGNUM *bn) {
    return (BN_num_bits(bn) + 7) / 8;
}


extern "C" int BN_bn2le_padded(uint8_t *out, size_t len, const BIGNUM *bn) {
    size_t num_bytes = BN_num_bytes(bn);
    
    if (num_bytes > len) {
        return 0;
    }
    
    memset(out, 0, len);
    
    if (num_bytes > 0) {
        char* hex_str = BN_bn2hex(bn);
        if (!hex_str) {
            return 0;
        }
        
        size_t hex_len = strlen(hex_str);
        
        for (size_t i = 0; i < num_bytes; i++) {
            unsigned int byte_val;
            char hex_byte[3] = {0};
            
            size_t hex_index = hex_len - 2 * (i + 1);
            if (hex_index < hex_len) {
                hex_byte[0] = hex_str[hex_index];
                hex_byte[1] = hex_str[hex_index + 1];
                sscanf(hex_byte, "%x", &byte_val);
                out[i] = byte_val & 0xFF;
            }
        }
        
        OPENSSL_free(hex_str);
    }
    
    return 1;
}