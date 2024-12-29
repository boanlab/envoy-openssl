#include <openssl/bn.h>
#include <ossl.h>
#include <string.h>

#define OPENSSL_free free

extern "C" int BN_bn2bin(const BIGNUM *a, unsigned char *to) {
   if (!a || !to) {
       return 0;
   }

   char *hex_str = ossl.ossl_BN_bn2hex(a);
   if (!hex_str) {
       return 0;
   }

   int hex_len = strlen(hex_str);
   int num_bytes = (hex_len + 1) / 2;

   for (int i = 0; i < num_bytes; i++) {
       unsigned int byte_val;
       char hex_byte[3] = {0};
       
       size_t hex_index = hex_len - 2 * (i + 1);
       if (hex_index < hex_len) {
           hex_byte[0] = hex_len > hex_index + 1 ? hex_str[hex_index] : '0';
           hex_byte[1] = hex_len > hex_index + 1 ? hex_str[hex_index + 1] : hex_str[hex_index];
           sscanf(hex_byte, "%x", &byte_val);
           to[num_bytes - 1 - i] = byte_val & 0xFF;
       }
   }

   OPENSSL_free(hex_str);
   return num_bytes;
}