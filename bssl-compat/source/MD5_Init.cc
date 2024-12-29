#include <openssl/md5.h>
#include <string.h>
#include <ossl.h>

typedef struct {
    uint32_t state[4];
    uint64_t count;
    unsigned char buffer[64];
} MD5_CTX;

extern "C" int MD5_Init(MD5_CTX *md5) {
    if (md5 == NULL) {
        return 0;
    }

    md5->state[0] = 0x67452301;
    md5->state[1] = 0xefcdab89;
    md5->state[2] = 0x98badcfe;
    md5->state[3] = 0x10325476;
    
    md5->count = 0;
    
    memset(md5->buffer, 0, sizeof(md5->buffer));
    
    return 1;
}