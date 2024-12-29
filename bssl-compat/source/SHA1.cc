#include <openssl/sha.h>
#include <ossl.h>
#include <string.h>
#include <stdint.h>

typedef struct {
   uint32_t state[5];
   uint64_t count;
   unsigned char buffer[64];
} SHA_CTX;

extern "C" int SHA1_Init(SHA_CTX *c) {
   if (!c) return 0;

   c->state[0] = 0x67452301;
   c->state[1] = 0xefcdab89;
   c->state[2] = 0x98badcfe;
   c->state[3] = 0x10325476;
   c->state[4] = 0xc3d2e1f0;

   c->count = 0;
   memset(c->buffer, 0, sizeof(c->buffer));

   return 1;
}

extern "C" void SHA1_Transform(SHA_CTX *c, const unsigned char *data) {
   uint32_t a, b, c_local, d, e;
   uint32_t X[16];

   for (int i = 0; i < 16; i++) {
       X[i] = ((uint32_t)data[i*4] << 24) |
              ((uint32_t)data[i*4+1] << 16) |
              ((uint32_t)data[i*4+2] << 8) |
              ((uint32_t)data[i*4+3]);
   }

   #define K1 0x5A827999
   #define K2 0x6ED9EBA1
   #define K3 0x8F1BBCDC
   #define K4 0xCA62C1D6

   #define F1(b,c,d) (((c) ^ (d)) & (b) ^ (d))
   #define F2(b,c,d) ((b) ^ (c) ^ (d))
   #define F3(b,c,d) (((b) & (c)) | ((d) & ((b) | (c))))
   #define F4(b,c,d) ((b) ^ (c) ^ (d))

   #define ROTATE(x,s) (((x) << (s)) | ((x) >> (32 - (s))))

   a = c->state[0];
   b = c->state[1];
   c_local = c->state[2];
   d = c->state[3];
   e = c->state[4];

   #define R1(a,b,c,d,e,w) \
       e += ROTATE(a,5) + F1(b,c,d) + w + K1; \
       b = ROTATE(b,30);

   #define R2(a,b,c,d,e,w) \
       e += ROTATE(a,5) + F2(b,c,d) + w + K2; \
       b = ROTATE(b,30);

   #define R3(a,b,c,d,e,w) \
       e += ROTATE(a,5) + F3(b,c,d) + w + K3; \
       b = ROTATE(b,30);

   #define R4(a,b,c,d,e,w) \
       e += ROTATE(a,5) + F4(b,c,d) + w + K4; \
       b = ROTATE(b,30);

   uint32_t W[80];
   for (int i = 0; i < 16; i++) {
       W[i] = X[i];
   }
   for (int i = 16; i < 80; i++) {
       W[i] = ROTATE(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
   }

   R1(a,b,c_local,d,e,W[ 0]); R1(e,a,b,c_local,d,W[ 1]); R1(d,e,a,b,c_local,W[ 2]); R1(c_local,d,e,a,b,W[ 3]);
   R1(b,c_local,d,e,a,W[ 4]); R1(a,b,c_local,d,e,W[ 5]); R1(e,a,b,c_local,d,W[ 6]); R1(d,e,a,b,c_local,W[ 7]);
   R1(c_local,d,e,a,b,W[ 8]); R1(b,c_local,d,e,a,W[ 9]); R1(a,b,c_local,d,e,W[10]); R1(e,a,b,c_local,d,W[11]);
   R1(d,e,a,b,c_local,W[12]); R1(c_local,d,e,a,b,W[13]); R1(b,c_local,d,e,a,W[14]); R1(a,b,c_local,d,e,W[15]);

   R2(e,a,b,c_local,d,W[16]); R2(d,e,a,b,c_local,W[17]); R2(c_local,d,e,a,b,W[18]); R2(b,c_local,d,e,a,W[19]);
   R2(a,b,c_local,d,e,W[20]); R2(e,a,b,c_local,d,W[21]); R2(d,e,a,b,c_local,W[22]); R2(c_local,d,e,a,b,W[23]);
   R2(b,c_local,d,e,a,W[24]); R2(a,b,c_local,d,e,W[25]); R2(e,a,b,c_local,d,W[26]); R2(d,e,a,b,c_local,W[27]);
   R2(c_local,d,e,a,b,W[28]); R2(b,c_local,d,e,a,W[29]); R2(a,b,c_local,d,e,W[30]); R2(e,a,b,c_local,d,W[31]);

   R3(d,e,a,b,c_local,W[32]); R3(c_local,d,e,a,b,W[33]); R3(b,c_local,d,e,a,W[34]); R3(a,b,c_local,d,e,W[35]);
   R3(e,a,b,c_local,d,W[36]); R3(d,e,a,b,c_local,W[37]); R3(c_local,d,e,a,b,W[38]); R3(b,c_local,d,e,a,W[39]);

   R4(a,b,c_local,d,e,W[40]); R4(e,a,b,c_local,d,W[41]); R4(d,e,a,b,c_local,W[42]); R4(c_local,d,e,a,b,W[43]);
   R4(b,c_local,d,e,a,W[44]); R4(a,b,c_local,d,e,W[45]); R4(e,a,b,c_local,d,W[46]); R4(d,e,a,b,c_local,W[47]);
   R4(c_local,d,e,a,b,W[48]); R4(b,c_local,d,e,a,W[49]); R4(a,b,c_local,d,e,W[50]); R4(e,a,b,c_local,d,W[51]);
   R4(d,e,a,b,c_local,W[52]); R4(c_local,d,e,a,b,W[53]); R4(b,c_local,d,e,a,W[54]); R4(a,b,c_local,d,e,W[55]);
   R4(e,a,b,c_local,d,W[56]); R4(d,e,a,b,c_local,W[57]); R4(c_local,d,e,a,b,W[58]); R4(b,c_local,d,e,a,W[59]);
   R4(a,b,c_local,d,e,W[60]); R4(e,a,b,c_local,d,W[61]); R4(d,e,a,b,c_local,W[62]); R4(c_local,d,e,a,b,W[63]);
   R4(b,c_local,d,e,a,W[64]); R4(a,b,c_local,d,e,W[65]); R4(e,a,b,c_local,d,W[66]); R4(d,e,a,b,c_local,W[67]);
   R4(c_local,d,e,a,b,W[68]); R4(b,c_local,d,e,a,W[69]); R4(a,b,c_local,d,e,W[70]); R4(e,a,b,c_local,d,W[71]);
   R4(d,e,a,b,c_local,W[72]); R4(c_local,d,e,a,b,W[73]); R4(b,c_local,d,e,a,W[74]); R4(a,b,c_local,d,e,W[75]);
   R4(e,a,b,c_local,d,W[76]); R4(d,e,a,b,c_local,W[77]); R4(c_local,d,e,a,b,W[78]); R4(b,c_local,d,e,a,W[79]);

   c->state[0] += a;
   c->state[1] += b;
   c->state[2] += c_local;
   c->state[3] += d;
   c->state[4] += e;
}

extern "C" int SHA1_Update_internal(SHA_CTX *ctx, const void *data, size_t len) {
   if (!ctx || !data) return 0;

   const unsigned char *input = (const unsigned char *)data;
   unsigned int have = (unsigned int)((ctx->count) & 0x3f);
   unsigned int need = 64 - have;

   ctx->count += len;

   if (len >= need) {
       memcpy(&ctx->buffer[have], input, need);
       SHA1_Transform(ctx, ctx->buffer);
       input += need;
       len -= need;
       have = 0;

       while (len >= 64) {
           SHA1_Transform(ctx, input);
           input += 64;
           len -= 64;
       }
   }

   if (len > 0) {
       memcpy(&ctx->buffer[have], input, len);
   }

   return 1;
}

extern "C" int SHA1_Update(SHA_CTX *ctx, const void *data, size_t len) {
   return SHA1_Update_internal(ctx, data, len);
}

extern "C" int SHA1_Final(unsigned char *md, SHA_CTX *ctx) {
   if (!md || !ctx) return 0;

   unsigned int have = (unsigned int)((ctx->count) & 0x3f);
   ctx->buffer[have++] = 0x80;

   unsigned char *p = ctx->buffer + have;
   if (have > 56) {
       memset(p, 0, 64 - have);
       SHA1_Transform(ctx, ctx->buffer);
       have = 0;
       p = ctx->buffer;
   }

   memset(p, 0, 56 - have);

   ctx->count *= 8;
   *(uint64_t *)(ctx->buffer + 56) = __builtin_bswap64(ctx->count);

   SHA1_Transform(ctx, ctx->buffer);

   for (int i = 0; i < 5; i++) {
       md[i*4]   = (ctx->state[i] >> 24) & 0xFF;
       md[i*4+1] = (ctx->state[i] >> 16) & 0xFF;
       md[i*4+2] = (ctx->state[i] >> 8) & 0xFF;
       md[i*4+3] = ctx->state[i] & 0xFF;
   }

   return 1;
}