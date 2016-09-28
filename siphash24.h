#ifndef siphash24_h_
#define siphash24_h_

#define SIPHASH_MAXLEN 64
#define SIPHASH_KEYLEN 16
#define SIPHASH_HASHLEN 8

int siphash(uint8_t *out, const uint8_t *in, uint64_t inlen, const uint8_t *k);

#endif 
