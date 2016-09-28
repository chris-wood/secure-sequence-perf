#ifndef __CRYPTOHASH_H
#define __CRYPTOHASH_H

#include <stdint.h>

#define MD5_DIGEST_WORDS 4
#define MD5_MESSAGE_BYTES 64

// Modified from /include/cryptohash.h
void md5_transform(uint32_t *hash, uint32_t const *in);

#endif
