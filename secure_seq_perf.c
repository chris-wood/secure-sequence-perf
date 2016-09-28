#include <stdio.h>
#include <stdint.h>

#include <sys/time.h>
#include <time.h>

#include "cryptohash.h"
#include "siphash24.h"

// http://crypto.stackexchange.com/questions/13303/is-md5-second-preimage-resistant-when-used-only-on-fixed-length-messages
// https://131002.net/siphash/
// http://cr.yp.to/siphash/siphash-20120620.pdf
// http://lxr.linux.no/linux+v4.7.5/net/core/secure_seq.c

// The statically allocated and once-initialized net secret
uint32_t net_secret[16];

static uint32_t get_real_time_ns()
{
    return 0; // we can't get the current time without a context switch, so always return 0
}

static uint32_t seq_scale(uint32_t seq)
{
    return seq + (get_real_time_ns() >> 6);
}

// Adapted from /net/core/secure_seq.c
uint32_t secure_sequence_number_md5(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport)
{
    uint32_t hash[MD5_DIGEST_WORDS];

    // Per the linux implementation, this function seeds a net_secret once, 
    // so we may omit it to amortize the overhead in the long run.
    // net_secret_init(); 
    hash[0] = saddr;
    hash[1] = daddr;
    hash[2] = (((uint32_t ) sport) << 16) + ((uint32_t) dport);
    hash[3] = net_secret[15];

    md5_transform(hash, net_secret);

    return seq_scale(hash[0]);
}

uint32_t secure_sequence_number_siphash(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport)
{
    uint32_t secret = net_secret[15];
    uint8_t out[SIPHASH_HASHLEN]; 
    uint8_t in[16];
    in[0] = saddr >> 24;
    in[1] = saddr >> 16;
    in[2] = saddr >> 8;
    in[3] = saddr & 0xFF;
    in[4] = daddr >> 24;
    in[5] = daddr >> 16;
    in[6] = daddr >> 8;
    in[7] = daddr & 0xFF;
    in[8] = sport >> 8;
    in[9] = sport & 0xFF;
    in[10] = dport >> 8;
    in[11] = dport & 0xFF;
    in[12] = secret >> 24;;
    in[13] = secret >> 16;
    in[14] = secret >> 8;
    in[15] = secret & 0xFF;

    siphash(out, in, 16, (uint8_t *) net_secret);
    
    uint32_t random_word = in[0] << 24;
    random_word |= in[1] << 16;
    random_word |= in[2] << 8;
    random_word |= in[3];

    return seq_scale(random_word);
}

typedef uint32_t (*PRF)(uint32_t, uint32_t, uint16_t, uint16_t);

uint64_t 
time_it(PRF func, uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport)
{
    struct timeval start;
    struct timeval end; 
    struct timeval delta;
    gettimeofday(&start, NULL);
     
    // time it   
    uint32_t random_seq = func(saddr, daddr, sport, dport);

    gettimeofday(&end, NULL); \
    timersub(&end, &start, &delta); \
    return (delta.tv_sec * 1000000L) + delta.tv_usec;
}

#define NUM_TRIALS 1000

int 
main(int argc, char *argv[argc])
{
    // initialize net_secret with random bytes
    // XXX

    uint64_t md5Times[NUM_TRIALS];
    uint64_t totalMD5Time = 0L;
    uint64_t siphashTimes[NUM_TRIALS];
    uint64_t totalSiphashTime = 0L;
    
    // profile both functions
    for (int i = 0; i < NUM_TRIALS; i++) {
        uint64_t t1 = time_it(secure_sequence_number_md5, 1, 2, 3, 4);
        md5Times[i] = t1;
        totalMD5Time += t1;

        uint64_t t2 = time_it(secure_sequence_number_siphash, 1, 2, 3, 4);
        siphashTimes[i] = t2;
        totalSiphashTime += t2;
    }

    double md5Average = ((double) totalMD5Time) / NUM_TRIALS;
    double siphashAverage = ((double) totalSiphashTime) / NUM_TRIALS;

    printf("MD5:     %f\n", md5Average);
    printf("SipHash: %f\n", siphashAverage);

    return 0;
}
