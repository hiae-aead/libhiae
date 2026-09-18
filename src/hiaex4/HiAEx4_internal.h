#ifndef HiAEx4_INTERNAL_H
#define HiAEx4_INTERNAL_H

#include "../common/common.h"
#include "../common/cpu.h"
#include "HiAEx4.h"
#include <string.h>

/* Implementation function table */
typedef struct {
    const char *name;
    void (*init)(HiAEx4_state_t *state, const uint8_t *key, const uint8_t *nonce);
    void (*absorb)(HiAEx4_state_t *state, const uint8_t *ad, size_t len);
    void (*finalize)(HiAEx4_state_t *state, uint64_t ad_len, uint64_t msg_len, uint8_t *tag);
    void (*finalize_mac)(HiAEx4_state_t *state, uint64_t data_len, uint8_t *tag);
    void (*enc)(HiAEx4_state_t *state, uint8_t *ci, const uint8_t *mi, size_t size);
    void (*dec)(HiAEx4_state_t *state, uint8_t *mi, const uint8_t *ci, size_t size);
    void (*enc_partial_noupdate)(HiAEx4_state_t *state, uint8_t *ci, const uint8_t *mi,
                                 size_t size);
    void (*dec_partial_noupdate)(HiAEx4_state_t *state, uint8_t *mi, const uint8_t *ci,
                                 size_t size);
    int (*encrypt)(const uint8_t *key, const uint8_t *nonce, const uint8_t *msg, uint8_t *ct,
                   size_t msg_len, const uint8_t *ad, size_t ad_len, uint8_t *tag);
    int (*decrypt)(const uint8_t *key, const uint8_t *nonce, uint8_t *msg, const uint8_t *ct,
                   size_t ct_len, const uint8_t *ad, size_t ad_len, const uint8_t *tag);
    int (*mac)(const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len,
               uint8_t *tag);
} HiAEx4_impl_t;

/* Cryptographic parameter sizes */
#define HIAEX4_KEYBYTES   32 /* 256-bit key */
#define HIAEX4_NONCEBYTES 16 /* 128-bit nonce */
#define HIAEX4_MACBYTES   16 /* 128-bit authentication tag */

/* Internal constants */
#define P_0 0
#define P_1 1
#define P_4 13
#define P_7 9
#define I_1 3
#define I_2 13

#define UNROLL_BLOCK_SIZE (4 * 256)
#define BLOCK_SIZE        (4 * 16)
#define STATE             16

/* Implementation forcing macros - define at compile time to force specific implementation */
#ifdef HIAEX4_FORCE_SOFTWARE
#    define HIAEX4_FORCED_IMPL "Software"
#endif
#ifdef HIAEX4_FORCE_VAES_AVX4
#    define HIAEX4_FORCED_IMPL "VAES-AVX4"
#endif
#ifdef HIAEX4_FORCE_ARM
#    define HIAEX4_FORCED_IMPL "ARM NEON"
#endif
#ifdef HIAEX4_FORCE_ARM_SHA3
#    define HIAEX4_FORCED_IMPL "ARM SHA3"
#endif

/* Internal constant arrays */
static const uint8_t C0[BLOCK_SIZE] = { HIAE_C0_BYTES, HIAE_C0_BYTES, HIAE_C0_BYTES,
                                        HIAE_C0_BYTES };
static const uint8_t C1[BLOCK_SIZE] = { HIAE_C1_BYTES, HIAE_C1_BYTES, HIAE_C1_BYTES,
                                        HIAE_C1_BYTES };

/* Internal helper functions */
static inline int
hiaex4_constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(result) :);
#endif
    return -(result != 0);
}

#endif /* HiAEx4_INTERNAL_H */
