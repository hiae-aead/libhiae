#ifndef HIAET_INTERNAL_H
#define HIAET_INTERNAL_H

#include "HiAEt.h"
#include <string.h>

/* Implementation function table */
typedef struct {
    const char *name;
    void (*init)(HiAEt_state_t *state, const uint8_t *key, const uint8_t *nonce);
    void (*absorb)(HiAEt_state_t *state, const uint8_t *ad, size_t len);
    void (*finalize)(HiAEt_state_t *state, uint64_t ad_len, uint64_t msg_len, uint8_t *tag);
    void (*enc)(HiAEt_state_t *state, uint8_t *ci, const uint8_t *mi, size_t size);
    void (*dec)(HiAEt_state_t *state, uint8_t *mi, const uint8_t *ci, size_t size);
    void (*enc_partial_noupdate)(HiAEt_state_t *state, uint8_t *ci, const uint8_t *mi, size_t size);
    void (*dec_partial_noupdate)(HiAEt_state_t *state, uint8_t *mi, const uint8_t *ci, size_t size);
    int (*encrypt)(const uint8_t *key, const uint8_t *nonce, const uint8_t *msg, uint8_t *ct,
                   size_t msg_len, const uint8_t *ad, size_t ad_len, uint8_t *tag);
    int (*decrypt)(const uint8_t *key, const uint8_t *nonce, uint8_t *msg, const uint8_t *ct,
                   size_t ct_len, const uint8_t *ad, size_t ad_len, const uint8_t *tag);
    int (*mac)(const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len,
               uint8_t *tag);
} HiAEt_impl_t;

/* Cryptographic parameter sizes */
#define HIAET_KEYBYTES   32 /* 256-bit key */
#define HIAET_NONCEBYTES 16 /* 128-bit nonce */
#define HIAET_MACBYTES   16 /* 128-bit authentication tag */

/* Internal constants */
#define P_0 0
#define P_1 1
#define P_4 13
#define P_7 9
#define I_1 3
#define I_2 13

#define UNROLL_BLOCK_SIZE 256
#define BLOCK_SIZE        16
#define STATE             16

/* Implementation forcing macros - define at compile time to force specific implementation */
#ifdef HIAET_FORCE_SOFTWARE
#    define HIAET_FORCED_IMPL "Software"
#endif

/* Internal constant arrays */
static const uint8_t C0[BLOCK_SIZE] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                                        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
static const uint8_t C1[BLOCK_SIZE] = { 0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d,
                                        0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8 };

/* Internal helper functions */
static inline int
hiaet_constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len)
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

#endif /* HIAET_INTERNAL_H */