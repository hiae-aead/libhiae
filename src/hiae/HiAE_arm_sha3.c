#include "HiAE.h"
#include "HiAE_internal.h"

#if defined(__aarch64__) || defined(_M_ARM64)

#    ifndef __ARM_FEATURE_CRYPTO
#        define __ARM_FEATURE_CRYPTO 1
#    endif
#    ifndef __ARM_FEATURE_AES
#        define __ARM_FEATURE_AES 1
#    endif
#    ifndef __ARM_FEATURE_SHA3
#        define __ARM_FEATURE_SHA3 1
#    endif

#    include <arm_neon.h>

#    ifdef __clang__
#        pragma clang attribute push(__attribute__((target("neon,crypto,aes,sha3"))), \
                                     apply_to = function)
#    elif defined(__GNUC__)
#        pragma GCC target("+simd+crypto+sha3")
#    endif

// Prefetch macros - tuned for ARM64
// locality: 0 = no temporal locality (streaming), 3 = high temporal locality
#    ifdef _MSC_VER
// MSVC doesn't have __builtin_prefetch, use ARM64 specific intrinsics
#        include <intrin.h>
#        define PREFETCH_READ(addr, locality)  __prefetch((const void *) (addr))
#        define PREFETCH_WRITE(addr, locality) __prefetch((const void *) (addr))
#    else
#        define PREFETCH_READ(addr, locality)  __builtin_prefetch((addr), 0, (locality))
#        define PREFETCH_WRITE(addr, locality) __builtin_prefetch((addr), 1, (locality))
#    endif

// Prefetch distance in bytes - tuned for typical ARM64 cache line size (64-128 bytes)
#    define PREFETCH_DISTANCE 128

typedef uint8x16_t DATA128b;

#    define SIMD_LOAD(x)       vld1q_u8(x)
#    define SIMD_STORE(dst, x) vst1q_u8(dst, x)
#    define SIMD_XOR(a, b)     veorq_u8(a, b)
#    define SIMD_AND(a, b)     vandq_u8(a, b)
#    define SIMD_XOR3(a, b, c) veor3q_u8(a, b, c)
#    define SIMD_ZERO_128()    vmovq_n_u8(0)
#    define XAESL(x, y)        vaesmcq_u8(vaeseq_u8(x, y))
#    define AESL(x)            XAESL(x, SIMD_ZERO_128())

static inline void
update_state_offset(DATA128b *state, DATA128b *tmp, DATA128b M, int offset)
{
    tmp[offset] = XAESL(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    tmp[offset] = SIMD_XOR(tmp[offset], M);
    state[(0 + offset) % STATE]   = SIMD_XOR(tmp[offset], AESL(state[(P_4 + offset) % STATE]));
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], M);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], M);
}

static inline DATA128b
keystream_block(DATA128b *state, DATA128b M, int offset)
{
    DATA128b tmp = XAESL(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    M            = SIMD_XOR3(tmp, M, state[(P_7 + offset) % STATE]);
    return M;
}

static inline DATA128b
enc_offset(DATA128b *state, DATA128b M, int offset)
{
    DATA128b C = XAESL(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    C          = SIMD_XOR(C, M);
    state[(0 + offset) % STATE]   = SIMD_XOR(C, AESL(state[(P_4 + offset) % STATE]));
    C                             = SIMD_XOR(C, state[(P_7 + offset) % STATE]);
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], M);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], M);
    return C;
}

static inline DATA128b
dec_offset(DATA128b *state, DATA128b *tmp, DATA128b C, int offset)
{
    tmp[offset] = XAESL(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    DATA128b M  = SIMD_XOR(state[(P_7 + offset) % STATE], C);
    state[(0 + offset) % STATE]   = SIMD_XOR(M, AESL(state[(P_4 + offset) % STATE]));
    M                             = SIMD_XOR(M, tmp[offset]);
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], M);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], M);
    return M;
}

#    define LOAD_1BLOCK_offset_enc(M, offset)  (M) = SIMD_LOAD(mi + i + 0 + BLOCK_SIZE * offset);
#    define LOAD_1BLOCK_offset_dec(C, offset)  (C) = SIMD_LOAD(ci + i + 0 + BLOCK_SIZE * offset);
#    define LOAD_1BLOCK_offset_ad(M, offset)   (M) = SIMD_LOAD(ad + i + 0 + BLOCK_SIZE * offset);
#    define STORE_1BLOCK_offset_enc(C, offset) SIMD_STORE(ci + i + 0 + BLOCK_SIZE * offset, (C));
#    define STORE_1BLOCK_offset_dec(M, offset) SIMD_STORE(mi + i + 0 + BLOCK_SIZE * offset, (M));

static inline void
state_shift(DATA128b *state)
{
    DATA128b temp = state[0];
    state[0]      = state[1];
    state[1]      = state[2];
    state[2]      = state[3];
    state[3]      = state[4];
    state[4]      = state[5];
    state[5]      = state[6];
    state[6]      = state[7];
    state[7]      = state[8];
    state[8]      = state[9];
    state[9]      = state[10];
    state[10]     = state[11];
    state[11]     = state[12];
    state[12]     = state[13];
    state[13]     = state[14];
    state[14]     = state[15];
    state[15]     = temp;
}

static inline void
init_update(DATA128b *state, DATA128b *tmp, DATA128b c0)
{
    update_state_offset(state, tmp, c0, 0);
    update_state_offset(state, tmp, c0, 1);
    update_state_offset(state, tmp, c0, 2);
    update_state_offset(state, tmp, c0, 3);
    update_state_offset(state, tmp, c0, 4);
    update_state_offset(state, tmp, c0, 5);
    update_state_offset(state, tmp, c0, 6);
    update_state_offset(state, tmp, c0, 7);
    update_state_offset(state, tmp, c0, 8);
    update_state_offset(state, tmp, c0, 9);
    update_state_offset(state, tmp, c0, 10);
    update_state_offset(state, tmp, c0, 11);
    update_state_offset(state, tmp, c0, 12);
    update_state_offset(state, tmp, c0, 13);
    update_state_offset(state, tmp, c0, 14);
    update_state_offset(state, tmp, c0, 15);
}

static inline void
ad_update(DATA128b *state, DATA128b *tmp, const uint8_t *ad, size_t i)
{
    DATA128b M[16];

    PREFETCH_READ(ad + i + UNROLL_BLOCK_SIZE, 0);
    PREFETCH_READ(ad + i + UNROLL_BLOCK_SIZE + 128, 0);

    LOAD_1BLOCK_offset_ad(M[0], 0);
    LOAD_1BLOCK_offset_ad(M[1], 1);
    LOAD_1BLOCK_offset_ad(M[2], 2);
    LOAD_1BLOCK_offset_ad(M[3], 3);
    LOAD_1BLOCK_offset_ad(M[4], 4);
    LOAD_1BLOCK_offset_ad(M[5], 5);
    LOAD_1BLOCK_offset_ad(M[6], 6);
    LOAD_1BLOCK_offset_ad(M[7], 7);
    LOAD_1BLOCK_offset_ad(M[8], 8);
    LOAD_1BLOCK_offset_ad(M[9], 9);
    LOAD_1BLOCK_offset_ad(M[10], 10);
    LOAD_1BLOCK_offset_ad(M[11], 11);
    LOAD_1BLOCK_offset_ad(M[12], 12);
    LOAD_1BLOCK_offset_ad(M[13], 13);
    LOAD_1BLOCK_offset_ad(M[14], 14);
    LOAD_1BLOCK_offset_ad(M[15], 15);
    update_state_offset(state, tmp, M[0], 0);
    update_state_offset(state, tmp, M[1], 1);
    update_state_offset(state, tmp, M[2], 2);
    update_state_offset(state, tmp, M[3], 3);
    update_state_offset(state, tmp, M[4], 4);
    update_state_offset(state, tmp, M[5], 5);
    update_state_offset(state, tmp, M[6], 6);
    update_state_offset(state, tmp, M[7], 7);
    update_state_offset(state, tmp, M[8], 8);
    update_state_offset(state, tmp, M[9], 9);
    update_state_offset(state, tmp, M[10], 10);
    update_state_offset(state, tmp, M[11], 11);
    update_state_offset(state, tmp, M[12], 12);
    update_state_offset(state, tmp, M[13], 13);
    update_state_offset(state, tmp, M[14], 14);
    update_state_offset(state, tmp, M[15], 15);
}

static inline void
encrypt_chunk(DATA128b *state, const uint8_t *mi, uint8_t *ci, size_t i)
{
    DATA128b M[16], C[16];

    // Prefetch next chunk for reading
    PREFETCH_READ(mi + i + PREFETCH_DISTANCE, 0);
    // Prefetch for writing
    PREFETCH_WRITE(ci + i + PREFETCH_DISTANCE, 0);

    LOAD_1BLOCK_offset_enc(M[0], 0);
    LOAD_1BLOCK_offset_enc(M[1], 1);
    LOAD_1BLOCK_offset_enc(M[2], 2);
    LOAD_1BLOCK_offset_enc(M[3], 3);
    LOAD_1BLOCK_offset_enc(M[4], 4);
    LOAD_1BLOCK_offset_enc(M[5], 5);
    LOAD_1BLOCK_offset_enc(M[6], 6);
    LOAD_1BLOCK_offset_enc(M[7], 7);
    LOAD_1BLOCK_offset_enc(M[8], 8);
    LOAD_1BLOCK_offset_enc(M[9], 9);
    LOAD_1BLOCK_offset_enc(M[10], 10);
    LOAD_1BLOCK_offset_enc(M[11], 11);
    LOAD_1BLOCK_offset_enc(M[12], 12);
    LOAD_1BLOCK_offset_enc(M[13], 13);
    LOAD_1BLOCK_offset_enc(M[14], 14);
    LOAD_1BLOCK_offset_enc(M[15], 15);
    C[0]  = enc_offset(state, M[0], 0);
    C[1]  = enc_offset(state, M[1], 1);
    C[2]  = enc_offset(state, M[2], 2);
    C[3]  = enc_offset(state, M[3], 3);
    C[4]  = enc_offset(state, M[4], 4);
    C[5]  = enc_offset(state, M[5], 5);
    C[6]  = enc_offset(state, M[6], 6);
    C[7]  = enc_offset(state, M[7], 7);
    C[8]  = enc_offset(state, M[8], 8);
    C[9]  = enc_offset(state, M[9], 9);
    C[10] = enc_offset(state, M[10], 10);
    C[11] = enc_offset(state, M[11], 11);
    C[12] = enc_offset(state, M[12], 12);
    C[13] = enc_offset(state, M[13], 13);
    C[14] = enc_offset(state, M[14], 14);
    C[15] = enc_offset(state, M[15], 15);
    STORE_1BLOCK_offset_enc(C[0], 0);
    STORE_1BLOCK_offset_enc(C[1], 1);
    STORE_1BLOCK_offset_enc(C[2], 2);
    STORE_1BLOCK_offset_enc(C[3], 3);
    STORE_1BLOCK_offset_enc(C[4], 4);
    STORE_1BLOCK_offset_enc(C[5], 5);
    STORE_1BLOCK_offset_enc(C[6], 6);
    STORE_1BLOCK_offset_enc(C[7], 7);
    STORE_1BLOCK_offset_enc(C[8], 8);
    STORE_1BLOCK_offset_enc(C[9], 9);
    STORE_1BLOCK_offset_enc(C[10], 10);
    STORE_1BLOCK_offset_enc(C[11], 11);
    STORE_1BLOCK_offset_enc(C[12], 12);
    STORE_1BLOCK_offset_enc(C[13], 13);
    STORE_1BLOCK_offset_enc(C[14], 14);
    STORE_1BLOCK_offset_enc(C[15], 15);
}

static inline void
decrypt_chunk(DATA128b *state, DATA128b *tmp, const uint8_t *ci, uint8_t *mi, size_t i)
{
    DATA128b M[16], C[16];

    // Prefetch next chunk for reading
    PREFETCH_READ(ci + i + PREFETCH_DISTANCE, 0);
    // Prefetch for writing
    PREFETCH_WRITE(mi + i + PREFETCH_DISTANCE, 0);

    LOAD_1BLOCK_offset_dec(C[0], 0);
    LOAD_1BLOCK_offset_dec(C[1], 1);
    LOAD_1BLOCK_offset_dec(C[2], 2);
    LOAD_1BLOCK_offset_dec(C[3], 3);
    LOAD_1BLOCK_offset_dec(C[4], 4);
    LOAD_1BLOCK_offset_dec(C[5], 5);
    LOAD_1BLOCK_offset_dec(C[6], 6);
    LOAD_1BLOCK_offset_dec(C[7], 7);
    LOAD_1BLOCK_offset_dec(C[8], 8);
    LOAD_1BLOCK_offset_dec(C[9], 9);
    LOAD_1BLOCK_offset_dec(C[10], 10);
    LOAD_1BLOCK_offset_dec(C[11], 11);
    LOAD_1BLOCK_offset_dec(C[12], 12);
    LOAD_1BLOCK_offset_dec(C[13], 13);
    LOAD_1BLOCK_offset_dec(C[14], 14);
    LOAD_1BLOCK_offset_dec(C[15], 15);
    M[0]  = dec_offset(state, tmp, C[0], 0);
    M[1]  = dec_offset(state, tmp, C[1], 1);
    M[2]  = dec_offset(state, tmp, C[2], 2);
    M[3]  = dec_offset(state, tmp, C[3], 3);
    M[4]  = dec_offset(state, tmp, C[4], 4);
    M[5]  = dec_offset(state, tmp, C[5], 5);
    M[6]  = dec_offset(state, tmp, C[6], 6);
    M[7]  = dec_offset(state, tmp, C[7], 7);
    M[8]  = dec_offset(state, tmp, C[8], 8);
    M[9]  = dec_offset(state, tmp, C[9], 9);
    M[10] = dec_offset(state, tmp, C[10], 10);
    M[11] = dec_offset(state, tmp, C[11], 11);
    M[12] = dec_offset(state, tmp, C[12], 12);
    M[13] = dec_offset(state, tmp, C[13], 13);
    M[14] = dec_offset(state, tmp, C[14], 14);
    M[15] = dec_offset(state, tmp, C[15], 15);
    STORE_1BLOCK_offset_dec(M[0], 0);
    STORE_1BLOCK_offset_dec(M[1], 1);
    STORE_1BLOCK_offset_dec(M[2], 2);
    STORE_1BLOCK_offset_dec(M[3], 3);
    STORE_1BLOCK_offset_dec(M[4], 4);
    STORE_1BLOCK_offset_dec(M[5], 5);
    STORE_1BLOCK_offset_dec(M[6], 6);
    STORE_1BLOCK_offset_dec(M[7], 7);
    STORE_1BLOCK_offset_dec(M[8], 8);
    STORE_1BLOCK_offset_dec(M[9], 9);
    STORE_1BLOCK_offset_dec(M[10], 10);
    STORE_1BLOCK_offset_dec(M[11], 11);
    STORE_1BLOCK_offset_dec(M[12], 12);
    STORE_1BLOCK_offset_dec(M[13], 13);
    STORE_1BLOCK_offset_dec(M[14], 14);
    STORE_1BLOCK_offset_dec(M[15], 15);
}

static void
HiAE_init_arm_sha3(HiAE_state_t *state_opaque, const uint8_t *key, const uint8_t *nonce)
{
    DATA128b state[STATE];
    memset(&state, 0, sizeof state);
    DATA128b c0 = SIMD_LOAD(C0);
    DATA128b c1 = SIMD_LOAD(C1);
    DATA128b k0 = SIMD_LOAD(key);
    DATA128b k1 = SIMD_LOAD(key + 16);
    DATA128b N  = SIMD_LOAD(nonce);

    DATA128b ze = SIMD_ZERO_128();
    state[0]    = c0;
    state[1]    = k1;
    state[2]    = N;
    state[3]    = c0;
    state[4]    = ze;
    state[5]    = SIMD_XOR(N, k0);
    state[6]    = ze;
    state[7]    = c1;
    state[8]    = SIMD_XOR(N, k1);
    state[9]    = ze;
    state[10]   = k1;
    state[11]   = c0;
    state[12]   = c1;
    state[13]   = k1;
    state[14]   = ze;
    state[15]   = SIMD_XOR(c0, c1);

    DATA128b tmp[STATE];
    init_update(state, tmp, c0);
    init_update(state, tmp, c0);

    state[9]  = SIMD_XOR(state[9], k0);
    state[13] = SIMD_XOR(state[13], k1);
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAE_absorb_arm_sha3(HiAE_state_t *state_opaque, const uint8_t *ad, size_t len)
{
    DATA128b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t   i      = 0;
    size_t   rest   = len % UNROLL_BLOCK_SIZE;
    size_t   prefix = len - rest;
    DATA128b tmp[STATE], M[16];
    if (len == 0)
        return;

    for (; i < prefix; i += UNROLL_BLOCK_SIZE) {
        ad_update(state, tmp, ad, i);
    }

    size_t pad = len % BLOCK_SIZE;
    len -= pad;
    for (; i < len; i += BLOCK_SIZE) {
        M[0] = SIMD_LOAD(ad + i);
        update_state_offset(state, tmp, M[0], 0);
        state_shift(state);
    }
    if (pad != 0) {
        uint8_t buf[BLOCK_SIZE];
        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, ad + len, pad);
        M[0] = SIMD_LOAD(buf);
        update_state_offset(state, tmp, M[0], 0);
        state_shift(state);
    }
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAE_finalize_arm_sha3(HiAE_state_t *state_opaque, uint64_t ad_len, uint64_t msg_len, uint8_t *tag)
{
    DATA128b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    uint64_t lens[2];
    lens[0] = ad_len * 8;
    lens[1] = msg_len * 8;
    DATA128b temp, tmp[STATE];
    temp = SIMD_LOAD((uint8_t *) lens);
    init_update(state, tmp, temp);
    init_update(state, tmp, temp);

    // Use EOR3 to compute the final tag more efficiently
    // First, XOR groups of 3 states together
    DATA128b acc0 = SIMD_XOR3(state[0], state[1], state[2]);
    DATA128b acc1 = SIMD_XOR3(state[3], state[4], state[5]);
    DATA128b acc2 = SIMD_XOR3(state[6], state[7], state[8]);
    DATA128b acc3 = SIMD_XOR3(state[9], state[10], state[11]);
    DATA128b acc4 = SIMD_XOR3(state[12], state[13], state[14]);

    // Then combine the accumulators
    DATA128b acc_final = SIMD_XOR3(acc0, acc1, acc2);
    acc_final          = SIMD_XOR3(acc_final, acc3, acc4);
    acc_final          = SIMD_XOR(acc_final, state[15]);

    SIMD_STORE(tag, acc_final);
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAE_enc_arm_sha3(HiAE_state_t *state_opaque, uint8_t *ci, const uint8_t *mi, size_t size)
{
    DATA128b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t rest   = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    if (size == 0)
        return;
    DATA128b M[STATE], C[STATE];

    // Main processing loop with prefetching
    for (size_t i = 0; i < prefix; i += UNROLL_BLOCK_SIZE) {
        // Unconditional prefetch for next iteration
        PREFETCH_READ(mi + i + UNROLL_BLOCK_SIZE, 0);
        PREFETCH_WRITE(ci + i + UNROLL_BLOCK_SIZE, 0);
        encrypt_chunk(state, mi, ci, i);
    }

    size_t pad = rest % BLOCK_SIZE;
    rest -= pad;
    for (size_t i = 0; i < rest; i += BLOCK_SIZE) {
        M[0] = SIMD_LOAD(mi + i + prefix);
        C[0] = enc_offset(state, M[0], 0);
        state_shift(state);
        SIMD_STORE(ci + i + prefix, C[0]);
    }
    if (pad != 0) {
        uint8_t buf[BLOCK_SIZE];
        memcpy(buf, mi + rest + prefix, pad);
        memset(buf + pad, 0, BLOCK_SIZE - pad);
        M[0] = SIMD_LOAD(buf);
        C[0] = enc_offset(state, M[0], 0);
        state_shift(state);
        SIMD_STORE(buf, C[0]);
        memcpy(ci + rest + prefix, buf, pad);
    }
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAE_dec_arm_sha3(HiAE_state_t *state_opaque, uint8_t *mi, const uint8_t *ci, size_t size)
{
    DATA128b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t rest   = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    if (size == 0)
        return;
    DATA128b M[STATE], C[STATE], tmp[STATE];

    // Main processing loop with prefetching
    for (size_t i = 0; i < prefix; i += UNROLL_BLOCK_SIZE) {
        // Unconditional prefetch for next iteration
        PREFETCH_READ(ci + i + UNROLL_BLOCK_SIZE, 0);
        PREFETCH_WRITE(mi + i + UNROLL_BLOCK_SIZE, 0);
        decrypt_chunk(state, tmp, ci, mi, i);
    }

    size_t pad = rest % BLOCK_SIZE;
    rest -= pad;

    for (size_t i = 0; i < rest; i += BLOCK_SIZE) {
        C[0] = SIMD_LOAD(ci + i + prefix);
        M[0] = dec_offset(state, tmp, C[0], 0);
        state_shift(state);
        SIMD_STORE(mi + i + prefix, M[0]);
    }
    if (pad != 0) {
        uint8_t buf[BLOCK_SIZE];
        uint8_t mask[BLOCK_SIZE];
        memcpy(buf, ci + rest + prefix, pad);
        memset(mask, 0xff, pad);
        memset(mask + pad, 0x00, BLOCK_SIZE - pad);
        C[0] = SIMD_LOAD(buf);
        M[0] = SIMD_LOAD(mask);
        C[0] = keystream_block(state, C[0], 0);
        C[0] = SIMD_AND(C[0], M[0]);
        update_state_offset(state, tmp, C[0], 0);
        state_shift(state);
        SIMD_STORE(buf, C[0]);
        memcpy(mi + rest + prefix, buf, pad);
    }
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAE_enc_partial_noupdate_arm_sha3(HiAE_state_t  *state_opaque,
                                   uint8_t       *ci,
                                   const uint8_t *mi,
                                   size_t         size)
{
    if (size == 0)
        return;

    DATA128b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));

    DATA128b M[1], C[1];
    uint8_t  buf[BLOCK_SIZE];

    memcpy(buf, mi, size);
    memset(buf + size, 0, BLOCK_SIZE - size);
    M[0] = SIMD_LOAD(buf);
    C[0] = enc_offset(state, M[0], 0);
    SIMD_STORE(buf, C[0]);
    memcpy(ci, buf, size);
}

static void
HiAE_dec_partial_noupdate_arm_sha3(HiAE_state_t  *state_opaque,
                                   uint8_t       *mi,
                                   const uint8_t *ci,
                                   size_t         size)
{
    if (size == 0)
        return;

    DATA128b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));

    DATA128b M[1], C[1];
    uint8_t  buf[BLOCK_SIZE];
    uint8_t  mask[BLOCK_SIZE];

    memcpy(buf, ci, size);
    memset(mask, 0xff, size);
    memset(mask + size, 0x00, BLOCK_SIZE - size);
    C[0] = SIMD_LOAD(buf);
    M[0] = SIMD_LOAD(mask);
    C[0] = keystream_block(state, C[0], 0);
    C[0] = SIMD_AND(C[0], M[0]);
    SIMD_STORE(buf, C[0]);
    memcpy(mi, buf, size);
}

static int
HiAE_encrypt_arm_sha3(const uint8_t *key,
                      const uint8_t *nonce,
                      const uint8_t *msg,
                      uint8_t       *ct,
                      size_t         msg_len,
                      const uint8_t *ad,
                      size_t         ad_len,
                      uint8_t       *tag)
{
    HiAE_state_t state;
    HiAE_init_arm_sha3(&state, key, nonce);
    HiAE_absorb_arm_sha3(&state, ad, ad_len);
    HiAE_enc_arm_sha3(&state, ct, msg, msg_len);
    HiAE_finalize_arm_sha3(&state, ad_len, msg_len, tag);

    return 0;
}

static int
HiAE_decrypt_arm_sha3(const uint8_t *key,
                      const uint8_t *nonce,
                      uint8_t       *msg,
                      const uint8_t *ct,
                      size_t         ct_len,
                      const uint8_t *ad,
                      size_t         ad_len,
                      const uint8_t *tag)
{
    HiAE_state_t state;
    uint8_t      computed_tag[HIAE_MACBYTES];
    HiAE_init_arm_sha3(&state, key, nonce);
    HiAE_absorb_arm_sha3(&state, ad, ad_len);
    HiAE_dec_arm_sha3(&state, msg, ct, ct_len);
    HiAE_finalize_arm_sha3(&state, ad_len, ct_len, computed_tag);

    return hiae_constant_time_compare(computed_tag, tag, HIAE_MACBYTES);
}

static int
HiAE_mac_arm_sha3(
    const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len, uint8_t *tag)
{
    HiAE_state_t state;
    HiAE_init_arm_sha3(&state, key, nonce);
    HiAE_absorb_arm_sha3(&state, data, data_len);
    HiAE_finalize_arm_sha3(&state, data_len, 0, tag);

    return 0;
}

const HiAE_impl_t hiae_arm_sha3_impl = { .name                 = "ARM SHA3",
                                         .init                 = HiAE_init_arm_sha3,
                                         .absorb               = HiAE_absorb_arm_sha3,
                                         .finalize             = HiAE_finalize_arm_sha3,
                                         .enc                  = HiAE_enc_arm_sha3,
                                         .dec                  = HiAE_dec_arm_sha3,
                                         .enc_partial_noupdate = HiAE_enc_partial_noupdate_arm_sha3,
                                         .dec_partial_noupdate = HiAE_dec_partial_noupdate_arm_sha3,
                                         .encrypt              = HiAE_encrypt_arm_sha3,
                                         .decrypt              = HiAE_decrypt_arm_sha3,
                                         .mac                  = HiAE_mac_arm_sha3 };

#    ifdef __clang__
#        pragma clang attribute pop
#    endif

#else
// ARM SHA3 extensions not available, provide stub implementation
const HiAE_impl_t hiae_arm_sha3_impl = { .name                 = NULL,
                                         .init                 = NULL,
                                         .absorb               = NULL,
                                         .finalize             = NULL,
                                         .enc                  = NULL,
                                         .dec                  = NULL,
                                         .enc_partial_noupdate = NULL,
                                         .dec_partial_noupdate = NULL,
                                         .encrypt              = NULL,
                                         .decrypt              = NULL,
                                         .mac                  = NULL };
#endif