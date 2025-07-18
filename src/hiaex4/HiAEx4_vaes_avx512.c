#include "HiAEx4.h"
#include "HiAEx4_internal.h"

#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)

#    ifdef __clang__
#        if __clang_major__ >= 18
#            pragma clang attribute push(__attribute__((target("aes,vaes,avx512f,evex512"))), \
                                         apply_to = function)
#        else
#            pragma clang attribute push(__attribute__((target("aes,vaes,avx512f"))), \
                                         apply_to = function)
#        endif
#    elif defined(__GNUC__)
#        pragma GCC target("aes,vaes,avx512f")
#    endif

#    include <immintrin.h>
#    include <wmmintrin.h>
#    include <xmmintrin.h>

#    define PREFETCH_READ(addr, locality)  _mm_prefetch((const char *) (addr), _MM_HINT_T0)
#    define PREFETCH_WRITE(addr, locality) _mm_prefetch((const char *) (addr), _MM_HINT_T0)
/* Prefetch distance in bytes - matches ARM implementation */
#    define PREFETCH_DISTANCE (4 * 256)

typedef __m128i DATA128b;
typedef __m512i DATA512b;

#    define SIMD_LOAD(x)        _mm512_loadu_si512((const __m512i *) (x))
#    define SIMD_LOADx4(x)      _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *) (x)))
#    define SIMD_STORE(x, y)    _mm512_storeu_si512((__m512i *) (x), y)
#    define SIMD_STORE128(x, y) _mm_storeu_si128((__m128i *) (x), y)
#    define SIMD_XOR(x, y)      _mm512_xor_si512(x, y)
#    define SIMD_AND(x, y)      _mm512_and_si512(x, y)
#    define SIMD_ZERO_512()     _mm512_setzero_si512()
#    define SIMD_FOLD(x, y)                                                        \
        _mm_xor_si128(_mm512_castsi512_si128(x),                                   \
                      _mm_xor_si128(_mm512_extracti32x4_epi32(x, 1),               \
                                    _mm_xor_si128(_mm512_extracti32x4_epi32(x, 2), \
                                                  _mm512_extracti32x4_epi32(x, 3))))
#    define AESENC(x, y) _mm512_aesenc_epi128(x, y)

static inline void
update_state_offset(DATA512b *state, DATA512b *tmp, DATA512b M, int offset)
{
    tmp[offset] = SIMD_XOR(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    tmp[offset] = AESENC(tmp[offset], M);
    state[(0 + offset) % STATE]   = AESENC(state[(P_4 + offset) % STATE], tmp[offset]);
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], M);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], M);
}

static inline DATA512b
keystream_block(DATA512b *state, DATA512b *tmp, DATA512b M, int offset)
{
    tmp[offset] = SIMD_XOR(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    M           = AESENC(tmp[offset], M);
    M           = SIMD_XOR(M, state[(P_7 + offset) % STATE]);
    return M;
}

static inline DATA512b
enc_offset(DATA512b *state, DATA512b M, int offset)
{
    DATA512b C = SIMD_XOR(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    C          = AESENC(C, M);
    state[(0 + offset) % STATE]   = AESENC(state[(P_4 + offset) % STATE], C);
    C                             = SIMD_XOR(C, state[(P_7 + offset) % STATE]);
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], M);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], M);
    return C;
}

static inline DATA512b
dec_offset(DATA512b *state, DATA512b *tmp, DATA512b C, int offset)
{
    tmp[offset] = SIMD_XOR(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    DATA512b M  = SIMD_XOR(state[(P_7 + offset) % STATE], C);
    state[(0 + offset) % STATE]   = AESENC(state[(P_4 + offset) % STATE], M);
    M                             = AESENC(tmp[offset], M);
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
state_shift(DATA512b *state)
{
    DATA512b temp = state[0];
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
init_update(DATA512b *state, DATA512b *tmp, DATA512b c0)
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
ad_update(DATA512b *state, DATA512b *tmp, DATA512b *M, const uint8_t *ad, size_t i)
{
    PREFETCH_READ(ad + i + UNROLL_BLOCK_SIZE, 0);
    PREFETCH_READ(ad + i + UNROLL_BLOCK_SIZE + 128, 0);

    // Process in groups of 4 blocks to reduce register pressure
    // This allows GCC to better manage register allocation

    // Group 1: blocks 0-3
    LOAD_1BLOCK_offset_ad(M[0], 0);
    LOAD_1BLOCK_offset_ad(M[1], 1);
    LOAD_1BLOCK_offset_ad(M[2], 2);
    LOAD_1BLOCK_offset_ad(M[3], 3);
    update_state_offset(state, tmp, M[0], 0);
    update_state_offset(state, tmp, M[1], 1);
    update_state_offset(state, tmp, M[2], 2);
    update_state_offset(state, tmp, M[3], 3);

    // Group 2: blocks 4-7
    LOAD_1BLOCK_offset_ad(M[4], 4);
    LOAD_1BLOCK_offset_ad(M[5], 5);
    LOAD_1BLOCK_offset_ad(M[6], 6);
    LOAD_1BLOCK_offset_ad(M[7], 7);
    update_state_offset(state, tmp, M[4], 4);
    update_state_offset(state, tmp, M[5], 5);
    update_state_offset(state, tmp, M[6], 6);
    update_state_offset(state, tmp, M[7], 7);

    // Group 3: blocks 8-11
    LOAD_1BLOCK_offset_ad(M[8], 8);
    LOAD_1BLOCK_offset_ad(M[9], 9);
    LOAD_1BLOCK_offset_ad(M[10], 10);
    LOAD_1BLOCK_offset_ad(M[11], 11);
    update_state_offset(state, tmp, M[8], 8);
    update_state_offset(state, tmp, M[9], 9);
    update_state_offset(state, tmp, M[10], 10);
    update_state_offset(state, tmp, M[11], 11);

    // Group 4: blocks 12-15
    LOAD_1BLOCK_offset_ad(M[12], 12);
    LOAD_1BLOCK_offset_ad(M[13], 13);
    LOAD_1BLOCK_offset_ad(M[14], 14);
    LOAD_1BLOCK_offset_ad(M[15], 15);
    update_state_offset(state, tmp, M[12], 12);
    update_state_offset(state, tmp, M[13], 13);
    update_state_offset(state, tmp, M[14], 14);
    update_state_offset(state, tmp, M[15], 15);
}

static inline void
encrypt_chunk(DATA512b *state, DATA512b *M, DATA512b *C, const uint8_t *mi, uint8_t *ci, size_t i)
{
    PREFETCH_READ(mi + i + PREFETCH_DISTANCE, 0);
    PREFETCH_WRITE(ci + i + PREFETCH_DISTANCE, 0);

    // Process blocks in groups of 4 to reduce register pressure
    // This prevents GCC from trying to keep all 16 M[] and C[] values in registers

    // Group 1: blocks 0-3
    LOAD_1BLOCK_offset_enc(M[0], 0);
    LOAD_1BLOCK_offset_enc(M[1], 1);
    LOAD_1BLOCK_offset_enc(M[2], 2);
    LOAD_1BLOCK_offset_enc(M[3], 3);
    C[0] = enc_offset(state, M[0], 0);
    C[1] = enc_offset(state, M[1], 1);
    C[2] = enc_offset(state, M[2], 2);
    C[3] = enc_offset(state, M[3], 3);
    STORE_1BLOCK_offset_enc(C[0], 0);
    STORE_1BLOCK_offset_enc(C[1], 1);
    STORE_1BLOCK_offset_enc(C[2], 2);
    STORE_1BLOCK_offset_enc(C[3], 3);

    // Group 2: blocks 4-7
    LOAD_1BLOCK_offset_enc(M[4], 4);
    LOAD_1BLOCK_offset_enc(M[5], 5);
    LOAD_1BLOCK_offset_enc(M[6], 6);
    LOAD_1BLOCK_offset_enc(M[7], 7);
    C[4] = enc_offset(state, M[4], 4);
    C[5] = enc_offset(state, M[5], 5);
    C[6] = enc_offset(state, M[6], 6);
    C[7] = enc_offset(state, M[7], 7);
    STORE_1BLOCK_offset_enc(C[4], 4);
    STORE_1BLOCK_offset_enc(C[5], 5);
    STORE_1BLOCK_offset_enc(C[6], 6);
    STORE_1BLOCK_offset_enc(C[7], 7);

    // Group 3: blocks 8-11
    LOAD_1BLOCK_offset_enc(M[8], 8);
    LOAD_1BLOCK_offset_enc(M[9], 9);
    LOAD_1BLOCK_offset_enc(M[10], 10);
    LOAD_1BLOCK_offset_enc(M[11], 11);
    C[8]  = enc_offset(state, M[8], 8);
    C[9]  = enc_offset(state, M[9], 9);
    C[10] = enc_offset(state, M[10], 10);
    C[11] = enc_offset(state, M[11], 11);
    STORE_1BLOCK_offset_enc(C[8], 8);
    STORE_1BLOCK_offset_enc(C[9], 9);
    STORE_1BLOCK_offset_enc(C[10], 10);
    STORE_1BLOCK_offset_enc(C[11], 11);

    // Group 4: blocks 12-15
    LOAD_1BLOCK_offset_enc(M[12], 12);
    LOAD_1BLOCK_offset_enc(M[13], 13);
    LOAD_1BLOCK_offset_enc(M[14], 14);
    LOAD_1BLOCK_offset_enc(M[15], 15);
    C[12] = enc_offset(state, M[12], 12);
    C[13] = enc_offset(state, M[13], 13);
    C[14] = enc_offset(state, M[14], 14);
    C[15] = enc_offset(state, M[15], 15);
    STORE_1BLOCK_offset_enc(C[12], 12);
    STORE_1BLOCK_offset_enc(C[13], 13);
    STORE_1BLOCK_offset_enc(C[14], 14);
    STORE_1BLOCK_offset_enc(C[15], 15);
}

static inline void
decrypt_chunk(DATA512b      *state,
              DATA512b      *tmp,
              DATA512b      *M,
              DATA512b      *C,
              const uint8_t *ci,
              uint8_t       *mi,
              size_t         i)
{
    PREFETCH_READ(ci + i + PREFETCH_DISTANCE, 0);
    PREFETCH_WRITE(mi + i + PREFETCH_DISTANCE, 0);

    // Group 1: blocks 0-3
    LOAD_1BLOCK_offset_dec(C[0], 0);
    LOAD_1BLOCK_offset_dec(C[1], 1);
    LOAD_1BLOCK_offset_dec(C[2], 2);
    LOAD_1BLOCK_offset_dec(C[3], 3);
    M[0] = dec_offset(state, tmp, C[0], 0);
    M[1] = dec_offset(state, tmp, C[1], 1);
    M[2] = dec_offset(state, tmp, C[2], 2);
    M[3] = dec_offset(state, tmp, C[3], 3);
    STORE_1BLOCK_offset_dec(M[0], 0);
    STORE_1BLOCK_offset_dec(M[1], 1);
    STORE_1BLOCK_offset_dec(M[2], 2);
    STORE_1BLOCK_offset_dec(M[3], 3);

    // Group 2: blocks 4-7
    LOAD_1BLOCK_offset_dec(C[4], 4);
    LOAD_1BLOCK_offset_dec(C[5], 5);
    LOAD_1BLOCK_offset_dec(C[6], 6);
    LOAD_1BLOCK_offset_dec(C[7], 7);
    M[4] = dec_offset(state, tmp, C[4], 4);
    M[5] = dec_offset(state, tmp, C[5], 5);
    M[6] = dec_offset(state, tmp, C[6], 6);
    M[7] = dec_offset(state, tmp, C[7], 7);
    STORE_1BLOCK_offset_dec(M[4], 4);
    STORE_1BLOCK_offset_dec(M[5], 5);
    STORE_1BLOCK_offset_dec(M[6], 6);
    STORE_1BLOCK_offset_dec(M[7], 7);

    // Group 3: blocks 8-11
    LOAD_1BLOCK_offset_dec(C[8], 8);
    LOAD_1BLOCK_offset_dec(C[9], 9);
    LOAD_1BLOCK_offset_dec(C[10], 10);
    LOAD_1BLOCK_offset_dec(C[11], 11);
    M[8]  = dec_offset(state, tmp, C[8], 8);
    M[9]  = dec_offset(state, tmp, C[9], 9);
    M[10] = dec_offset(state, tmp, C[10], 10);
    M[11] = dec_offset(state, tmp, C[11], 11);
    STORE_1BLOCK_offset_dec(M[8], 8);
    STORE_1BLOCK_offset_dec(M[9], 9);
    STORE_1BLOCK_offset_dec(M[10], 10);
    STORE_1BLOCK_offset_dec(M[11], 11);

    // Group 4: blocks 12-15
    LOAD_1BLOCK_offset_dec(C[12], 12);
    LOAD_1BLOCK_offset_dec(C[13], 13);
    LOAD_1BLOCK_offset_dec(C[14], 14);
    LOAD_1BLOCK_offset_dec(C[15], 15);
    M[12] = dec_offset(state, tmp, C[12], 12);
    M[13] = dec_offset(state, tmp, C[13], 13);
    M[14] = dec_offset(state, tmp, C[14], 14);
    M[15] = dec_offset(state, tmp, C[15], 15);
    STORE_1BLOCK_offset_dec(M[12], 12);
    STORE_1BLOCK_offset_dec(M[13], 13);
    STORE_1BLOCK_offset_dec(M[14], 14);
    STORE_1BLOCK_offset_dec(M[15], 15);
}

static void
HiAEx4_init_vaes_avx512(HiAEx4_state_t *state_opaque, const uint8_t *key, const uint8_t *nonce)
{
    DATA512b state[STATE];
    memset(&state, 0, sizeof state);
    DATA512b c0 = SIMD_LOAD(C0);
    DATA512b c1 = SIMD_LOAD(C1);
    DATA512b k0 = SIMD_LOADx4(key);
    DATA512b k1 = SIMD_LOADx4(key + 16);
    DATA512b N  = SIMD_LOADx4(nonce);

    DATA512b ze = SIMD_ZERO_512();
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

    // Context separation
    const uint8_t degree                = 4;
    uint8_t       ctx_bytes[BLOCK_SIZE] = { 0 };
    for (size_t i = 0; i < degree; i++) {
        ctx_bytes[i * 16 + 0] = (uint8_t) i;
        ctx_bytes[i * 16 + 1] = degree - 1;
    }
    const DATA512b ctx = SIMD_LOAD(ctx_bytes);
    for (size_t i = 0; i < STATE; i++) {
        state[i] = SIMD_XOR(state[i], ctx);
    }

    DATA512b tmp[STATE];
    init_update(state, tmp, c0);
    init_update(state, tmp, c0);

    state[9]  = SIMD_XOR(state[9], k0);
    state[13] = SIMD_XOR(state[13], k1);
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAEx4_absorb_vaes_avx512(HiAEx4_state_t *state_opaque, const uint8_t *ad, size_t len)
{
    DATA512b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t   i      = 0;
    size_t   rest   = len % UNROLL_BLOCK_SIZE;
    size_t   prefix = len - rest;
    DATA512b tmp[STATE], M[16];
    if (len == 0)
        return;

    for (; i < prefix; i += UNROLL_BLOCK_SIZE) {
        ad_update(state, tmp, M, ad, i);
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
HiAEx4_finalize_vaes_avx512(HiAEx4_state_t *state_opaque,
                            uint64_t        ad_len,
                            uint64_t        msg_len,
                            uint8_t        *tag)
{
    DATA512b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    uint64_t lens[2];
    lens[0] = ad_len * 8;
    lens[1] = msg_len * 8;
    DATA512b temp, tmp[STATE];
    temp = SIMD_LOADx4((uint8_t *) lens);
    init_update(state, tmp, temp);
    init_update(state, tmp, temp);
    temp = state[0];
    for (size_t i = 1; i < STATE; ++i) {
        temp = SIMD_XOR(temp, state[i]);
    }
    SIMD_STORE128(tag, SIMD_FOLD(temp, temp));
    memcpy(state_opaque->opaque, state, sizeof(state));
}

/* Enhanced MAC finalization with proper domain separation for multi-parallel implementations */
static void
HiAEx4_finalize_mac_vaes_avx512(HiAEx4_state_t *state_opaque, uint64_t data_len, uint8_t *tag)
{
    DATA512b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    DATA512b      tmp[STATE];
    const uint8_t degree = 4;

    /* Step 1: Initial diffusion with data_len and HIAEX4_MACBYTES */
    uint64_t lens[2];
    lens[0]       = data_len * 8;
    lens[1]       = HIAEX4_MACBYTES * 8;
    DATA512b temp = SIMD_LOADx4((uint8_t *) lens);
    init_update(state, tmp, temp);
    init_update(state, tmp, temp);

    /* Step 2: XOR all states together to get tag_multi */
    temp = state[0];
    for (size_t i = 1; i < STATE; ++i) {
        temp = SIMD_XOR(temp, state[i]);
    }

    /* Step 3: Extract MAC from each lane and absorb it */
    uint8_t tag_multi_bytes[BLOCK_SIZE];
    SIMD_STORE(tag_multi_bytes, temp);

    /* Absorb MACs from lanes 1, 2, 3 (skip lane 0) */
    for (size_t d = 1; d < degree; d++) {
        uint8_t v_block[BLOCK_SIZE];
        memset(v_block, 0, BLOCK_SIZE);

        /* Extract MAC from lane d */
        memcpy(v_block, tag_multi_bytes + d * HIAEX4_MACBYTES, HIAEX4_MACBYTES);

        /* Absorb the MAC */
        DATA512b v = SIMD_LOAD(v_block);
        update_state_offset(state, tmp, v, 0);
        state_shift(state);
    }

    /* Step 4: Additional diffusion if degree > 1 */
    if (degree > 1) {
        uint64_t degree_lens[2];
        degree_lens[0]       = degree;
        degree_lens[1]       = HIAEX4_MACBYTES * 8;
        DATA512b degree_temp = SIMD_LOADx4((uint8_t *) degree_lens);
        init_update(state, tmp, degree_temp);
        init_update(state, tmp, degree_temp);
    }

    /* Step 5: Final MAC extraction */
    temp = state[0];
    for (size_t i = 1; i < STATE; ++i) {
        temp = SIMD_XOR(temp, state[i]);
    }
    SIMD_STORE128(tag, SIMD_FOLD(temp, temp));
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAEx4_enc_vaes_avx512(HiAEx4_state_t *state_opaque, uint8_t *ci, const uint8_t *mi, size_t size)
{
    DATA512b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t rest   = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    if (size == 0)
        return;
    DATA512b M[STATE], C[STATE];

    // Main processing loop with prefetching
    for (size_t i = 0; i < prefix; i += UNROLL_BLOCK_SIZE) {
        // Unconditional prefetch for next iteration
        PREFETCH_READ(mi + i + UNROLL_BLOCK_SIZE, 0);
        PREFETCH_WRITE(ci + i + UNROLL_BLOCK_SIZE, 0);

        encrypt_chunk(state, M, C, mi, ci, i);
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
HiAEx4_dec_vaes_avx512(HiAEx4_state_t *state_opaque, uint8_t *mi, const uint8_t *ci, size_t size)
{
    DATA512b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t rest   = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    if (size == 0)
        return;
    DATA512b M[STATE], C[STATE], tmp[STATE];

    // Main processing loop with prefetching
    for (size_t i = 0; i < prefix; i += UNROLL_BLOCK_SIZE) {
        // Unconditional prefetch for next iteration
        PREFETCH_READ(ci + i + UNROLL_BLOCK_SIZE, 0);
        PREFETCH_WRITE(mi + i + UNROLL_BLOCK_SIZE, 0);

        decrypt_chunk(state, tmp, M, C, ci, mi, i);
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
        C[0] = keystream_block(state, tmp, C[0], 0);
        C[0] = SIMD_AND(C[0], M[0]);
        update_state_offset(state, tmp, C[0], 0);
        state_shift(state);
        SIMD_STORE(buf, C[0]);
        memcpy(mi + rest + prefix, buf, pad);
    }
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAEx4_enc_partial_noupdate_vaes_avx512(HiAEx4_state_t *state_opaque,
                                        uint8_t        *ci,
                                        const uint8_t  *mi,
                                        size_t          size)
{
    if (size == 0)
        return;

    DATA512b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));

    DATA512b M[1], C[1];
    uint8_t  buf[BLOCK_SIZE];

    memcpy(buf, mi, size);
    memset(buf + size, 0, BLOCK_SIZE - size);
    M[0] = SIMD_LOAD(buf);
    C[0] = enc_offset(state, M[0], 0);
    SIMD_STORE(buf, C[0]);
    memcpy(ci, buf, size);
}

static void
HiAEx4_dec_partial_noupdate_vaes_avx512(HiAEx4_state_t *state_opaque,
                                        uint8_t        *mi,
                                        const uint8_t  *ci,
                                        size_t          size)
{
    if (size == 0)
        return;

    DATA512b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));

    DATA512b M[1], C[1], tmp[STATE];
    uint8_t  buf[BLOCK_SIZE];
    uint8_t  mask[BLOCK_SIZE];

    memcpy(buf, ci, size);
    memset(mask, 0xff, size);
    memset(mask + size, 0x00, BLOCK_SIZE - size);
    C[0] = SIMD_LOAD(buf);
    M[0] = SIMD_LOAD(mask);
    C[0] = keystream_block(state, tmp, C[0], 0);
    C[0] = SIMD_AND(C[0], M[0]);
    SIMD_STORE(buf, C[0]);
    memcpy(mi, buf, size);
}

static int
HiAEx4_encrypt_vaes_avx512(const uint8_t *key,
                           const uint8_t *nonce,
                           const uint8_t *msg,
                           uint8_t       *ct,
                           size_t         msg_len,
                           const uint8_t *ad,
                           size_t         ad_len,
                           uint8_t       *tag)
{
    HiAEx4_state_t state;
    HiAEx4_init_vaes_avx512(&state, key, nonce);
    HiAEx4_absorb_vaes_avx512(&state, ad, ad_len);
    HiAEx4_enc_vaes_avx512(&state, ct, msg, msg_len);
    HiAEx4_finalize_vaes_avx512(&state, ad_len, msg_len, tag);

    return 0;
}

static int
HiAEx4_decrypt_vaes_avx512(const uint8_t *key,
                           const uint8_t *nonce,
                           uint8_t       *msg,
                           const uint8_t *ct,
                           size_t         ct_len,
                           const uint8_t *ad,
                           size_t         ad_len,
                           const uint8_t *tag)
{
    HiAEx4_state_t state;
    uint8_t        computed_tag[HIAEX4_MACBYTES];
    HiAEx4_init_vaes_avx512(&state, key, nonce);
    HiAEx4_absorb_vaes_avx512(&state, ad, ad_len);
    HiAEx4_dec_vaes_avx512(&state, msg, ct, ct_len);
    HiAEx4_finalize_vaes_avx512(&state, ad_len, ct_len, computed_tag);

    return hiaex4_constant_time_compare(computed_tag, tag, HIAEX4_MACBYTES);
}

static int
HiAEx4_mac_vaes_avx512(
    const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len, uint8_t *tag)
{
    HiAEx4_state_t state;
    HiAEx4_init_vaes_avx512(&state, key, nonce);
    HiAEx4_absorb_vaes_avx512(&state, data, data_len);
    HiAEx4_finalize_mac_vaes_avx512(&state, data_len, tag);

    return 0;
}

const HiAEx4_impl_t hiaex4_vaes_avx512_impl = { .name         = "VAES-AVX512",
                                                .init         = HiAEx4_init_vaes_avx512,
                                                .absorb       = HiAEx4_absorb_vaes_avx512,
                                                .finalize     = HiAEx4_finalize_vaes_avx512,
                                                .finalize_mac = HiAEx4_finalize_mac_vaes_avx512,
                                                .enc          = HiAEx4_enc_vaes_avx512,
                                                .dec          = HiAEx4_dec_vaes_avx512,
                                                .enc_partial_noupdate =
                                                    HiAEx4_enc_partial_noupdate_vaes_avx512,
                                                .dec_partial_noupdate =
                                                    HiAEx4_dec_partial_noupdate_vaes_avx512,
                                                .encrypt = HiAEx4_encrypt_vaes_avx512,
                                                .decrypt = HiAEx4_decrypt_vaes_avx512,
                                                .mac     = HiAEx4_mac_vaes_avx512 };

#    ifdef __clang__
#        pragma clang attribute pop
#    endif

#else
const HiAEx4_impl_t hiaex4_vaes_avx4_impl = { .name                 = NULL,
                                              .init                 = NULL,
                                              .absorb               = NULL,
                                              .finalize             = NULL,
                                              .finalize_mac         = NULL,
                                              .enc                  = NULL,
                                              .dec                  = NULL,
                                              .enc_partial_noupdate = NULL,
                                              .dec_partial_noupdate = NULL,
                                              .encrypt              = NULL,
                                              .decrypt              = NULL,
                                              .mac                  = NULL };
#endif
