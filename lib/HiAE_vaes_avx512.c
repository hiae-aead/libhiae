#include "HiAE.h"
#include "HiAE_internal.h"

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

/* Prefetch macros for x86-64 - tuned for AVX512 */
/* locality hints: _MM_HINT_T0 = all cache levels, _MM_HINT_T1 = L2 and up, _MM_HINT_T2 = L3 and up,
 * _MM_HINT_NTA = non-temporal */
#    define PREFETCH_READ(addr, hint)  _mm_prefetch((const char *) (addr), (hint))
#    define PREFETCH_WRITE(addr, hint) _mm_prefetch((const char *) (addr), (hint))

/* Prefetch distance in bytes - matches ARM implementation */
#    define PREFETCH_DISTANCE 256

typedef __m128i DATA128b;

/* x86-64 AES-NI specific SIMD operations */
#    define SIMD_LOAD(x)     _mm_loadu_si128((const __m128i *) (x))
#    define SIMD_STORE(x, y) _mm_storeu_si128((__m128i *) (x), y)
#    define SIMD_XOR(x, y)   _mm_xor_si128(x, y)
#    define SIMD_ZERO_128()  _mm_setzero_si128()
#    define AESENC(x, y)     _mm_aesenc_si128(x, y)

/* x86-specific state update functions */
static inline void
update_state_offset(DATA128b *state, DATA128b *tmp, DATA128b M, int offset)
{
    tmp[offset] = SIMD_XOR(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    tmp[offset] = AESENC(tmp[offset], M);
    state[(0 + offset) % STATE]   = AESENC(state[(P_4 + offset) % STATE], tmp[offset]);
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], M);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], M);
}

static inline DATA128b
keystream_block(DATA128b *state, DATA128b *tmp, DATA128b M, int offset)
{
    tmp[offset] = SIMD_XOR(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    M           = AESENC(tmp[offset], M);
    M           = SIMD_XOR(M, state[(P_7 + offset) % STATE]);
    return M;
}

static inline DATA128b
enc_offset(DATA128b *state, DATA128b M, int offset)
{
    DATA128b C = SIMD_XOR(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    C          = AESENC(C, M);
    state[(0 + offset) % STATE]   = AESENC(state[(P_4 + offset) % STATE], C);
    C                             = SIMD_XOR(C, state[(P_7 + offset) % STATE]);
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], M);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], M);
    return C;
}

static inline DATA128b
dec_offset(DATA128b *state, DATA128b *tmp, DATA128b C, int offset)
{
    tmp[offset] = SIMD_XOR(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    DATA128b M  = SIMD_XOR(state[(P_7 + offset) % STATE], C);
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
HiAE_init_vaes(HiAE_state_t *state_opaque, const uint8_t *key, const uint8_t *nonce)
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
HiAE_absorb_vaes(HiAE_state_t *state_opaque, const uint8_t *ad, size_t len)
{
    DATA128b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t   i      = 0;
    size_t   rest   = len % UNROLL_BLOCK_SIZE;
    size_t   prefix = len - rest;
    DATA128b tmp[STATE], M[16];
    if (len == 0)
        return;

    // VAES optimized assembly code for AD processing
    __asm__ volatile(
        // Load state into xmm0-xmm15
        "vmovdqa64 (%0), %%xmm0;" // state[0]
        "vmovdqa64 16(%0), %%xmm1;" // state[1]
        "vmovdqa64 32(%0), %%xmm2;" // state[2]
        "vmovdqa64 48(%0), %%xmm3;" // state[3]
        "vmovdqa64 64(%0), %%xmm4;" // state[4]
        "vmovdqa64 80(%0), %%xmm5;" // state[5]
        "vmovdqa64 96(%0), %%xmm6;" // state[6]
        "vmovdqa64 112(%0), %%xmm7;" // state[7]
        "vmovdqa64 128(%0), %%xmm8;" // state[8]
        "vmovdqa64 144(%0), %%xmm9;" // state[9]
        "vmovdqa64 160(%0), %%xmm10;" // state[10]
        "vmovdqa64 176(%0), %%xmm11;" // state[11]
        "vmovdqa64 192(%0), %%xmm12;" // state[12]
        "vmovdqa64 208(%0), %%xmm13;" // state[13]
        "vmovdqa64 224(%0), %%xmm14;" // state[14]
        "vmovdqa64 240(%0), %%xmm15;" // state[15]

        "movq $0, %%rax;" // Initialize counter i = 0
        "1:;" // Loop start
        "cmpq %2, %%rax;" // Compare i and prefix
        "jge 2f;" // If i >= prefix, jump to loop end

        // Prefetch next iteration data (256 bytes ahead)
        "prefetcht0 256(%1, %%rax);" // Prefetch next chunk for reading
        "prefetcht0 320(%1, %%rax);" // Prefetch more data (cache line boundary)

        // round 1
        "vmovdqu64 0(%1, %%rax), %%xmm16;" // Load M[0] into xmm16
        "vpxorq %%xmm0, %%xmm1, %%xmm24;" // C[0] = SIMD_XOR(S[0], S[1])
        "vaesenc %%xmm16, %%xmm24, %%xmm24;" // C[0] = AESENC(C[0], M[0])
        "vaesenc %%xmm24, %%xmm13, %%xmm0;" // S[16] = AESENC(S[13], C[0])
        "vpxorq %%xmm3, %%xmm16, %%xmm3;" // S[3] = SIMD_XOR(S[3], M[0])
        "vpxorq %%xmm13, %%xmm16, %%xmm13;" // S[13] = SIMD_XOR(S[13], M[0])

        // round 2
        "vmovdqu64 16(%1, %%rax), %%xmm17;" // Load M[1] into xmm17
        "vpxorq %%xmm1, %%xmm2, %%xmm25;" // C[1] = SIMD_XOR(S[1], S[2])
        "vaesenc %%xmm17, %%xmm25, %%xmm25;" // C[1] = AESENC(C[1], M[1])
        "vaesenc %%xmm25, %%xmm14, %%xmm1;" // S[17] = AESENC(S[14], C[1])
        "vpxorq %%xmm4, %%xmm17, %%xmm4;" // S[4] = SIMD_XOR(S[4], M[1])
        "vpxorq %%xmm14, %%xmm17, %%xmm14;" // S[14] = SIMD_XOR(S[14], M[1])

        // round 3
        "vmovdqu64 32(%1, %%rax), %%xmm18;" // Load M[2] into xmm18
        "vpxorq %%xmm2, %%xmm3, %%xmm26;" // C[2] = SIMD_XOR(S[2], S[3])
        "vaesenc %%xmm18, %%xmm26, %%xmm26;" // C[2] = AESENC(C[2], M[2])
        "vaesenc %%xmm26, %%xmm15, %%xmm2;" // S[18] = AESENC(S[15], C[2])
        "vpxorq %%xmm5, %%xmm18, %%xmm5;" // S[5] = SIMD_XOR(S[5], M[2])
        "vpxorq %%xmm15, %%xmm18, %%xmm15;" // S[15] = SIMD_XOR(S[15], M[2])

        // round 4
        "vmovdqu64 48(%1, %%rax), %%xmm19;" // Load M[3] into xmm19
        "vpxorq %%xmm3, %%xmm4, %%xmm27;" // C[3] = SIMD_XOR(S[3], S[4])
        "vaesenc %%xmm19, %%xmm27, %%xmm27;" // C[3] = AESENC(C[3], M[3])
        "vaesenc %%xmm27, %%xmm0, %%xmm3;" // S[19] = AESENC(S[0], C[3])
        "vpxorq %%xmm6, %%xmm19, %%xmm6;" // S[6] = SIMD_XOR(S[6], M[3])
        "vpxorq %%xmm0, %%xmm19, %%xmm0;" // S[0] = SIMD_XOR(S[0], M[3])

        // round 5
        "vmovdqu64 64(%1, %%rax), %%xmm20;" // Load M[4] into xmm20
        "vpxorq %%xmm4, %%xmm5, %%xmm28;" // C[4] = SIMD_XOR(S[4], S[5])
        "vaesenc %%xmm20, %%xmm28, %%xmm28;" // C[4] = AESENC(C[4], M[4])
        "vaesenc %%xmm28, %%xmm1, %%xmm4;" // S[20] = AESENC(S[1], C[4])
        "vpxorq %%xmm7, %%xmm20, %%xmm7;" // S[7] = SIMD_XOR(S[7], M[4])
        "vpxorq %%xmm1, %%xmm20, %%xmm1;" // S[1] = SIMD_XOR(S[1], M[4])

        // round 6
        "vmovdqu64 80(%1, %%rax), %%xmm21;" // Load M[5] into xmm21
        "vpxorq %%xmm5, %%xmm6, %%xmm29;" // C[5] = SIMD_XOR(S[5], S[6])
        "vaesenc %%xmm21, %%xmm29, %%xmm29;" // C[5] = AESENC(C[5], M[5])
        "vaesenc %%xmm29, %%xmm2, %%xmm5;" // S[21] = AESENC(S[2], C[5])
        "vpxorq %%xmm8, %%xmm21, %%xmm8;" // S[8] = SIMD_XOR(S[8], M[5])
        "vpxorq %%xmm2, %%xmm21, %%xmm2;" // S[2] = SIMD_XOR(S[2], M[5])

        // round 7
        "vmovdqu64 96(%1, %%rax), %%xmm22;" // Load M[6] into xmm22
        "vpxorq %%xmm6, %%xmm7, %%xmm30;" // C[6] = SIMD_XOR(S[6], S[7])
        "vaesenc %%xmm22, %%xmm30, %%xmm30;" // C[6] = AESENC(C[6], M[6])
        "vaesenc %%xmm30, %%xmm3, %%xmm6;" // S[22] = AESENC(S[3], C[6])
        "vpxorq %%xmm9, %%xmm22, %%xmm9;" // S[9] = SIMD_XOR(S[9], M[6])
        "vpxorq %%xmm3, %%xmm22, %%xmm3;" // S[3] = SIMD_XOR(S[3], M[6])

        // round 8
        "vmovdqu64 112(%1, %%rax), %%xmm23;" // Load M[7] into xmm23
        "vpxorq %%xmm7, %%xmm8, %%xmm31;" // C[7] = SIMD_XOR(S[7], S[8])
        "vaesenc %%xmm23, %%xmm31, %%xmm31;" // C[7] = AESENC(C[7], M[7])
        "vaesenc %%xmm31, %%xmm4, %%xmm7;" // S[23] = AESENC(S[4], C[7])
        "vpxorq %%xmm10, %%xmm23, %%xmm10;" // S[10] = SIMD_XOR(S[10], M[7])
        "vpxorq %%xmm4, %%xmm23, %%xmm4;" // S[4] = SIMD_XOR(S[4], M[7])

        // round 9
        "vmovdqa64 128(%1, %%rax), %%xmm16;" // Load M[8] into xmm16
        "vpxorq %%xmm8, %%xmm9, %%xmm24;" // C[8] = SIMD_XOR(S[8], S[9])
        "vaesenc %%xmm16, %%xmm24, %%xmm24;" // C[8] = AESENC(M[8], C[8])
        "vaesenc %%xmm24, %%xmm5, %%xmm8;" // S[24] = AESENC(C[8], S[5])
        "vpxorq %%xmm11, %%xmm16, %%xmm11;" // S[11] = SIMD_XOR(S[11], M[8])
        "vpxorq %%xmm5, %%xmm16, %%xmm5;" // S[5] = SIMD_XOR(S[5], M[8])

        // round 10
        "vmovdqa64 144(%1, %%rax), %%xmm17;" // Load M[9] into xmm17
        "vpxorq %%xmm9, %%xmm10, %%xmm25;" // C[9] = SIMD_XOR(S[9], S[10])
        "vaesenc %%xmm17, %%xmm25, %%xmm25;" // C[9] = AESENC(M[9], C[9])
        "vaesenc %%xmm25, %%xmm6, %%xmm9;" // S[25] = AESENC(C[9], S[6])
        "vpxorq %%xmm12, %%xmm17, %%xmm12;" // S[12] = SIMD_XOR(S[12], M[9])
        "vpxorq %%xmm6, %%xmm17, %%xmm6;" // S[6] = SIMD_XOR(S[6], M[9])

        // round 11
        "vmovdqa64 160(%1, %%rax), %%xmm18;" // Load M[10] into xmm18
        "vpxorq %%xmm10, %%xmm11, %%xmm26;" // C[10] = SIMD_XOR(S[10], S[11])
        "vaesenc %%xmm18, %%xmm26, %%xmm26;" // C[10] = AESENC(M[10], C[10])
        "vaesenc %%xmm26, %%xmm7, %%xmm10;" // S[26] = AESENC(C[10], S[7])
        "vpxorq %%xmm13, %%xmm18, %%xmm13;" // S[13] = SIMD_XOR(S[13], M[10])
        "vpxorq %%xmm7, %%xmm18, %%xmm7;" // S[7] = SIMD_XOR(S[7], M[10])

        // round 12
        "vmovdqa64 176(%1, %%rax), %%xmm19;" // Load M[11] into xmm19
        "vpxorq %%xmm11, %%xmm12, %%xmm27;" // C[11] = SIMD_XOR(S[11], S[12])
        "vaesenc %%xmm19, %%xmm27, %%xmm27;" // C[11] = AESENC(M[11], C[11])
        "vaesenc %%xmm27, %%xmm8, %%xmm11;" // S[27] = AESENC(C[11], S[8])
        "vpxorq %%xmm14, %%xmm19, %%xmm14;" // S[14] = SIMD_XOR(S[14], M[11])
        "vpxorq %%xmm8, %%xmm19, %%xmm8;" // S[8] = SIMD_XOR(S[8], M[11])

        // round 13
        "vmovdqa64 192(%1, %%rax), %%xmm20;" // Load M[12] into xmm20
        "vpxorq %%xmm12, %%xmm13, %%xmm28;" // C[12] = SIMD_XOR(S[12], S[13])
        "vaesenc %%xmm20, %%xmm28, %%xmm28;" // C[12] = AESENC(M[12], C[12])
        "vaesenc %%xmm28, %%xmm9, %%xmm12;" // S[28] = AESENC(C[12], S[9])
        "vpxorq %%xmm15, %%xmm20, %%xmm15;" // S[15] = SIMD_XOR(S[15], M[12])
        "vpxorq %%xmm9, %%xmm20, %%xmm9;" // S[9] = SIMD_XOR(S[9], M[12])

        // round 14
        "vmovdqa64 208(%1, %%rax), %%xmm21;" // Load M[13] into xmm21
        "vpxorq %%xmm13, %%xmm14, %%xmm29;" // C[13] = SIMD_XOR(S[13], S[14])
        "vaesenc %%xmm21, %%xmm29, %%xmm29;" // C[13] = AESENC(M[13], C[13])
        "vaesenc %%xmm29, %%xmm10, %%xmm13;" // S[29] = AESENC(C[13], S[10])
        "vpxorq %%xmm0, %%xmm21, %%xmm0;" // S[0] = SIMD_XOR(S[0], M[13])
        "vpxorq %%xmm10, %%xmm21, %%xmm10;" // S[10] = SIMD_XOR(S[10], M[13])

        // round 15
        "vmovdqa64 224(%1, %%rax), %%xmm22;" // Load M[14] into xmm22
        "vpxorq %%xmm14, %%xmm15, %%xmm30;" // C[14] = SIMD_XOR(S[14], S[15])
        "vaesenc %%xmm22, %%xmm30, %%xmm30;" // C[14] = AESENC(M[14], C[14])
        "vaesenc %%xmm30, %%xmm11, %%xmm14;" // S[30] = AESENC(C[14], S[11])
        "vpxorq %%xmm1, %%xmm22, %%xmm1;" // S[1] = SIMD_XOR(S[1], M[14])
        "vpxorq %%xmm11, %%xmm22, %%xmm11;" // S[11] = SIMD_XOR(S[11], M[14])

        // round 16
        "vmovdqa64 240(%1, %%rax), %%xmm23;" // Load M[15] into xmm23
        "vpxorq %%xmm15, %%xmm0, %%xmm31;" // C[15] = SIMD_XOR(S[15], S[0])
        "vaesenc %%xmm23, %%xmm31, %%xmm31;" // C[15] = AESENC(M[15], C[15])
        "vaesenc %%xmm31, %%xmm12, %%xmm15;" // S[31] = AESENC(C[15], S[12])
        "vpxorq %%xmm2, %%xmm23, %%xmm2;" // S[2] = SIMD_XOR(S[2], M[15])
        "vpxorq %%xmm12, %%xmm23, %%xmm12;" // S[12] = SIMD_XOR(S[12], M[15])

        "addq $256, %%rax;" // i += 256
        "jmp 1b;" // Loop back

        "2:;" // Loop end

        // Write back state
        "vmovdqa64 %%xmm0, (%0);"
        "vmovdqa64 %%xmm1, 16(%0);"
        "vmovdqa64 %%xmm2, 32(%0);"
        "vmovdqa64 %%xmm3, 48(%0);"
        "vmovdqa64 %%xmm4, 64(%0);"
        "vmovdqa64 %%xmm5, 80(%0);"
        "vmovdqa64 %%xmm6, 96(%0);"
        "vmovdqa64 %%xmm7, 112(%0);"
        "vmovdqa64 %%xmm8, 128(%0);"
        "vmovdqa64 %%xmm9, 144(%0);"
        "vmovdqa64 %%xmm10, 160(%0);"
        "vmovdqa64 %%xmm11, 176(%0);"
        "vmovdqa64 %%xmm12, 192(%0);"
        "vmovdqa64 %%xmm13, 208(%0);"
        "vmovdqa64 %%xmm14, 224(%0);"
        "vmovdqa64 %%xmm15, 240(%0);"

        :
        : "r"(state), "r"(ad), "r"(prefix) // input dst, src, prefix, state
        : "%rax", "%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8",
          "%xmm9", "%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15", "%xmm16", "%xmm17",
          "%xmm18", "%xmm19", "%xmm20", "%xmm21", "%xmm22", "%xmm23", "%xmm24", "%xmm25", "%xmm26",
          "%xmm27", "%xmm28", "%xmm29", "%xmm30", "%xmm31", "memory");
    i = prefix;

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
HiAE_finalize_vaes(HiAE_state_t *state_opaque, uint64_t ad_len, uint64_t msg_len, uint8_t *tag)
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
    temp = state[0];
    for (size_t i = 1; i < STATE; ++i) {
        temp = SIMD_XOR(temp, state[i]);
    }
    SIMD_STORE(tag, temp);
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAE_enc_vaes(HiAE_state_t *state_opaque, uint8_t *ci, const uint8_t *mi, size_t size)
{
    DATA128b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t rest   = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    if (size == 0)
        return;
    DATA128b M[STATE], C[STATE];

    // VAES optimized assembly code for encryption
    __asm__ volatile(
        // Load state into xmm0-xmm15
        "vmovdqa64 (%3), %%xmm0;" // state[0]
        "vmovdqa64 16(%3), %%xmm1;" // state[1]
        "vmovdqa64 32(%3), %%xmm2;" // state[2]
        "vmovdqa64 48(%3), %%xmm3;" // state[3]
        "vmovdqa64 64(%3), %%xmm4;" // state[4]
        "vmovdqa64 80(%3), %%xmm5;" // state[5]
        "vmovdqa64 96(%3), %%xmm6;" // state[6]
        "vmovdqa64 112(%3), %%xmm7;" // state[7]
        "vmovdqa64 128(%3), %%xmm8;" // state[8]
        "vmovdqa64 144(%3), %%xmm9;" // state[9]
        "vmovdqa64 160(%3), %%xmm10;" // state[10]
        "vmovdqa64 176(%3), %%xmm11;" // state[11]
        "vmovdqa64 192(%3), %%xmm12;" // state[12]
        "vmovdqa64 208(%3), %%xmm13;" // state[13]
        "vmovdqa64 224(%3), %%xmm14;" // state[14]
        "vmovdqa64 240(%3), %%xmm15;" // state[15]

        "movq $0, %%rax;" // Initialize counter i = 0
        "1:;" // Loop start
        "cmpq %2, %%rax;" // Compare i and prefix
        "jge 2f;" // If i >= prefix, jump to loop end

        // Prefetch next iteration data (256 bytes ahead)
        "prefetcht0 256(%1, %%rax);" // Prefetch next chunk for reading (plaintext)
        "prefetcht0 256(%0, %%rax);" // Prefetch next chunk for writing (ciphertext)
        "prefetcht0 320(%1, %%rax);" // Prefetch more data (cache line boundary)

        // round 1
        "vmovdqu64 0(%1, %%rax), %%xmm16;" // Load M[0] into xmm16
        "vpxorq %%xmm0, %%xmm1, %%xmm24;" // C[0] = SIMD_XOR(S[0], S[1])
        "vaesenc %%xmm16, %%xmm24, %%xmm24;" // C[0] = AESENC(C[0], M[0])
        "vaesenc %%xmm24, %%xmm13, %%xmm0;" // S[16] = AESENC(S[13], C[0])
        "vpxorq %%xmm24, %%xmm9, %%xmm24;" // C[0] = SIMD_XOR(C[0], S[9])
        "vpxorq %%xmm3, %%xmm16, %%xmm3;" // S[3] = SIMD_XOR(S[3], M[0])
        "vpxorq %%xmm13, %%xmm16, %%xmm13;" // S[13] = SIMD_XOR(S[13], M[0])
        "vmovdqu64 %%xmm24, 0(%0, %%rax);" // Write back C[0] to ci[i:i+16]

        // round 2
        "vmovdqu64 16(%1, %%rax), %%xmm17;" // Load M[1] into xmm17
        "vpxorq %%xmm1, %%xmm2, %%xmm25;" // C[1] = SIMD_XOR(S[1], S[2])
        "vaesenc %%xmm17, %%xmm25, %%xmm25;" // C[1] = AESENC(C[1], M[1])
        "vaesenc %%xmm25, %%xmm14, %%xmm1;" // S[17] = AESENC(S[14], C[1])
        "vpxorq %%xmm25, %%xmm10, %%xmm25;" // C[1] = SIMD_XOR(C[1], S[10])
        "vpxorq %%xmm4, %%xmm17, %%xmm4;" // S[4] = SIMD_XOR(S[4], M[1])
        "vpxorq %%xmm14, %%xmm17, %%xmm14;" // S[14] = SIMD_XOR(S[14], M[1])
        "vmovdqu64 %%xmm25, 16(%0, %%rax);" // Write back C[1] to ci[i+16:i+32]

        // round 3
        "vmovdqu64 32(%1, %%rax), %%xmm18;" // Load M[2] into xmm18
        "vpxorq %%xmm2, %%xmm3, %%xmm26;" // C[2] = SIMD_XOR(S[2], S[3])
        "vaesenc %%xmm18, %%xmm26, %%xmm26;" // C[2] = AESENC(C[2], M[2])
        "vaesenc %%xmm26, %%xmm15, %%xmm2;" // S[18] = AESENC(S[15], C[2])
        "vpxorq %%xmm26, %%xmm11, %%xmm26;" // C[2] = SIMD_XOR(C[2], S[11])
        "vpxorq %%xmm5, %%xmm18, %%xmm5;" // S[5] = SIMD_XOR(S[5], M[2])
        "vpxorq %%xmm15, %%xmm18, %%xmm15;" // S[15] = SIMD_XOR(S[15], M[2])
        "vmovdqu64 %%xmm26, 32(%0, %%rax);" // Write back C[2] to ci[i+32:i+48]

        // round 4
        "vmovdqu64 48(%1, %%rax), %%xmm19;" // Load M[3] into xmm19
        "vpxorq %%xmm3, %%xmm4, %%xmm27;" // C[3] = SIMD_XOR(S[3], S[4])
        "vaesenc %%xmm19, %%xmm27, %%xmm27;" // C[3] = AESENC(C[3], M[3])
        "vaesenc %%xmm27, %%xmm0, %%xmm3;" // S[19] = AESENC(S[0], C[3])
        "vpxorq %%xmm27, %%xmm12, %%xmm27;" // C[3] = SIMD_XOR(C[3], S[12])
        "vpxorq %%xmm6, %%xmm19, %%xmm6;" // S[6] = SIMD_XOR(S[6], M[3])
        "vpxorq %%xmm0, %%xmm19, %%xmm0;" // S[0] = SIMD_XOR(S[0], M[3])
        "vmovdqu64 %%xmm27, 48(%0, %%rax);" // Write back C[3] to ci[i+48:i+64]

        // round 5
        "vmovdqu64 64(%1, %%rax), %%xmm20;" // Load M[4] into xmm20
        "vpxorq %%xmm4, %%xmm5, %%xmm28;" // C[4] = SIMD_XOR(S[4], S[5])
        "vaesenc %%xmm20, %%xmm28, %%xmm28;" // C[4] = AESENC(C[4], M[4])
        "vaesenc %%xmm28, %%xmm1, %%xmm4;" // S[20] = AESENC(S[1], C[4])
        "vpxorq %%xmm28, %%xmm13, %%xmm28;" // C[4] = SIMD_XOR(C[4], S[13])
        "vpxorq %%xmm7, %%xmm20, %%xmm7;" // S[7] = SIMD_XOR(S[7], M[4])
        "vpxorq %%xmm1, %%xmm20, %%xmm1;" // S[1] = SIMD_XOR(S[1], M[4])
        "vmovdqu64 %%xmm28, 64(%0, %%rax);" // Write back C[4] to ci[i+64:i+80]

        // round 6
        "vmovdqu64 80(%1, %%rax), %%xmm21;" // Load M[5] into xmm21
        "vpxorq %%xmm5, %%xmm6, %%xmm29;" // C[5] = SIMD_XOR(S[5], S[6])
        "vaesenc %%xmm21, %%xmm29, %%xmm29;" // C[5] = AESENC(C[5], M[5])
        "vaesenc %%xmm29, %%xmm2, %%xmm5;" // S[21] = AESENC(S[2], C[5])
        "vpxorq %%xmm29, %%xmm14, %%xmm29;" // C[5] = SIMD_XOR(C[5], S[14])
        "vpxorq %%xmm8, %%xmm21, %%xmm8;" // S[8] = SIMD_XOR(S[8], M[5])
        "vpxorq %%xmm2, %%xmm21, %%xmm2;" // S[2] = SIMD_XOR(S[2], M[5])
        "vmovdqu64 %%xmm29, 80(%0, %%rax);" // Write back C[5] to ci[i+80:i+96]

        // round 7
        "vmovdqu64 96(%1, %%rax), %%xmm22;" // Load M[6] into xmm22
        "vpxorq %%xmm6, %%xmm7, %%xmm30;" // C[6] = SIMD_XOR(S[6], S[7])
        "vaesenc %%xmm22, %%xmm30, %%xmm30;" // C[6] = AESENC(C[6], M[6])
        "vaesenc %%xmm30, %%xmm3, %%xmm6;" // S[22] = AESENC(S[3], C[6])
        "vpxorq %%xmm30, %%xmm15, %%xmm30;" // C[6] = SIMD_XOR(C[6], S[15])
        "vpxorq %%xmm9, %%xmm22, %%xmm9;" // S[9] = SIMD_XOR(S[9], M[6])
        "vpxorq %%xmm3, %%xmm22, %%xmm3;" // S[3] = SIMD_XOR(S[3], M[6])
        "vmovdqu64 %%xmm30, 96(%0, %%rax);" // Write back C[6] to ci[i+96:i+112]

        // round 8
        "vmovdqu64 112(%1, %%rax), %%xmm23;" // Load M[7] into xmm23
        "vpxorq %%xmm7, %%xmm8, %%xmm31;" // C[7] = SIMD_XOR(S[7], S[8])
        "vaesenc %%xmm23, %%xmm31, %%xmm31;" // C[7] = AESENC(C[7], M[7])
        "vaesenc %%xmm31, %%xmm4, %%xmm7;" // S[23] = AESENC(S[4], C[7])
        "vpxorq %%xmm31, %%xmm0, %%xmm31;" // C[7] = SIMD_XOR(C[7], S[0])
        "vpxorq %%xmm10, %%xmm23, %%xmm10;" // S[10] = SIMD_XOR(S[10], M[7])
        "vpxorq %%xmm4, %%xmm23, %%xmm4;" // S[4] = SIMD_XOR(S[4], M[7])
        "vmovdqu64 %%xmm31, 112(%0, %%rax);" // Write back C[7] to ci[i+112:i+128]

        // round 9
        "vmovdqa64 128(%1, %%rax), %%xmm16;" // Load M[8] into xmm16
        "vpxorq %%xmm8, %%xmm9, %%xmm24;" // C[8] = SIMD_XOR(S[8], S[9])
        "vaesenc %%xmm16, %%xmm24, %%xmm24;" // C[8] = AESENC(M[8], C[8])
        "vaesenc %%xmm24, %%xmm5, %%xmm8;" // S[24] = AESENC(C[8], S[5])
        "vpxorq %%xmm24, %%xmm1, %%xmm24;" // C[8] = SIMD_XOR(C[8], S[1])
        "vpxorq %%xmm11, %%xmm16, %%xmm11;" // S[11] = SIMD_XOR(S[11], M[8])
        "vpxorq %%xmm5, %%xmm16, %%xmm5;" // S[5] = SIMD_XOR(S[5], M[8])
        "vmovdqa64 %%xmm24, 128(%0, %%rax);" // Write back C[8] to ci[i+128:i+144]

        // round 10
        "vmovdqa64 144(%1, %%rax), %%xmm17;" // Load M[9] into xmm17
        "vpxorq %%xmm9, %%xmm10, %%xmm25;" // C[9] = SIMD_XOR(S[9], S[10])
        "vaesenc %%xmm17, %%xmm25, %%xmm25;" // C[9] = AESENC(M[9], C[9])
        "vaesenc %%xmm25, %%xmm6, %%xmm9;" // S[25] = AESENC(C[9], S[6])
        "vpxorq %%xmm25, %%xmm2, %%xmm25;" // C[9] = SIMD_XOR(C[9], S[2])
        "vpxorq %%xmm12, %%xmm17, %%xmm12;" // S[12] = SIMD_XOR(S[12], M[9])
        "vpxorq %%xmm6, %%xmm17, %%xmm6;" // S[6] = SIMD_XOR(S[6], M[9])
        "vmovdqa64 %%xmm25, 144(%0, %%rax);" // Write back C[9] to ci[i+144:i+160]

        // round 11
        "vmovdqa64 160(%1, %%rax), %%xmm18;" // Load M[10] into xmm18
        "vpxorq %%xmm10, %%xmm11, %%xmm26;" // C[10] = SIMD_XOR(S[10], S[11])
        "vaesenc %%xmm18, %%xmm26, %%xmm26;" // C[10] = AESENC(M[10], C[10])
        "vaesenc %%xmm26, %%xmm7, %%xmm10;" // S[26] = AESENC(C[10], S[7])
        "vpxorq %%xmm26, %%xmm3, %%xmm26;" // C[10] = SIMD_XOR(C[10], S[3])
        "vpxorq %%xmm13, %%xmm18, %%xmm13;" // S[13] = SIMD_XOR(S[13], M[10])
        "vpxorq %%xmm7, %%xmm18, %%xmm7;" // S[7] = SIMD_XOR(S[7], M[10])
        "vmovdqa64 %%xmm26, 160(%0, %%rax);" // Write back C[10] to ci[i+160:i+176]

        // round 12
        "vmovdqa64 176(%1, %%rax), %%xmm19;" // Load M[11] into xmm19
        "vpxorq %%xmm11, %%xmm12, %%xmm27;" // C[11] = SIMD_XOR(S[11], S[12])
        "vaesenc %%xmm19, %%xmm27, %%xmm27;" // C[11] = AESENC(M[11], C[11])
        "vaesenc %%xmm27, %%xmm8, %%xmm11;" // S[27] = AESENC(C[11], S[8])
        "vpxorq %%xmm27, %%xmm4, %%xmm27;" // C[11] = SIMD_XOR(C[11], S[4])
        "vpxorq %%xmm14, %%xmm19, %%xmm14;" // S[14] = SIMD_XOR(S[14], M[11])
        "vpxorq %%xmm8, %%xmm19, %%xmm8;" // S[8] = SIMD_XOR(S[8], M[11])
        "vmovdqa64 %%xmm27, 176(%0, %%rax);" // Write back C[11] to ci[i+176:i+192]

        // round 13
        "vmovdqa64 192(%1, %%rax), %%xmm20;" // Load M[12] into xmm20
        "vpxorq %%xmm12, %%xmm13, %%xmm28;" // C[12] = SIMD_XOR(S[12], S[13])
        "vaesenc %%xmm20, %%xmm28, %%xmm28;" // C[12] = AESENC(M[12], C[12])
        "vaesenc %%xmm28, %%xmm9, %%xmm12;" // S[28] = AESENC(C[12], S[9])
        "vpxorq %%xmm28, %%xmm5, %%xmm28;" // C[12] = SIMD_XOR(C[12], S[5])
        "vpxorq %%xmm15, %%xmm20, %%xmm15;" // S[15] = SIMD_XOR(S[15], M[12])
        "vpxorq %%xmm9, %%xmm20, %%xmm9;" // S[9] = SIMD_XOR(S[9], M[12])
        "vmovdqa64 %%xmm28, 192(%0, %%rax);" // Write back C[12] to ci[i+192:i+208]

        // round 14
        "vmovdqa64 208(%1, %%rax), %%xmm21;" // Load M[13] into xmm21
        "vpxorq %%xmm13, %%xmm14, %%xmm29;" // C[13] = SIMD_XOR(S[13], S[14])
        "vaesenc %%xmm21, %%xmm29, %%xmm29;" // C[13] = AESENC(M[13], C[13])
        "vaesenc %%xmm29, %%xmm10, %%xmm13;" // S[29] = AESENC(C[13], S[10])
        "vpxorq %%xmm29, %%xmm6, %%xmm29;" // C[13] = SIMD_XOR(C[13], S[6])
        "vpxorq %%xmm0, %%xmm21, %%xmm0;" // S[0] = SIMD_XOR(S[0], M[13])
        "vpxorq %%xmm10, %%xmm21, %%xmm10;" // S[10] = SIMD_XOR(S[10], M[13])
        "vmovdqa64 %%xmm29, 208(%0, %%rax);" // Write back C[13] to ci[i+208:i+224]

        // round 15
        "vmovdqa64 224(%1, %%rax), %%xmm22;" // Load M[14] into xmm22
        "vpxorq %%xmm14, %%xmm15, %%xmm30;" // C[14] = SIMD_XOR(S[14], S[15])
        "vaesenc %%xmm22, %%xmm30, %%xmm30;" // C[14] = AESENC(M[14], C[14])
        "vaesenc %%xmm30, %%xmm11, %%xmm14;" // S[30] = AESENC(C[14], S[11])
        "vpxorq %%xmm30, %%xmm7, %%xmm30;" // C[14] = SIMD_XOR(C[14], S[7])
        "vpxorq %%xmm1, %%xmm22, %%xmm1;" // S[1] = SIMD_XOR(S[1], M[14])
        "vpxorq %%xmm11, %%xmm22, %%xmm11;" // S[11] = SIMD_XOR(S[11], M[14])
        "vmovdqa64 %%xmm30, 224(%0, %%rax);" // Write back C[14] to ci[i+224:i+240]

        // round 16
        "vmovdqa64 240(%1, %%rax), %%xmm23;" // Load M[15] into xmm23
        "vpxorq %%xmm15, %%xmm0, %%xmm31;" // C[15] = SIMD_XOR(S[15], S[0])
        "vaesenc %%xmm23, %%xmm31, %%xmm31;" // C[15] = AESENC(M[15], C[15])
        "vaesenc %%xmm31, %%xmm12, %%xmm15;" // S[31] = AESENC(C[15], S[12])
        "vpxorq %%xmm31, %%xmm8, %%xmm31;" // C[15] = SIMD_XOR(C[15], S[8])
        "vpxorq %%xmm2, %%xmm23, %%xmm2;" // S[2] = SIMD_XOR(S[2], M[15])
        "vpxorq %%xmm12, %%xmm23, %%xmm12;" // S[12] = SIMD_XOR(S[12], M[15])
        "vmovdqa64 %%xmm31, 240(%0, %%rax);" // Write back C[15] to ci[i+240:i+256]

        "addq $256, %%rax;" // i += 256
        "jmp 1b;" // Loop back

        "2:;" // Loop end

        // Write back state
        "vmovdqa64 %%xmm0, (%3);"
        "vmovdqa64 %%xmm1, 16(%3);"
        "vmovdqa64 %%xmm2, 32(%3);"
        "vmovdqa64 %%xmm3, 48(%3);"
        "vmovdqa64 %%xmm4, 64(%3);"
        "vmovdqa64 %%xmm5, 80(%3);"
        "vmovdqa64 %%xmm6, 96(%3);"
        "vmovdqa64 %%xmm7, 112(%3);"
        "vmovdqa64 %%xmm8, 128(%3);"
        "vmovdqa64 %%xmm9, 144(%3);"
        "vmovdqa64 %%xmm10, 160(%3);"
        "vmovdqa64 %%xmm11, 176(%3);"
        "vmovdqa64 %%xmm12, 192(%3);"
        "vmovdqa64 %%xmm13, 208(%3);"
        "vmovdqa64 %%xmm14, 224(%3);"
        "vmovdqa64 %%xmm15, 240(%3);"

        :
        : "r"(ci), "r"(mi), "r"(prefix), "r"(state) // input ci, mi, prefix, state
        : "%rax", "%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8",
          "%xmm9", "%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15", "%xmm16", "%xmm17",
          "%xmm18", "%xmm19", "%xmm20", "%xmm21", "%xmm22", "%xmm23", "%xmm24", "%xmm25", "%xmm26",
          "%xmm27", "%xmm28", "%xmm29", "%xmm30", "%xmm31", "memory");

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
HiAE_dec_vaes(HiAE_state_t *state_opaque, uint8_t *mi, const uint8_t *ci, size_t size)
{
    DATA128b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t rest   = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    if (size == 0)
        return;
    DATA128b M[STATE], C[STATE], tmp[STATE];

    // VAES optimized assembly code for decryption
    __asm__ volatile(
        // Load state into xmm0-xmm15
        "vmovdqa64 (%3), %%xmm0;" // state[0]
        "vmovdqa64 16(%3), %%xmm1;" // state[1]
        "vmovdqa64 32(%3), %%xmm2;" // state[2]
        "vmovdqa64 48(%3), %%xmm3;" // state[3]
        "vmovdqa64 64(%3), %%xmm4;" // state[4]
        "vmovdqa64 80(%3), %%xmm5;" // state[5]
        "vmovdqa64 96(%3), %%xmm6;" // state[6]
        "vmovdqa64 112(%3), %%xmm7;" // state[7]
        "vmovdqa64 128(%3), %%xmm8;" // state[8]
        "vmovdqa64 144(%3), %%xmm9;" // state[9]
        "vmovdqa64 160(%3), %%xmm10;" // state[10]
        "vmovdqa64 176(%3), %%xmm11;" // state[11]
        "vmovdqa64 192(%3), %%xmm12;" // state[12]
        "vmovdqa64 208(%3), %%xmm13;" // state[13]
        "vmovdqa64 224(%3), %%xmm14;" // state[14]
        "vmovdqa64 240(%3), %%xmm15;" // state[15]

        "movq $0, %%rax;" // Initialize counter i = 0
        "1:;" // Loop start
        "cmpq %2, %%rax;" // Compare i and prefix
        "jge 2f;" // If i >= prefix, jump to loop end

        // Prefetch next iteration data (256 bytes ahead)
        "prefetcht0 256(%1, %%rax);" // Prefetch next chunk for reading (ciphertext)
        "prefetcht0 256(%0, %%rax);" // Prefetch next chunk for writing (plaintext)
        "prefetcht0 320(%1, %%rax);" // Prefetch more data (cache line boundary)

        // round 1
        "vmovdqu64 0(%1, %%rax), %%xmm24;" // Load C[0] into xmm24
        "vpxorq %%xmm0, %%xmm1, %%xmm16;" // M[0] = SIMD_XOR(S[0], S[1])
        "vpxorq %%xmm24, %%xmm9, %%xmm24;" // C[0] = SIMD_XOR(S[9], C[0])
        "vaesenc %%xmm24, %%xmm13, %%xmm0;" // S[16] = AESENC(S[13], C[0])
        "vaesenc %%xmm24, %%xmm16, %%xmm16;" // M[0] = AESENC(C[0], M[0])
        "vpxorq %%xmm3, %%xmm16, %%xmm3;" // S[3] = SIMD_XOR(S[3], M[0])
        "vpxorq %%xmm13, %%xmm16, %%xmm13;" // S[13] = SIMD_XOR(S[13], M[0])
        "vmovdqu64 %%xmm16, 0(%0, %%rax);" // Write back M[0] to mi[i+0:i+16]

        // round 2
        "vmovdqu64 16(%1, %%rax), %%xmm25;" // Load C[1] into xmm25
        "vpxorq %%xmm1, %%xmm2, %%xmm17;" // M[1] = SIMD_XOR(S[1], S[2])
        "vpxorq %%xmm25, %%xmm10, %%xmm25;" // C[1] = SIMD_XOR(S[10], C[1])
        "vaesenc %%xmm25, %%xmm14, %%xmm1;" // S[17] = AESENC(S[14], C[1])
        "vaesenc %%xmm25, %%xmm17, %%xmm17;" // M[1] = AESENC(C[1], M[1])
        "vpxorq %%xmm4, %%xmm17, %%xmm4;" // S[4] = SIMD_XOR(S[4], M[1])
        "vpxorq %%xmm14, %%xmm17, %%xmm14;" // S[14] = SIMD_XOR(S[14], M[1])
        "vmovdqu64 %%xmm17, 16(%0, %%rax);" // Write back M[1] to mi[i+16:i+32]

        // round 3
        "vmovdqu64 32(%1, %%rax), %%xmm26;" // Load C[2] into xmm26
        "vpxorq %%xmm2, %%xmm3, %%xmm18;" // M[2] = SIMD_XOR(S[2], S[3])
        "vpxorq %%xmm26, %%xmm11, %%xmm26;" // C[2] = SIMD_XOR(S[11], C[2])
        "vaesenc %%xmm26, %%xmm15, %%xmm2;" // S[18] = AESENC(S[15], C[2])
        "vaesenc %%xmm26, %%xmm18, %%xmm18;" // M[2] = AESENC(C[2], M[2])
        "vpxorq %%xmm5, %%xmm18, %%xmm5;" // S[5] = SIMD_XOR(S[5], M[2])
        "vpxorq %%xmm15, %%xmm18, %%xmm15;" // S[15] = SIMD_XOR(S[15], M[2])
        "vmovdqu64 %%xmm18, 32(%0, %%rax);" // Write back M[2] to mi[i+32:i+48]

        // round 4
        "vmovdqu64 48(%1, %%rax), %%xmm27;" // Load C[3] into xmm27
        "vpxorq %%xmm3, %%xmm4, %%xmm19;" // M[3] = SIMD_XOR(S[3], S[4])
        "vpxorq %%xmm27, %%xmm12, %%xmm27;" // C[3] = SIMD_XOR(S[12], C[3])
        "vaesenc %%xmm27, %%xmm0, %%xmm3;" // S[19] = AESENC(S[16], C[3])
        "vaesenc %%xmm27, %%xmm19, %%xmm19;" // M[3] = AESENC(C[3], M[3])
        "vpxorq %%xmm6, %%xmm19, %%xmm6;" // S[6] = SIMD_XOR(S[6], M[3])
        "vpxorq %%xmm0, %%xmm19, %%xmm0;" // S[16] = SIMD_XOR(S[16], M[3])
        "vmovdqu64 %%xmm19, 48(%0, %%rax);" // Write back M[3] to mi[i+48:i+64]

        // round 5
        "vmovdqu64 64(%1, %%rax), %%xmm28;" // Load C[4] into xmm28
        "vpxorq %%xmm4, %%xmm5, %%xmm20;" // M[4] = SIMD_XOR(S[4], S[5])
        "vpxorq %%xmm28, %%xmm13, %%xmm28;" // C[4] = SIMD_XOR(S[13], C[4])
        "vaesenc %%xmm28, %%xmm1, %%xmm4;" // S[20] = AESENC(S[17], C[4])
        "vaesenc %%xmm28, %%xmm20, %%xmm20;" // M[4] = AESENC(C[4], M[4])
        "vpxorq %%xmm7, %%xmm20, %%xmm7;" // S[7] = SIMD_XOR(S[7], M[4])
        "vpxorq %%xmm1, %%xmm20, %%xmm1;" // S[17] = SIMD_XOR(S[17], M[4])
        "vmovdqu64 %%xmm20, 64(%0, %%rax);" // Write back M[4] to mi[i+64:i+80]

        // round 6
        "vmovdqu64 80(%1, %%rax), %%xmm29;" // Load C[5] into xmm29
        "vpxorq %%xmm5, %%xmm6, %%xmm21;" // M[5] = SIMD_XOR(S[5], S[6])
        "vpxorq %%xmm29, %%xmm14, %%xmm29;" // C[5] = SIMD_XOR(S[14], C[5])
        "vaesenc %%xmm29, %%xmm2, %%xmm5;" // S[21] = AESENC(S[18], C[5])
        "vaesenc %%xmm29, %%xmm21, %%xmm21;" // M[5] = AESENC(C[5], M[5])
        "vpxorq %%xmm8, %%xmm21, %%xmm8;" // S[8] = SIMD_XOR(S[8], M[5])
        "vpxorq %%xmm2, %%xmm21, %%xmm2;" // S[18] = SIMD_XOR(S[18], M[5])
        "vmovdqu64 %%xmm21, 80(%0, %%rax);" // Write back M[5] to mi[i+80:i+96]

        // round 7
        "vmovdqu64 96(%1, %%rax), %%xmm30;" // Load C[6] into xmm30
        "vpxorq %%xmm6, %%xmm7, %%xmm22;" // M[6] = SIMD_XOR(S[6], S[7])
        "vpxorq %%xmm30, %%xmm15, %%xmm30;" // C[6] = SIMD_XOR(S[15], C[6])
        "vaesenc %%xmm30, %%xmm3, %%xmm6;" // S[22] = AESENC(S[19], C[6])
        "vaesenc %%xmm30, %%xmm22, %%xmm22;" // M[6] = AESENC(C[6], M[6])
        "vpxorq %%xmm9, %%xmm22, %%xmm9;" // S[9] = SIMD_XOR(S[9], M[6])
        "vpxorq %%xmm3, %%xmm22, %%xmm3;" // S[19] = SIMD_XOR(S[19], M[6])
        "vmovdqu64 %%xmm22, 96(%0, %%rax);" // Write back M[6] to mi[i+96:i+112]

        // round 8
        "vmovdqu64 112(%1, %%rax), %%xmm31;" // Load C[7] into xmm31
        "vpxorq %%xmm7, %%xmm8, %%xmm23;" // M[7] = SIMD_XOR(S[7], S[8])
        "vpxorq %%xmm31, %%xmm0, %%xmm31;" // C[7] = SIMD_XOR(S[16], C[7])
        "vaesenc %%xmm31, %%xmm4, %%xmm7;" // S[23] = AESENC(S[20], C[7])
        "vaesenc %%xmm31, %%xmm23, %%xmm23;" // M[7] = AESENC(C[7], M[7])
        "vpxorq %%xmm10, %%xmm23, %%xmm10;" // S[10] = SIMD_XOR(S[10], M[7])
        "vpxorq %%xmm4, %%xmm23, %%xmm4;" // S[20] = SIMD_XOR(S[20], M[7])
        "vmovdqu64 %%xmm23, 112(%0, %%rax);" // Write back M[7] to mi[i+112:i+128]

        // round 9
        "vmovdqu64 128(%1, %%rax), %%xmm24;" // Load C[8] into xmm24
        "vpxorq %%xmm8, %%xmm9, %%xmm16;" // M[8] = SIMD_XOR(S[8], S[9])
        "vpxorq %%xmm24, %%xmm1, %%xmm24;" // C[8] = SIMD_XOR(S[17], C[8])
        "vaesenc %%xmm24, %%xmm5, %%xmm8;" // S[24] = AESENC(S[21], C[8])
        "vaesenc %%xmm24, %%xmm16, %%xmm16;" // M[8] = AESENC(C[8], M[8])
        "vpxorq %%xmm11, %%xmm16, %%xmm11;" // S[11] = SIMD_XOR(S[11], M[8])
        "vpxorq %%xmm5, %%xmm16, %%xmm5;" // S[21] = SIMD_XOR(S[21], M[8])
        "vmovdqu64 %%xmm16, 128(%0, %%rax);" // Write back M[8] to mi[i+128:i+144]

        // round 10
        "vmovdqu64 144(%1, %%rax), %%xmm25;" // Load C[9] into xmm25
        "vpxorq %%xmm9, %%xmm10, %%xmm17;" // M[9] = SIMD_XOR(S[9], S[10])
        "vpxorq %%xmm25, %%xmm2, %%xmm25;" // C[9] = SIMD_XOR(S[18], C[9])
        "vaesenc %%xmm25, %%xmm6, %%xmm9;" // S[25] = AESENC(S[22], C[9])
        "vaesenc %%xmm25, %%xmm17, %%xmm17;" // M[9] = AESENC(C[9], M[9])
        "vpxorq %%xmm12, %%xmm17, %%xmm12;" // S[12] = SIMD_XOR(S[12], M[9])
        "vpxorq %%xmm6, %%xmm17, %%xmm6;" // S[22] = SIMD_XOR(S[22], M[9])
        "vmovdqu64 %%xmm17, 144(%0, %%rax);" // Write back M[9] to mi[i+144:i+160]

        // round 11
        "vmovdqu64 160(%1, %%rax), %%xmm26;" // Load C[10] into xmm26
        "vpxorq %%xmm10, %%xmm11, %%xmm18;" // M[10] = SIMD_XOR(S[10], S[11])
        "vpxorq %%xmm26, %%xmm3, %%xmm26;" // C[10] = SIMD_XOR(S[19], C[10])
        "vaesenc %%xmm26, %%xmm7, %%xmm10;" // S[26] = AESENC(S[23], C[10])
        "vaesenc %%xmm26, %%xmm18, %%xmm18;" // M[10] = AESENC(C[10], M[10])
        "vpxorq %%xmm13, %%xmm18, %%xmm13;" // S[13] = SIMD_XOR(S[13], M[10])
        "vpxorq %%xmm7, %%xmm18, %%xmm7;" // S[23] = SIMD_XOR(S[23], M[10])
        "vmovdqu64 %%xmm18, 160(%0, %%rax);" // Write back M[10] to mi[i+160:i+176]

        // round 12
        "vmovdqu64 176(%1, %%rax), %%xmm27;" // Load C[11] into xmm27
        "vpxorq %%xmm11, %%xmm12, %%xmm19;" // M[11] = SIMD_XOR(S[11], S[12])
        "vpxorq %%xmm27, %%xmm4, %%xmm27;" // C[11] = SIMD_XOR(S[20], C[11])
        "vaesenc %%xmm27, %%xmm8, %%xmm11;" // S[27] = AESENC(S[24], C[11])
        "vaesenc %%xmm27, %%xmm19, %%xmm19;" // M[11] = AESENC(C[11], M[11])
        "vpxorq %%xmm14, %%xmm19, %%xmm14;" // S[14] = SIMD_XOR(S[14], M[11])
        "vpxorq %%xmm8, %%xmm19, %%xmm8;" // S[24] = SIMD_XOR(S[24], M[11])
        "vmovdqu64 %%xmm19, 176(%0, %%rax);" // Write back M[11] to mi[i+176:i+192]

        // round 13
        "vmovdqu64 192(%1, %%rax), %%xmm28;" // Load C[12] into xmm28
        "vpxorq %%xmm12, %%xmm13, %%xmm20;" // M[12] = SIMD_XOR(S[12], S[13])
        "vpxorq %%xmm28, %%xmm5, %%xmm28;" // C[12] = SIMD_XOR(S[21], C[12])
        "vaesenc %%xmm28, %%xmm9, %%xmm12;" // S[28] = AESENC(S[25], C[12])
        "vaesenc %%xmm28, %%xmm20, %%xmm20;" // M[12] = AESENC(C[12], M[12])
        "vpxorq %%xmm15, %%xmm20, %%xmm15;" // S[15] = SIMD_XOR(S[15], M[12])
        "vpxorq %%xmm9, %%xmm20, %%xmm9;" // S[25] = SIMD_XOR(S[25], M[12])
        "vmovdqu64 %%xmm20, 192(%0, %%rax);" // Write back M[12] to mi[i+192:i+208]

        // round 14
        "vmovdqu64 208(%1, %%rax), %%xmm29;" // Load C[13] into xmm29
        "vpxorq %%xmm13, %%xmm14, %%xmm21;" // M[13] = SIMD_XOR(S[13], S[14])
        "vpxorq %%xmm29, %%xmm6, %%xmm29;" // C[13] = SIMD_XOR(S[22], C[13])
        "vaesenc %%xmm29, %%xmm10, %%xmm13;" // S[29] = AESENC(S[26], C[13])
        "vaesenc %%xmm29, %%xmm21, %%xmm21;" // M[13] = AESENC(C[13], M[13])
        "vpxorq %%xmm0, %%xmm21, %%xmm0;" // S[16] = SIMD_XOR(S[16], M[13])
        "vpxorq %%xmm10, %%xmm21, %%xmm10;" // S[26] = SIMD_XOR(S[26], M[13])
        "vmovdqu64 %%xmm21, 208(%0, %%rax);" // Write back M[13] to mi[i+208:i+224]

        // round 15
        "vmovdqu64 224(%1, %%rax), %%xmm30;" // Load C[14] into xmm30
        "vpxorq %%xmm14, %%xmm15, %%xmm22;" // M[14] = SIMD_XOR(S[14], S[15])
        "vpxorq %%xmm30, %%xmm7, %%xmm30;" // C[14] = SIMD_XOR(S[23], C[14])
        "vaesenc %%xmm30, %%xmm11, %%xmm14;" // S[30] = AESENC(S[27], C[14])
        "vaesenc %%xmm30, %%xmm22, %%xmm22;" // M[14] = AESENC(C[14], M[14])
        "vpxorq %%xmm1, %%xmm22, %%xmm1;" // S[17] = SIMD_XOR(S[17], M[14])
        "vpxorq %%xmm11, %%xmm22, %%xmm11;" // S[27] = SIMD_XOR(S[27], M[14])
        "vmovdqu64 %%xmm22, 224(%0, %%rax);" // Write back M[14] to mi[i+224:i+240]

        // round 16
        "vmovdqu64 240(%1, %%rax), %%xmm31;" // Load C[15] into xmm31
        "vpxorq %%xmm15, %%xmm0, %%xmm23;" // M[15] = SIMD_XOR(S[15], S[16])
        "vpxorq %%xmm31, %%xmm8, %%xmm31;" // C[15] = SIMD_XOR(S[24], C[15])
        "vaesenc %%xmm31, %%xmm12, %%xmm15;" // S[31] = AESENC(S[28], C[15])
        "vaesenc %%xmm31, %%xmm23, %%xmm23;" // M[15] = AESENC(C[15], M[15])
        "vpxorq %%xmm2, %%xmm23, %%xmm2;" // S[18] = SIMD_XOR(S[18], M[15])
        "vpxorq %%xmm12, %%xmm23, %%xmm12;" // S[28] = SIMD_XOR(S[28], M[15])
        "vmovdqu64 %%xmm23, 240(%0, %%rax);" // Write back M[15] to mi[i+240:i+256]

        "addq $256, %%rax;" // i += 256
        "jmp 1b;" // Loop back

        "2:;" // Loop end

        // Write back state
        "vmovdqa64 %%xmm0, (%3);"
        "vmovdqa64 %%xmm1, 16(%3);"
        "vmovdqa64 %%xmm2, 32(%3);"
        "vmovdqa64 %%xmm3, 48(%3);"
        "vmovdqa64 %%xmm4, 64(%3);"
        "vmovdqa64 %%xmm5, 80(%3);"
        "vmovdqa64 %%xmm6, 96(%3);"
        "vmovdqa64 %%xmm7, 112(%3);"
        "vmovdqa64 %%xmm8, 128(%3);"
        "vmovdqa64 %%xmm9, 144(%3);"
        "vmovdqa64 %%xmm10, 160(%3);"
        "vmovdqa64 %%xmm11, 176(%3);"
        "vmovdqa64 %%xmm12, 192(%3);"
        "vmovdqa64 %%xmm13, 208(%3);"
        "vmovdqa64 %%xmm14, 224(%3);"
        "vmovdqa64 %%xmm15, 240(%3);"

        :
        : "r"(mi), "r"(ci), "r"(prefix), "r"(state) // input mi, ci, prefix, state
        : "%rax", "%xmm0", "%xmm1", "%xmm2", "%xmm3", "%xmm4", "%xmm5", "%xmm6", "%xmm7", "%xmm8",
          "%xmm9", "%xmm10", "%xmm11", "%xmm12", "%xmm13", "%xmm14", "%xmm15", "%xmm16", "%xmm17",
          "%xmm18", "%xmm19", "%xmm20", "%xmm21", "%xmm22", "%xmm23", "%xmm24", "%xmm25", "%xmm26",
          "%xmm27", "%xmm28", "%xmm29", "%xmm30", "%xmm31", "memory");

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
        C[0] = _mm_and_si128(C[0], M[0]);
        update_state_offset(state, tmp, C[0], 0);
        state_shift(state);
        SIMD_STORE(buf, C[0]);
        memcpy(mi + rest + prefix, buf, pad);
    }
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAE_enc_partial_noupdate_vaes(HiAE_state_t  *state_opaque,
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
HiAE_dec_partial_noupdate_vaes(HiAE_state_t  *state_opaque,
                               uint8_t       *mi,
                               const uint8_t *ci,
                               size_t         size)
{
    if (size == 0)
        return;

    DATA128b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));

    DATA128b M[1], C[1], tmp[STATE];
    uint8_t  buf[BLOCK_SIZE];
    uint8_t  mask[BLOCK_SIZE];

    memcpy(buf, ci, size);
    memset(mask, 0xff, size);
    memset(mask + size, 0x00, BLOCK_SIZE - size);
    C[0] = SIMD_LOAD(buf);
    M[0] = SIMD_LOAD(mask);
    C[0] = keystream_block(state, tmp, C[0], 0);
    C[0] = _mm_and_si128(C[0], M[0]);
    SIMD_STORE(buf, C[0]);
    memcpy(mi, buf, size);
}

static int
HiAE_encrypt_vaes(const uint8_t *key,
                  const uint8_t *nonce,
                  const uint8_t *msg,
                  uint8_t       *ct,
                  size_t         msg_len,
                  const uint8_t *ad,
                  size_t         ad_len,
                  uint8_t       *tag)
{
    HiAE_state_t state;
    HiAE_init_vaes(&state, key, nonce);
    HiAE_absorb_vaes(&state, ad, ad_len);
    HiAE_enc_vaes(&state, ct, msg, msg_len);
    HiAE_finalize_vaes(&state, ad_len, msg_len, tag);

    return 0;
}

static int
HiAE_decrypt_vaes(const uint8_t *key,
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
    HiAE_init_vaes(&state, key, nonce);
    HiAE_absorb_vaes(&state, ad, ad_len);
    HiAE_dec_vaes(&state, msg, ct, ct_len);
    HiAE_finalize_vaes(&state, ad_len, ct_len, computed_tag);

    return hiae_constant_time_compare(computed_tag, tag, HIAE_MACBYTES);
}

static int
HiAE_mac_vaes(const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len,
              uint8_t *tag)
{
    HiAE_state_t state;
    HiAE_init_vaes(&state, key, nonce);
    HiAE_absorb_vaes(&state, data, data_len);
    HiAE_finalize_vaes(&state, data_len, 0, tag);

    return 0;
}

const HiAE_impl_t hiae_vaes_avx512_impl = { .name                 = "VAES+AVX512",
                                            .init                 = HiAE_init_vaes,
                                            .absorb               = HiAE_absorb_vaes,
                                            .finalize             = HiAE_finalize_vaes,
                                            .enc                  = HiAE_enc_vaes,
                                            .dec                  = HiAE_dec_vaes,
                                            .enc_partial_noupdate = HiAE_enc_partial_noupdate_vaes,
                                            .dec_partial_noupdate = HiAE_dec_partial_noupdate_vaes,
                                            .encrypt              = HiAE_encrypt_vaes,
                                            .decrypt              = HiAE_decrypt_vaes,
                                            .mac                  = HiAE_mac_vaes };

#    ifdef __clang__
#        pragma clang attribute pop
#    endif

#else
// VAES+AVX512 not available, provide stub implementation
const HiAE_impl_t hiae_vaes_avx512_impl = { .name                 = NULL,
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
