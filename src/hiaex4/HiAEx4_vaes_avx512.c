#include "HiAEx4.h"
#include "HiAEx4_internal.h"

#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)

#    ifdef __clang__
#        if __clang_major__ >= 18 && __clang_major__ < 22
#            pragma clang attribute push( \
                __attribute__((target("aes,vaes,avx512f,avx512vl,evex512"))), apply_to = function)
#        else
#            pragma clang attribute push(__attribute__((target("aes,vaes,avx512f,avx512vl"))), \
                                         apply_to = function)
#        endif
#    elif defined(__GNUC__)
// The code doesn't need avx512vl, but without it GCC only uses half of the vector registers for AES and the loops end up shuffling data around. Every CPU with VAES and AVX-512 has it anyway.
#        pragma GCC target("aes,vaes,avx512f,avx512vl")
#    endif

#    include <immintrin.h>

// The state is kept in 16 separate variables rather than an array, so that compilers keep it in registers. Instead of shifting the state after every block, the code just uses the variables in a different order, and the order repeats every 16 blocks.
//
// Each state word gets XORed with two message blocks at different times. The bulk loops apply both at once, later than the reference code does, which saves an operation per block. That means holding on to the last few message blocks, in registers since in-place encryption overwrites them in memory. When a loop ends, whatever is still pending gets applied, so the state matches the reference code again.

typedef __m512i DATA512b;

#    define SIMD_LOAD(x)        _mm512_loadu_si512((const void *) (x))
#    define SIMD_LOADx4(x)      _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *) (x)))
#    define SIMD_STORE(x, y)    _mm512_storeu_si512((void *) (x), (y))
#    define SIMD_STORE128(x, y) _mm_storeu_si128((__m128i *) (x), (y))
#    define SIMD_XOR(x, y)      _mm512_xor_si512((x), (y))
#    define SIMD_XOR3(x, y, z)  _mm512_ternarylogic_epi64((x), (y), (z), 0x96)
#    define SIMD_AND(x, y)      _mm512_and_si512((x), (y))
#    define SIMD_ZERO_512()     _mm512_setzero_si512()
#    define SIMD_FOLD(x)                                                           \
        _mm_xor_si128(_mm512_castsi512_si128(x),                                   \
                      _mm_xor_si128(_mm512_extracti32x4_epi32(x, 1),               \
                                    _mm_xor_si128(_mm512_extracti32x4_epi32(x, 2), \
                                                  _mm512_extracti32x4_epi32(x, 3))))
#    define AESENC(x, y) _mm512_aesenc_epi128((x), (y))

// Keeps GCC from mixing consecutive steps together, which makes it run out of registers. clang doesn't need it.
#    if defined(__GNUC__) && !defined(__clang__)
#        define STEP_BARRIER(a, b, c) __asm__("" : "+v"(a), "+v"(b), "+v"(c))
#        define STEP_BARRIER5(a, b, c, d, e) \
            __asm__("" : "+v"(a), "+v"(b), "+v"(c), "+v"(d), "+v"(e))
#    else
#        define STEP_BARRIER(a, b, c)        (void) 0
#        define STEP_BARRIER5(a, b, c, d, e) (void) 0
#    endif

// a ^ b ^ c, for when a is the input that arrives last. On Zen 4 the three-way XOR is a cycle faster if that input is the one it overwrites, and compilers would otherwise pick the operand order themselves.
static inline DATA512b
xor3_fast(DATA512b a, const DATA512b b, const DATA512b c)
{
#    if defined(__GNUC__) || defined(__clang__)
    __asm__("vpternlogq $0x96, %2, %1, %0" : "+v"(a) : "v"(b), "v"(c));
    return a;
#    else
    return SIMD_XOR3(a, b, c);
#    endif
}

#    define STATE_DECL DATA512b s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15

#    define STATE_LOAD(p)                                        \
        do {                                                     \
            const uint8_t *const sp_ = (p);                      \
            s0                       = SIMD_LOAD(sp_ + 64 * 0);  \
            s1                       = SIMD_LOAD(sp_ + 64 * 1);  \
            s2                       = SIMD_LOAD(sp_ + 64 * 2);  \
            s3                       = SIMD_LOAD(sp_ + 64 * 3);  \
            s4                       = SIMD_LOAD(sp_ + 64 * 4);  \
            s5                       = SIMD_LOAD(sp_ + 64 * 5);  \
            s6                       = SIMD_LOAD(sp_ + 64 * 6);  \
            s7                       = SIMD_LOAD(sp_ + 64 * 7);  \
            s8                       = SIMD_LOAD(sp_ + 64 * 8);  \
            s9                       = SIMD_LOAD(sp_ + 64 * 9);  \
            s10                      = SIMD_LOAD(sp_ + 64 * 10); \
            s11                      = SIMD_LOAD(sp_ + 64 * 11); \
            s12                      = SIMD_LOAD(sp_ + 64 * 12); \
            s13                      = SIMD_LOAD(sp_ + 64 * 13); \
            s14                      = SIMD_LOAD(sp_ + 64 * 14); \
            s15                      = SIMD_LOAD(sp_ + 64 * 15); \
        } while (0)

#    define STATE_STORE(p)                  \
        do {                                \
            uint8_t *const sp_ = (p);       \
            SIMD_STORE(sp_ + 64 * 0, s0);   \
            SIMD_STORE(sp_ + 64 * 1, s1);   \
            SIMD_STORE(sp_ + 64 * 2, s2);   \
            SIMD_STORE(sp_ + 64 * 3, s3);   \
            SIMD_STORE(sp_ + 64 * 4, s4);   \
            SIMD_STORE(sp_ + 64 * 5, s5);   \
            SIMD_STORE(sp_ + 64 * 6, s6);   \
            SIMD_STORE(sp_ + 64 * 7, s7);   \
            SIMD_STORE(sp_ + 64 * 8, s8);   \
            SIMD_STORE(sp_ + 64 * 9, s9);   \
            SIMD_STORE(sp_ + 64 * 10, s10); \
            SIMD_STORE(sp_ + 64 * 11, s11); \
            SIMD_STORE(sp_ + 64 * 12, s12); \
            SIMD_STORE(sp_ + 64 * 13, s13); \
            SIMD_STORE(sp_ + 64 * 14, s14); \
            SIMD_STORE(sp_ + 64 * 15, s15); \
        } while (0)

#    define STATE_FOLD()                                                                         \
        SIMD_XOR(SIMD_XOR3(SIMD_XOR3(s0, s1, s2), SIMD_XOR3(s3, s4, s5), SIMD_XOR3(s6, s7, s8)), \
                 SIMD_XOR3(SIMD_XOR3(s9, s10, s11), SIMD_XOR3(s12, s13, s14), s15))

// What each of the 16 steps of a chunk works on: its state words, its message block, and the blocks from 4 and 10 steps earlier (h0..h9 are the last blocks of the previous chunk).
#    define ROUNDS16(F)                            \
        F(0, s0, s1, s3, s9, s13, m0, h6, h0)      \
        F(1, s1, s2, s4, s10, s14, m1, h7, h1)     \
        F(2, s2, s3, s5, s11, s15, m2, h8, h2)     \
        F(3, s3, s4, s6, s12, s0, m3, h9, h3)      \
        F(4, s4, s5, s7, s13, s1, m4, m0, h4)      \
        F(5, s5, s6, s8, s14, s2, m5, m1, h5)      \
        F(6, s6, s7, s9, s15, s3, m6, m2, h6)      \
        F(7, s7, s8, s10, s0, s4, m7, m3, h7)      \
        F(8, s8, s9, s11, s1, s5, m8, m4, h8)      \
        F(9, s9, s10, s12, s2, s6, m9, m5, h9)     \
        F(10, s10, s11, s13, s3, s7, m10, m6, m0)  \
        F(11, s11, s12, s14, s4, s8, m11, m7, m1)  \
        F(12, s12, s13, s15, s5, s9, m12, m8, m2)  \
        F(13, s13, s14, s0, s6, s10, m13, m9, m3)  \
        F(14, s14, s15, s1, s7, s11, m14, m10, m4) \
        F(15, s15, s0, s2, s8, s12, m15, m11, m5)

#    define HISTORY_DECL                                                                     \
        DATA512b h0 = SIMD_ZERO_512(), h1 = h0, h2 = h0, h3 = h0, h4 = h0, h5 = h0, h6 = h0, \
                 h7 = h0, h8 = h0, h9 = h0

#    define CHUNK_DECL DATA512b m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15

#    define HISTORY_CARRY() \
        do {                \
            h0 = m6;        \
            h1 = m7;        \
            h2 = m8;        \
            h3 = m9;        \
            h4 = m10;       \
            h5 = m11;       \
            h6 = m12;       \
            h7 = m13;       \
            h8 = m14;       \
            h9 = m15;       \
        } while (0)

// Applies the message blocks that are still pending when a bulk loop ends.
#    define HISTORY_APPLY()          \
        do {                         \
            s3  = SIMD_XOR(s3, h0);  \
            s4  = SIMD_XOR(s4, h1);  \
            s5  = SIMD_XOR(s5, h2);  \
            s6  = SIMD_XOR(s6, h3);  \
            s7  = SIMD_XOR(s7, h4);  \
            s8  = SIMD_XOR(s8, h5);  \
            s9  = SIMD_XOR(s9, h6);  \
            s10 = SIMD_XOR(s10, h7); \
            s11 = SIMD_XOR(s11, h8); \
            s12 = SIMD_XOR(s12, h9); \
        } while (0)

#    define AD_STEP(i, S0, S1, S3, S9, S13, Mi, Mi4, Mi10) \
        Mi = SIMD_LOAD(ad + 64 * (i));                     \
        S0 = AESENC(S13, AESENC(SIMD_XOR(S0, S1), Mi));    \
        S3 = SIMD_XOR3(S3, Mi10, Mi);                      \
        STEP_BARRIER(S0, S3, Mi);

#    define ENC_STEP(i, S0, S1, S3, S9, S13, Mi, Mi4, Mi10)    \
        Mi = SIMD_LOAD(mi + 64 * (i));                         \
        {                                                      \
            const DATA512b t_ = AESENC(SIMD_XOR(S0, S1), Mi);  \
            S0                = AESENC(S13, t_);               \
            SIMD_STORE(ci + 64 * (i), SIMD_XOR3(t_, S9, Mi4)); \
        }                                                      \
        S3 = SIMD_XOR3(S3, Mi10, Mi);                          \
        STEP_BARRIER(S0, S3, Mi);

// Decryption is limited by latency rather than throughput, since every decrypted block is needed to decrypt the block two steps later. This loop splits the pending XORs differently from the others, so that a single three-way XOR sits between a decrypted block and the AES round that needs it. It costs an extra XOR per block, and the next two AES inputs are carried over from one chunk to the next (xa, xb).
#    define DEC_ROUNDS16(F)                                      \
        F(0, s0, s2, s3, s4, s9, s13, m0, h6, h1, xa, x2)        \
        F(1, s1, s3, s4, s5, s10, s14, m1, h7, h2, xb, x3)       \
        F(2, s2, s4, s5, s6, s11, s15, m2, h8, h3, x2, x4)       \
        F(3, s3, s5, s6, s7, s12, s0, m3, h9, h4, x3, x5)        \
        F(4, s4, s6, s7, s8, s13, s1, m4, m0, h5, x4, x6)        \
        F(5, s5, s7, s8, s9, s14, s2, m5, m1, h6, x5, x7)        \
        F(6, s6, s8, s9, s10, s15, s3, m6, m2, h7, x6, x8)       \
        F(7, s7, s9, s10, s11, s0, s4, m7, m3, h8, x7, x9)       \
        F(8, s8, s10, s11, s12, s1, s5, m8, m4, h9, x8, x10)     \
        F(9, s9, s11, s12, s13, s2, s6, m9, m5, m0, x9, x11)     \
        F(10, s10, s12, s13, s14, s3, s7, m10, m6, m1, x10, x12) \
        F(11, s11, s13, s14, s15, s4, s8, m11, m7, m2, x11, x13) \
        F(12, s12, s14, s15, s0, s5, s9, m12, m8, m3, x12, x14)  \
        F(13, s13, s15, s0, s1, s6, s10, m13, m9, m4, x13, x15)  \
        F(14, s14, s0, s1, s2, s7, s11, m14, m10, m5, x14, xa)   \
        F(15, s15, s1, s2, s3, s8, s12, m15, m11, m6, x15, xb)

#    define DEC_STEP(j, S0, S2, S3, S4, S9, S13, Mj, Mj4, Mj9, Xj, Xj2)       \
        {                                                                     \
            const DATA512b t_ = SIMD_XOR3(SIMD_LOAD(ci + 64 * (j)), S9, Mj4); \
            Mj                = AESENC(Xj, t_);                               \
            Xj2               = xor3_fast(Mj, S2, S3);                        \
            S3                = SIMD_XOR(S3, Mj);                             \
            S0                = AESENC(S13, t_);                              \
            SIMD_STORE(mi + 64 * (j), Mj);                                    \
        }                                                                     \
        S4 = SIMD_XOR(S4, Mj9);                                               \
        STEP_BARRIER5(S0, S3, S4, Mj, Xj2);

#    define DEC_CHUNK_DECL DATA512b x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15

#    define DEC_HISTORY_CARRY() \
        do {                    \
            h1 = m7;            \
            h2 = m8;            \
            h3 = m9;            \
            h4 = m10;           \
            h5 = m11;           \
            h6 = m12;           \
            h7 = m13;           \
            h8 = m14;           \
            h9 = m15;           \
        } while (0)

// Applies the message blocks that are still pending when the decryption loop ends.
#    define DEC_HISTORY_APPLY()      \
        do {                         \
            s4  = SIMD_XOR(s4, h1);  \
            s5  = SIMD_XOR(s5, h2);  \
            s6  = SIMD_XOR(s6, h3);  \
            s7  = SIMD_XOR(s7, h4);  \
            s8  = SIMD_XOR(s8, h5);  \
            s9  = SIMD_XOR(s9, h6);  \
            s10 = SIMD_XOR(s10, h7); \
            s11 = SIMD_XOR(s11, h8); \
            s12 = SIMD_XOR(s12, h9); \
        } while (0)

// Plain steps, as in the reference code, for the blocks left over after a bulk loop.

#    define UPDATE(S0, S1, S3, S13, M)                         \
        do {                                                   \
            const DATA512b t_ = AESENC(SIMD_XOR(S0, S1), (M)); \
            S0                = AESENC(S13, t_);               \
            S3                = SIMD_XOR(S3, (M));             \
            S13               = SIMD_XOR(S13, (M));            \
        } while (0)

#    define ENC(S0, S1, S3, S9, S13, M, C)                     \
        do {                                                   \
            const DATA512b t_ = AESENC(SIMD_XOR(S0, S1), (M)); \
            (C)               = SIMD_XOR(t_, S9);              \
            S0                = AESENC(S13, t_);               \
            S3                = SIMD_XOR(S3, (M));             \
            S13               = SIMD_XOR(S13, (M));            \
        } while (0)

#    define DEC(S0, S1, S3, S9, S13, C, M)                    \
        do {                                                  \
            const DATA512b t_ = SIMD_XOR((C), S9);            \
            (M)               = AESENC(SIMD_XOR(S0, S1), t_); \
            S0                = AESENC(S13, t_);              \
            S3                = SIMD_XOR(S3, (M));            \
            S13               = SIMD_XOR(S13, (M));           \
        } while (0)

// The last, partial block when decrypting: only the actual plaintext bytes, padded with zeros, go into the state.
#    define DEC_LAST(S0, S1, S3, S9, S13, C, MASK, M)                            \
        do {                                                                     \
            const DATA512b x_ = SIMD_XOR(S0, S1);                                \
            (M)               = SIMD_AND(SIMD_XOR(AESENC(x_, (C)), S9), (MASK)); \
            S0                = AESENC(S13, AESENC(x_, (M)));                    \
            S3                = SIMD_XOR(S3, (M));                               \
            S13               = SIMD_XOR(S13, (M));                              \
        } while (0)

// Handles what's left after a bulk loop, and counts the steps so that the state can be put back in order afterwards.

#    define AD_TAIL(i, S0, S1, S3, S9, S13, Mi, Mi4, Mi10) \
        if ((i) == nfull) {                                \
            if (pad != 0) {                                \
                const DATA512b m_ = SIMD_LOAD(pbuf);       \
                UPDATE(S0, S1, S3, S13, m_);               \
                r = (i) + 1;                               \
            } else {                                       \
                r = (i);                                   \
            }                                              \
            goto done;                                     \
        }                                                  \
        {                                                  \
            const DATA512b m_ = SIMD_LOAD(ad + 64 * (i));  \
            UPDATE(S0, S1, S3, S13, m_);                   \
        }

#    define ENC_TAIL(i, S0, S1, S3, S9, S13, Mi, Mi4, Mi10) \
        if ((i) == nfull) {                                 \
            if (pad != 0) {                                 \
                const DATA512b m_ = SIMD_LOAD(pbuf);        \
                DATA512b       c_;                          \
                ENC(S0, S1, S3, S9, S13, m_, c_);           \
                SIMD_STORE(pbuf, c_);                       \
                r = (i) + 1;                                \
            } else {                                        \
                r = (i);                                    \
            }                                               \
            goto done;                                      \
        }                                                   \
        {                                                   \
            const DATA512b m_ = SIMD_LOAD(mi + 64 * (i));   \
            DATA512b       c_;                              \
            ENC(S0, S1, S3, S9, S13, m_, c_);               \
            SIMD_STORE(ci + 64 * (i), c_);                  \
        }

#    define DEC_TAIL(i, S0, S1, S3, S9, S13, Mi, Mi4, Mi10) \
        if ((i) == nfull) {                                 \
            if (pad != 0) {                                 \
                const DATA512b c_ = SIMD_LOAD(pbuf);        \
                const DATA512b k_ = SIMD_LOAD(pmask);       \
                DATA512b       m_;                          \
                DEC_LAST(S0, S1, S3, S9, S13, c_, k_, m_);  \
                SIMD_STORE(pbuf, m_);                       \
                r = (i) + 1;                                \
            } else {                                        \
                r = (i);                                    \
            }                                               \
            goto done;                                      \
        }                                                   \
        {                                                   \
            const DATA512b c_ = SIMD_LOAD(ci + 64 * (i));   \
            DATA512b       m_;                              \
            DEC(S0, S1, S3, S9, S13, c_, m_);               \
            SIMD_STORE(mi + 64 * (i), m_);                  \
        }

// The 32 updates of initialization and finalization, where the message block alternates between two fixed values. Most of the pending XORs cancel out because a word gets the same value twice, so only the first and last few are actually done.
#    define CUPD(S0, S1, S13, M) S0 = AESENC(S13, AESENC(SIMD_XOR(S0, S1), (M)))

#    define UPDATE_32_CONST(ME, MO)  \
        do {                         \
            CUPD(s0, s1, s13, ME);   \
            s3 = SIMD_XOR(s3, ME);   \
            CUPD(s1, s2, s14, MO);   \
            s4 = SIMD_XOR(s4, MO);   \
            CUPD(s2, s3, s15, ME);   \
            s5 = SIMD_XOR(s5, ME);   \
            CUPD(s3, s4, s0, MO);    \
            s6 = SIMD_XOR(s6, MO);   \
            CUPD(s4, s5, s1, ME);    \
            s7 = SIMD_XOR(s7, ME);   \
            CUPD(s5, s6, s2, MO);    \
            s8 = SIMD_XOR(s8, MO);   \
            CUPD(s6, s7, s3, ME);    \
            s9 = SIMD_XOR(s9, ME);   \
            CUPD(s7, s8, s4, MO);    \
            s10 = SIMD_XOR(s10, MO); \
            CUPD(s8, s9, s5, ME);    \
            s11 = SIMD_XOR(s11, ME); \
            CUPD(s9, s10, s6, MO);   \
            s12 = SIMD_XOR(s12, MO); \
            CUPD(s10, s11, s7, ME);  \
            CUPD(s11, s12, s8, MO);  \
            CUPD(s12, s13, s9, ME);  \
            CUPD(s13, s14, s10, MO); \
            CUPD(s14, s15, s11, ME); \
            CUPD(s15, s0, s12, MO);  \
                                     \
            CUPD(s0, s1, s13, ME);   \
            CUPD(s1, s2, s14, MO);   \
            CUPD(s2, s3, s15, ME);   \
            CUPD(s3, s4, s0, MO);    \
            CUPD(s4, s5, s1, ME);    \
            CUPD(s5, s6, s2, MO);    \
            CUPD(s6, s7, s3, ME);    \
            CUPD(s7, s8, s4, MO);    \
            CUPD(s8, s9, s5, ME);    \
            CUPD(s9, s10, s6, MO);   \
            CUPD(s10, s11, s7, ME);  \
            CUPD(s11, s12, s8, MO);  \
            CUPD(s12, s13, s9, ME);  \
            CUPD(s13, s14, s10, MO); \
            CUPD(s14, s15, s11, ME); \
            CUPD(s15, s0, s12, MO);  \
                                     \
            s3  = SIMD_XOR(s3, ME);  \
            s4  = SIMD_XOR(s4, MO);  \
            s5  = SIMD_XOR(s5, ME);  \
            s6  = SIMD_XOR(s6, MO);  \
            s7  = SIMD_XOR(s7, ME);  \
            s8  = SIMD_XOR(s8, MO);  \
            s9  = SIMD_XOR(s9, ME);  \
            s10 = SIMD_XOR(s10, MO); \
            s11 = SIMD_XOR(s11, ME); \
            s12 = SIMD_XOR(s12, MO); \
        } while (0)

// Each phase keeps the state in registers. The one-shot functions chain them without ever writing the state to memory, which makes a big difference for short messages, while the low-level API loads and saves the state around each phase.
#    if defined(_MSC_VER) && !defined(__clang__)
#        define HIAE_ALWAYS_INLINE __forceinline
#    else
#        define HIAE_ALWAYS_INLINE inline __attribute__((always_inline))
#    endif

#    define STATE_PARAMS                                                                          \
        DATA512b *const ps0, DATA512b *const ps1, DATA512b *const ps2, DATA512b *const ps3,       \
            DATA512b *const ps4, DATA512b *const ps5, DATA512b *const ps6, DATA512b *const ps7,   \
            DATA512b *const ps8, DATA512b *const ps9, DATA512b *const ps10, DATA512b *const ps11, \
            DATA512b *const ps12, DATA512b *const ps13, DATA512b *const ps14, DATA512b *const ps15

#    define STATE_ARGS \
        &s0, &s1, &s2, &s3, &s4, &s5, &s6, &s7, &s8, &s9, &s10, &s11, &s12, &s13, &s14, &s15

#    define STATE_IN                                                                          \
        DATA512b s0 = *ps0, s1 = *ps1, s2 = *ps2, s3 = *ps3, s4 = *ps4, s5 = *ps5, s6 = *ps6, \
                 s7 = *ps7, s8 = *ps8, s9 = *ps9, s10 = *ps10, s11 = *ps11, s12 = *ps12,      \
                 s13 = *ps13, s14 = *ps14, s15 = *ps15

#    define STATE_OUT()  \
        do {             \
            *ps0  = s0;  \
            *ps1  = s1;  \
            *ps2  = s2;  \
            *ps3  = s3;  \
            *ps4  = s4;  \
            *ps5  = s5;  \
            *ps6  = s6;  \
            *ps7  = s7;  \
            *ps8  = s8;  \
            *ps9  = s9;  \
            *ps10 = s10; \
            *ps11 = s11; \
            *ps12 = s12; \
            *ps13 = s13; \
            *ps14 = s14; \
            *ps15 = s15; \
        } while (0)

// Puts the state words back in order after a tail, which can stop at any step. Modern CPUs handle these register copies for free.
#    define STATE_ROTATE(r)                                                                        \
        do {                                                                                       \
            const DATA512b t0 = s0, t1 = s1, t2 = s2, t3 = s3, t4 = s4, t5 = s5, t6 = s6, t7 = s7, \
                           t8 = s8, t9 = s9, t10 = s10, t11 = s11, t12 = s12, t13 = s13,           \
                           t14 = s14, t15 = s15;                                                   \
            switch ((r) & 15) {                                                                    \
            case 0:                                                                                \
                break;                                                                             \
            case 1:                                                                                \
                s0  = t1;                                                                          \
                s1  = t2;                                                                          \
                s2  = t3;                                                                          \
                s3  = t4;                                                                          \
                s4  = t5;                                                                          \
                s5  = t6;                                                                          \
                s6  = t7;                                                                          \
                s7  = t8;                                                                          \
                s8  = t9;                                                                          \
                s9  = t10;                                                                         \
                s10 = t11;                                                                         \
                s11 = t12;                                                                         \
                s12 = t13;                                                                         \
                s13 = t14;                                                                         \
                s14 = t15;                                                                         \
                s15 = t0;                                                                          \
                break;                                                                             \
            case 2:                                                                                \
                s0  = t2;                                                                          \
                s1  = t3;                                                                          \
                s2  = t4;                                                                          \
                s3  = t5;                                                                          \
                s4  = t6;                                                                          \
                s5  = t7;                                                                          \
                s6  = t8;                                                                          \
                s7  = t9;                                                                          \
                s8  = t10;                                                                         \
                s9  = t11;                                                                         \
                s10 = t12;                                                                         \
                s11 = t13;                                                                         \
                s12 = t14;                                                                         \
                s13 = t15;                                                                         \
                s14 = t0;                                                                          \
                s15 = t1;                                                                          \
                break;                                                                             \
            case 3:                                                                                \
                s0  = t3;                                                                          \
                s1  = t4;                                                                          \
                s2  = t5;                                                                          \
                s3  = t6;                                                                          \
                s4  = t7;                                                                          \
                s5  = t8;                                                                          \
                s6  = t9;                                                                          \
                s7  = t10;                                                                         \
                s8  = t11;                                                                         \
                s9  = t12;                                                                         \
                s10 = t13;                                                                         \
                s11 = t14;                                                                         \
                s12 = t15;                                                                         \
                s13 = t0;                                                                          \
                s14 = t1;                                                                          \
                s15 = t2;                                                                          \
                break;                                                                             \
            case 4:                                                                                \
                s0  = t4;                                                                          \
                s1  = t5;                                                                          \
                s2  = t6;                                                                          \
                s3  = t7;                                                                          \
                s4  = t8;                                                                          \
                s5  = t9;                                                                          \
                s6  = t10;                                                                         \
                s7  = t11;                                                                         \
                s8  = t12;                                                                         \
                s9  = t13;                                                                         \
                s10 = t14;                                                                         \
                s11 = t15;                                                                         \
                s12 = t0;                                                                          \
                s13 = t1;                                                                          \
                s14 = t2;                                                                          \
                s15 = t3;                                                                          \
                break;                                                                             \
            case 5:                                                                                \
                s0  = t5;                                                                          \
                s1  = t6;                                                                          \
                s2  = t7;                                                                          \
                s3  = t8;                                                                          \
                s4  = t9;                                                                          \
                s5  = t10;                                                                         \
                s6  = t11;                                                                         \
                s7  = t12;                                                                         \
                s8  = t13;                                                                         \
                s9  = t14;                                                                         \
                s10 = t15;                                                                         \
                s11 = t0;                                                                          \
                s12 = t1;                                                                          \
                s13 = t2;                                                                          \
                s14 = t3;                                                                          \
                s15 = t4;                                                                          \
                break;                                                                             \
            case 6:                                                                                \
                s0  = t6;                                                                          \
                s1  = t7;                                                                          \
                s2  = t8;                                                                          \
                s3  = t9;                                                                          \
                s4  = t10;                                                                         \
                s5  = t11;                                                                         \
                s6  = t12;                                                                         \
                s7  = t13;                                                                         \
                s8  = t14;                                                                         \
                s9  = t15;                                                                         \
                s10 = t0;                                                                          \
                s11 = t1;                                                                          \
                s12 = t2;                                                                          \
                s13 = t3;                                                                          \
                s14 = t4;                                                                          \
                s15 = t5;                                                                          \
                break;                                                                             \
            case 7:                                                                                \
                s0  = t7;                                                                          \
                s1  = t8;                                                                          \
                s2  = t9;                                                                          \
                s3  = t10;                                                                         \
                s4  = t11;                                                                         \
                s5  = t12;                                                                         \
                s6  = t13;                                                                         \
                s7  = t14;                                                                         \
                s8  = t15;                                                                         \
                s9  = t0;                                                                          \
                s10 = t1;                                                                          \
                s11 = t2;                                                                          \
                s12 = t3;                                                                          \
                s13 = t4;                                                                          \
                s14 = t5;                                                                          \
                s15 = t6;                                                                          \
                break;                                                                             \
            case 8:                                                                                \
                s0  = t8;                                                                          \
                s1  = t9;                                                                          \
                s2  = t10;                                                                         \
                s3  = t11;                                                                         \
                s4  = t12;                                                                         \
                s5  = t13;                                                                         \
                s6  = t14;                                                                         \
                s7  = t15;                                                                         \
                s8  = t0;                                                                          \
                s9  = t1;                                                                          \
                s10 = t2;                                                                          \
                s11 = t3;                                                                          \
                s12 = t4;                                                                          \
                s13 = t5;                                                                          \
                s14 = t6;                                                                          \
                s15 = t7;                                                                          \
                break;                                                                             \
            case 9:                                                                                \
                s0  = t9;                                                                          \
                s1  = t10;                                                                         \
                s2  = t11;                                                                         \
                s3  = t12;                                                                         \
                s4  = t13;                                                                         \
                s5  = t14;                                                                         \
                s6  = t15;                                                                         \
                s7  = t0;                                                                          \
                s8  = t1;                                                                          \
                s9  = t2;                                                                          \
                s10 = t3;                                                                          \
                s11 = t4;                                                                          \
                s12 = t5;                                                                          \
                s13 = t6;                                                                          \
                s14 = t7;                                                                          \
                s15 = t8;                                                                          \
                break;                                                                             \
            case 10:                                                                               \
                s0  = t10;                                                                         \
                s1  = t11;                                                                         \
                s2  = t12;                                                                         \
                s3  = t13;                                                                         \
                s4  = t14;                                                                         \
                s5  = t15;                                                                         \
                s6  = t0;                                                                          \
                s7  = t1;                                                                          \
                s8  = t2;                                                                          \
                s9  = t3;                                                                          \
                s10 = t4;                                                                          \
                s11 = t5;                                                                          \
                s12 = t6;                                                                          \
                s13 = t7;                                                                          \
                s14 = t8;                                                                          \
                s15 = t9;                                                                          \
                break;                                                                             \
            case 11:                                                                               \
                s0  = t11;                                                                         \
                s1  = t12;                                                                         \
                s2  = t13;                                                                         \
                s3  = t14;                                                                         \
                s4  = t15;                                                                         \
                s5  = t0;                                                                          \
                s6  = t1;                                                                          \
                s7  = t2;                                                                          \
                s8  = t3;                                                                          \
                s9  = t4;                                                                          \
                s10 = t5;                                                                          \
                s11 = t6;                                                                          \
                s12 = t7;                                                                          \
                s13 = t8;                                                                          \
                s14 = t9;                                                                          \
                s15 = t10;                                                                         \
                break;                                                                             \
            case 12:                                                                               \
                s0  = t12;                                                                         \
                s1  = t13;                                                                         \
                s2  = t14;                                                                         \
                s3  = t15;                                                                         \
                s4  = t0;                                                                          \
                s5  = t1;                                                                          \
                s6  = t2;                                                                          \
                s7  = t3;                                                                          \
                s8  = t4;                                                                          \
                s9  = t5;                                                                          \
                s10 = t6;                                                                          \
                s11 = t7;                                                                          \
                s12 = t8;                                                                          \
                s13 = t9;                                                                          \
                s14 = t10;                                                                         \
                s15 = t11;                                                                         \
                break;                                                                             \
            case 13:                                                                               \
                s0  = t13;                                                                         \
                s1  = t14;                                                                         \
                s2  = t15;                                                                         \
                s3  = t0;                                                                          \
                s4  = t1;                                                                          \
                s5  = t2;                                                                          \
                s6  = t3;                                                                          \
                s7  = t4;                                                                          \
                s8  = t5;                                                                          \
                s9  = t6;                                                                          \
                s10 = t7;                                                                          \
                s11 = t8;                                                                          \
                s12 = t9;                                                                          \
                s13 = t10;                                                                         \
                s14 = t11;                                                                         \
                s15 = t12;                                                                         \
                break;                                                                             \
            case 14:                                                                               \
                s0  = t14;                                                                         \
                s1  = t15;                                                                         \
                s2  = t0;                                                                          \
                s3  = t1;                                                                          \
                s4  = t2;                                                                          \
                s5  = t3;                                                                          \
                s6  = t4;                                                                          \
                s7  = t5;                                                                          \
                s8  = t6;                                                                          \
                s9  = t7;                                                                          \
                s10 = t8;                                                                          \
                s11 = t9;                                                                          \
                s12 = t10;                                                                         \
                s13 = t11;                                                                         \
                s14 = t12;                                                                         \
                s15 = t13;                                                                         \
                break;                                                                             \
            case 15:                                                                               \
                s0  = t15;                                                                         \
                s1  = t0;                                                                          \
                s2  = t1;                                                                          \
                s3  = t2;                                                                          \
                s4  = t3;                                                                          \
                s5  = t4;                                                                          \
                s6  = t5;                                                                          \
                s7  = t6;                                                                          \
                s8  = t7;                                                                          \
                s9  = t8;                                                                          \
                s10 = t9;                                                                          \
                s11 = t10;                                                                         \
                s12 = t11;                                                                         \
                s13 = t12;                                                                         \
                s14 = t13;                                                                         \
                s15 = t14;                                                                         \
                break;                                                                             \
            }                                                                                      \
        } while (0)

static HIAE_ALWAYS_INLINE void
init_regs(STATE_PARAMS, const uint8_t *key, const uint8_t *nonce)
{
    STATE_DECL;
    const DATA512b c0 = SIMD_LOAD(C0);
    const DATA512b c1 = SIMD_LOAD(C1);
    const DATA512b k0 = SIMD_LOADx4(key);
    const DATA512b k1 = SIMD_LOADx4(key + 16);
    const DATA512b N  = SIMD_LOADx4(nonce);
    const DATA512b ze = SIMD_ZERO_512();

    // Makes every lane different: its index and the number of lanes minus one
    const uint8_t degree                = 4;
    uint8_t       ctx_bytes[BLOCK_SIZE] = { 0 };
    for (size_t i = 0; i < degree; i++) {
        ctx_bytes[i * 16 + 0] = (uint8_t) i;
        ctx_bytes[i * 16 + 1] = degree - 1;
    }
    const DATA512b ctx = SIMD_LOAD(ctx_bytes);

    s0  = SIMD_XOR(c0, ctx);
    s1  = SIMD_XOR(k0, ctx);
    s2  = SIMD_XOR(c0, ctx);
    s3  = SIMD_XOR(N, ctx);
    s4  = SIMD_XOR(ze, ctx);
    s5  = SIMD_XOR(k0, ctx);
    s6  = SIMD_XOR(ze, ctx);
    s7  = SIMD_XOR(c1, ctx);
    s8  = SIMD_XOR(k1, ctx);
    s9  = SIMD_XOR(ze, ctx);
    s10 = SIMD_XOR3(N, k1, ctx);
    s11 = SIMD_XOR(c0, ctx);
    s12 = SIMD_XOR(c1, ctx);
    s13 = SIMD_XOR(k1, ctx);
    s14 = SIMD_XOR(ze, ctx);
    s15 = SIMD_XOR3(c0, c1, ctx);

    UPDATE_32_CONST(k0, k1);

    STATE_OUT();
}

static HIAE_ALWAYS_INLINE void
absorb_regs(STATE_PARAMS, const uint8_t *ad, size_t len)
{
    size_t r;

    if (len == 0) {
        return;
    }
    STATE_IN;
    if (len >= UNROLL_BLOCK_SIZE) {
        HISTORY_DECL;
        do {
            CHUNK_DECL;
            ROUNDS16(AD_STEP)
            HISTORY_CARRY();
            ad += UNROLL_BLOCK_SIZE;
            len -= UNROLL_BLOCK_SIZE;
        } while (len >= UNROLL_BLOCK_SIZE);
        HISTORY_APPLY();
    }
    {
        const size_t nfull = len / BLOCK_SIZE;
        const size_t pad   = len % BLOCK_SIZE;
        uint8_t      pbuf[BLOCK_SIZE];

        if (pad != 0) {
            memset(pbuf, 0, sizeof pbuf);
            memcpy(pbuf, ad + nfull * BLOCK_SIZE, pad);
        }
        ROUNDS16(AD_TAIL)
        r = 16; // never reached, there are fewer than 16 blocks left
    done:
        STATE_ROTATE(r);
    }
    STATE_OUT();
}

static HIAE_ALWAYS_INLINE void
enc_regs(STATE_PARAMS, uint8_t *ci, const uint8_t *mi, size_t size)
{
    size_t r;

    if (size == 0) {
        return;
    }
    STATE_IN;
    if (size >= UNROLL_BLOCK_SIZE) {
        HISTORY_DECL;
        do {
            CHUNK_DECL;
            ROUNDS16(ENC_STEP)
            HISTORY_CARRY();
            mi += UNROLL_BLOCK_SIZE;
            ci += UNROLL_BLOCK_SIZE;
            size -= UNROLL_BLOCK_SIZE;
        } while (size >= UNROLL_BLOCK_SIZE);
        HISTORY_APPLY();
    }
    {
        const size_t nfull = size / BLOCK_SIZE;
        const size_t pad   = size % BLOCK_SIZE;
        uint8_t      pbuf[BLOCK_SIZE];

        if (pad != 0) {
            memset(pbuf, 0, sizeof pbuf);
            memcpy(pbuf, mi + nfull * BLOCK_SIZE, pad);
        }
        ROUNDS16(ENC_TAIL)
        r = 16; // never reached, there are fewer than 16 blocks left
    done:
        STATE_ROTATE(r);
        if (pad != 0) {
            memcpy(ci + nfull * BLOCK_SIZE, pbuf, pad);
        }
    }
    STATE_OUT();
}

static HIAE_ALWAYS_INLINE void
dec_regs(STATE_PARAMS, uint8_t *mi, const uint8_t *ci, size_t size)
{
    size_t r;

    if (size == 0) {
        return;
    }
    STATE_IN;
    if (size >= UNROLL_BLOCK_SIZE) {
        HISTORY_DECL;
        DATA512b xa = SIMD_XOR(s0, s1), xb = SIMD_XOR(s1, s2);
        (void) h0;
        do {
            CHUNK_DECL;
            DEC_CHUNK_DECL;
            DEC_ROUNDS16(DEC_STEP)
            DEC_HISTORY_CARRY();
            mi += UNROLL_BLOCK_SIZE;
            ci += UNROLL_BLOCK_SIZE;
            size -= UNROLL_BLOCK_SIZE;
        } while (size >= UNROLL_BLOCK_SIZE);
        DEC_HISTORY_APPLY();
    }
    {
        const size_t nfull = size / BLOCK_SIZE;
        const size_t pad   = size % BLOCK_SIZE;
        uint8_t      pbuf[BLOCK_SIZE];
        uint8_t      pmask[BLOCK_SIZE];

        if (pad != 0) {
            memset(pbuf, 0, sizeof pbuf);
            memcpy(pbuf, ci + nfull * BLOCK_SIZE, pad);
            memset(pmask, 0xff, pad);
            memset(pmask + pad, 0x00, BLOCK_SIZE - pad);
        }
        ROUNDS16(DEC_TAIL)
        r = 16; // never reached, there are fewer than 16 blocks left
    done:
        STATE_ROTATE(r);
        if (pad != 0) {
            memcpy(mi + nfull * BLOCK_SIZE, pbuf, pad);
        }
    }
    STATE_OUT();
}

static HIAE_ALWAYS_INLINE void
finalize_regs(STATE_PARAMS, uint64_t ad_len, uint64_t msg_len, uint8_t *tag)
{
    STATE_IN;
    uint64_t lens[2];

    lens[0]             = ad_len * 8;
    lens[1]             = msg_len * 8;
    const DATA512b temp = SIMD_LOADx4((uint8_t *) lens);
    UPDATE_32_CONST(temp, temp);
    SIMD_STORE128(tag, SIMD_FOLD(STATE_FOLD()));
    STATE_OUT();
}

// Like the regular finalization, but the tags of all lanes are then mixed into a single one.
static HIAE_ALWAYS_INLINE void
finalize_mac_regs(STATE_PARAMS, uint64_t data_len, uint8_t *tag)
{
    STATE_IN;
    const uint8_t degree = 4;
    uint64_t      lens[2];
    uint8_t       tag_multi_bytes[BLOCK_SIZE];
    uint8_t       v_block[BLOCK_SIZE];
    DATA512b      v;

    lens[0]       = data_len * 8;
    lens[1]       = HIAEX4_MACBYTES * 8;
    DATA512b temp = SIMD_LOADx4((uint8_t *) lens);
    UPDATE_32_CONST(temp, temp);

    SIMD_STORE(tag_multi_bytes, STATE_FOLD());

    // Absorbs the tags of lanes 1 to 3, each one in the first lane of an otherwise empty block
    memset(v_block, 0, sizeof v_block);
    memcpy(v_block, tag_multi_bytes + 1 * HIAEX4_MACBYTES, HIAEX4_MACBYTES);
    v = SIMD_LOAD(v_block);
    UPDATE(s0, s1, s3, s13, v);
    memcpy(v_block, tag_multi_bytes + 2 * HIAEX4_MACBYTES, HIAEX4_MACBYTES);
    v = SIMD_LOAD(v_block);
    UPDATE(s1, s2, s4, s14, v);
    memcpy(v_block, tag_multi_bytes + 3 * HIAEX4_MACBYTES, HIAEX4_MACBYTES);
    v = SIMD_LOAD(v_block);
    UPDATE(s2, s3, s5, s15, v);
    STATE_ROTATE(3);

    lens[0] = degree;
    lens[1] = HIAEX4_MACBYTES * 8;
    temp    = SIMD_LOADx4((uint8_t *) lens);
    UPDATE_32_CONST(temp, temp);

    SIMD_STORE128(tag, SIMD_FOLD(STATE_FOLD()));
    STATE_OUT();
}

static void
HiAEx4_init_vaes_avx512(HiAEx4_state_t *state_opaque, const uint8_t *key, const uint8_t *nonce)
{
    STATE_DECL;
    init_regs(STATE_ARGS, key, nonce);
    STATE_STORE(state_opaque->opaque);
}

static void
HiAEx4_absorb_vaes_avx512(HiAEx4_state_t *state_opaque, const uint8_t *ad, size_t len)
{
    STATE_DECL;
    if (len == 0) {
        return;
    }
    STATE_LOAD(state_opaque->opaque);
    absorb_regs(STATE_ARGS, ad, len);
    STATE_STORE(state_opaque->opaque);
}

static void
HiAEx4_finalize_vaes_avx512(HiAEx4_state_t *state_opaque,
                            uint64_t        ad_len,
                            uint64_t        msg_len,
                            uint8_t        *tag)
{
    STATE_DECL;
    STATE_LOAD(state_opaque->opaque);
    finalize_regs(STATE_ARGS, ad_len, msg_len, tag);
    STATE_STORE(state_opaque->opaque);
}

static void
HiAEx4_finalize_mac_vaes_avx512(HiAEx4_state_t *state_opaque, uint64_t data_len, uint8_t *tag)
{
    STATE_DECL;
    STATE_LOAD(state_opaque->opaque);
    finalize_mac_regs(STATE_ARGS, data_len, tag);
    STATE_STORE(state_opaque->opaque);
}

static void
HiAEx4_enc_vaes_avx512(HiAEx4_state_t *state_opaque, uint8_t *ci, const uint8_t *mi, size_t size)
{
    STATE_DECL;
    if (size == 0) {
        return;
    }
    STATE_LOAD(state_opaque->opaque);
    enc_regs(STATE_ARGS, ci, mi, size);
    STATE_STORE(state_opaque->opaque);
}

static void
HiAEx4_dec_vaes_avx512(HiAEx4_state_t *state_opaque, uint8_t *mi, const uint8_t *ci, size_t size)
{
    STATE_DECL;
    if (size == 0) {
        return;
    }
    STATE_LOAD(state_opaque->opaque);
    dec_regs(STATE_ARGS, mi, ci, size);
    STATE_STORE(state_opaque->opaque);
}

static void
HiAEx4_enc_partial_noupdate_vaes_avx512(HiAEx4_state_t *state_opaque,
                                        uint8_t        *ci,
                                        const uint8_t  *mi,
                                        size_t          size)
{
    const uint8_t *const st = state_opaque->opaque;
    uint8_t              buf[BLOCK_SIZE];

    if (size == 0) {
        return;
    }
    memset(buf, 0, sizeof buf);
    memcpy(buf, mi, size);
    const DATA512b x = SIMD_XOR(SIMD_LOAD(st + 64 * P_0), SIMD_LOAD(st + 64 * P_1));
    const DATA512b c = SIMD_XOR(AESENC(x, SIMD_LOAD(buf)), SIMD_LOAD(st + 64 * P_7));
    SIMD_STORE(buf, c);
    memcpy(ci, buf, size);
}

static void
HiAEx4_dec_partial_noupdate_vaes_avx512(HiAEx4_state_t *state_opaque,
                                        uint8_t        *mi,
                                        const uint8_t  *ci,
                                        size_t          size)
{
    const uint8_t *const st = state_opaque->opaque;
    uint8_t              buf[BLOCK_SIZE];

    if (size == 0) {
        return;
    }
    memset(buf, 0, sizeof buf);
    memcpy(buf, ci, size);
    const DATA512b x = SIMD_XOR(SIMD_LOAD(st + 64 * P_0), SIMD_LOAD(st + 64 * P_1));
    const DATA512b m = SIMD_XOR(AESENC(x, SIMD_LOAD(buf)), SIMD_LOAD(st + 64 * P_7));
    SIMD_STORE(buf, m);
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
    STATE_DECL;
    init_regs(STATE_ARGS, key, nonce);
    absorb_regs(STATE_ARGS, ad, ad_len);
    enc_regs(STATE_ARGS, ct, msg, msg_len);
    finalize_regs(STATE_ARGS, ad_len, msg_len, tag);

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
    STATE_DECL;
    uint8_t computed_tag[HIAEX4_MACBYTES];
    init_regs(STATE_ARGS, key, nonce);
    absorb_regs(STATE_ARGS, ad, ad_len);
    dec_regs(STATE_ARGS, msg, ct, ct_len);
    finalize_regs(STATE_ARGS, ad_len, ct_len, computed_tag);

    return hiaex4_constant_time_compare(computed_tag, tag, HIAEX4_MACBYTES);
}

static int
HiAEx4_mac_vaes_avx512(
    const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len, uint8_t *tag)
{
    STATE_DECL;
    init_regs(STATE_ARGS, key, nonce);
    absorb_regs(STATE_ARGS, data, data_len);
    finalize_mac_regs(STATE_ARGS, data_len, tag);

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
const HiAEx4_impl_t hiaex4_vaes_avx512_impl = { .name                 = NULL,
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
