#include "HiAEt.h"
#include "HiAEt_internal.h"

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
    // HiAEt modification: compute mask 't' and use it for state updates
    tmp[offset]     = XAESL(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    DATA128b mask_t = SIMD_XOR(tmp[offset], M);
    state[(0 + offset) % STATE]   = SIMD_XOR(mask_t, AESL(state[(P_4 + offset) % STATE]));
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], mask_t);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], mask_t);
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
    // HiAEt modification: compute mask 't' and use it for state updates
    DATA128b C      = XAESL(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    DATA128b mask_t = SIMD_XOR(C, M); // This is the mask 't'
    state[(0 + offset) % STATE] = SIMD_XOR(mask_t, AESL(state[(P_4 + offset) % STATE]));
    C = SIMD_XOR(mask_t, state[(P_7 + offset) % STATE]); // Ciphertext output
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], mask_t);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], mask_t);
    return C;
}

static inline DATA128b
dec_offset(DATA128b *state, DATA128b *tmp, DATA128b C, int offset)
{
    // HiAEt modification: recover mask 't' and use it for state updates
    tmp[offset]     = XAESL(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    DATA128b mask_t = SIMD_XOR(state[(P_7 + offset) % STATE], C); // Recover mask 't'
    state[(0 + offset) % STATE]   = SIMD_XOR(mask_t, AESL(state[(P_4 + offset) % STATE]));
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], mask_t);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], mask_t);
    DATA128b plaintext            = SIMD_XOR(mask_t, tmp[offset]); // Recover original plaintext
    return plaintext;
}

#    define LOAD_1BLOCK_offset_enc(M, offset)  (M) = SIMD_LOAD(mi + BLOCK_SIZE * offset);
#    define LOAD_1BLOCK_offset_dec(C, offset)  (C) = SIMD_LOAD(ci + BLOCK_SIZE * offset);
#    define LOAD_1BLOCK_offset_ad(M, offset)   (M) = SIMD_LOAD(ad + BLOCK_SIZE * offset);
#    define STORE_1BLOCK_offset_enc(C, offset) SIMD_STORE(ci + BLOCK_SIZE * offset, (C));
#    define STORE_1BLOCK_offset_dec(M, offset) SIMD_STORE(mi + BLOCK_SIZE * offset, (M));

static inline void
state_shift(DATA128b *state, DATA128b *tmp)
{
    tmp[0]    = state[0];
    state[0]  = state[1];
    state[1]  = state[2];
    state[2]  = state[3];
    state[3]  = state[4];
    state[4]  = state[5];
    state[5]  = state[6];
    state[6]  = state[7];
    state[7]  = state[8];
    state[8]  = state[9];
    state[9]  = state[10];
    state[10] = state[11];
    state[11] = state[12];
    state[12] = state[13];
    state[13] = state[14];
    state[14] = state[15];
    state[15] = tmp[0];
}

static inline void
encrypt_chunk(DATA128b *state, DATA128b *tmp, const uint8_t *mi, uint8_t *ci)
{
    DATA128b M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15;
    DATA128b C0, C1, C2, C3, C4, C5, C6, C7, C8, C9, C10, C11, C12, C13, C14, C15;

    // Prefetch input data
    PREFETCH_READ(mi + PREFETCH_DISTANCE, 1);

    // Load 16 blocks of plaintext
    LOAD_1BLOCK_offset_enc(M0, 0);
    LOAD_1BLOCK_offset_enc(M1, 1);
    LOAD_1BLOCK_offset_enc(M2, 2);
    LOAD_1BLOCK_offset_enc(M3, 3);
    LOAD_1BLOCK_offset_enc(M4, 4);
    LOAD_1BLOCK_offset_enc(M5, 5);
    LOAD_1BLOCK_offset_enc(M6, 6);
    LOAD_1BLOCK_offset_enc(M7, 7);
    LOAD_1BLOCK_offset_enc(M8, 8);
    LOAD_1BLOCK_offset_enc(M9, 9);
    LOAD_1BLOCK_offset_enc(M10, 10);
    LOAD_1BLOCK_offset_enc(M11, 11);
    LOAD_1BLOCK_offset_enc(M12, 12);
    LOAD_1BLOCK_offset_enc(M13, 13);
    LOAD_1BLOCK_offset_enc(M14, 14);
    LOAD_1BLOCK_offset_enc(M15, 15);

    // Encrypt 16 blocks in parallel
    C0  = enc_offset(state, M0, 0);
    C1  = enc_offset(state, M1, 1);
    C2  = enc_offset(state, M2, 2);
    C3  = enc_offset(state, M3, 3);
    C4  = enc_offset(state, M4, 4);
    C5  = enc_offset(state, M5, 5);
    C6  = enc_offset(state, M6, 6);
    C7  = enc_offset(state, M7, 7);
    C8  = enc_offset(state, M8, 8);
    C9  = enc_offset(state, M9, 9);
    C10 = enc_offset(state, M10, 10);
    C11 = enc_offset(state, M11, 11);
    C12 = enc_offset(state, M12, 12);
    C13 = enc_offset(state, M13, 13);
    C14 = enc_offset(state, M14, 14);
    C15 = enc_offset(state, M15, 15);

    // Prefetch output location
    PREFETCH_WRITE(ci + PREFETCH_DISTANCE, 1);

    // Store 16 blocks of ciphertext
    STORE_1BLOCK_offset_enc(C0, 0);
    STORE_1BLOCK_offset_enc(C1, 1);
    STORE_1BLOCK_offset_enc(C2, 2);
    STORE_1BLOCK_offset_enc(C3, 3);
    STORE_1BLOCK_offset_enc(C4, 4);
    STORE_1BLOCK_offset_enc(C5, 5);
    STORE_1BLOCK_offset_enc(C6, 6);
    STORE_1BLOCK_offset_enc(C7, 7);
    STORE_1BLOCK_offset_enc(C8, 8);
    STORE_1BLOCK_offset_enc(C9, 9);
    STORE_1BLOCK_offset_enc(C10, 10);
    STORE_1BLOCK_offset_enc(C11, 11);
    STORE_1BLOCK_offset_enc(C12, 12);
    STORE_1BLOCK_offset_enc(C13, 13);
    STORE_1BLOCK_offset_enc(C14, 14);
    STORE_1BLOCK_offset_enc(C15, 15);

    // Rotate state
    state_shift(state, tmp);
}

static inline void
decrypt_chunk(DATA128b *state, DATA128b *tmp, const uint8_t *ci, uint8_t *mi)
{
    DATA128b M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15;
    DATA128b C0, C1, C2, C3, C4, C5, C6, C7, C8, C9, C10, C11, C12, C13, C14, C15;

    // Prefetch input data
    PREFETCH_READ(ci + PREFETCH_DISTANCE, 1);

    // Load 16 blocks of ciphertext
    LOAD_1BLOCK_offset_dec(C0, 0);
    LOAD_1BLOCK_offset_dec(C1, 1);
    LOAD_1BLOCK_offset_dec(C2, 2);
    LOAD_1BLOCK_offset_dec(C3, 3);
    LOAD_1BLOCK_offset_dec(C4, 4);
    LOAD_1BLOCK_offset_dec(C5, 5);
    LOAD_1BLOCK_offset_dec(C6, 6);
    LOAD_1BLOCK_offset_dec(C7, 7);
    LOAD_1BLOCK_offset_dec(C8, 8);
    LOAD_1BLOCK_offset_dec(C9, 9);
    LOAD_1BLOCK_offset_dec(C10, 10);
    LOAD_1BLOCK_offset_dec(C11, 11);
    LOAD_1BLOCK_offset_dec(C12, 12);
    LOAD_1BLOCK_offset_dec(C13, 13);
    LOAD_1BLOCK_offset_dec(C14, 14);
    LOAD_1BLOCK_offset_dec(C15, 15);

    // Decrypt 16 blocks in parallel
    M0  = dec_offset(state, tmp, C0, 0);
    M1  = dec_offset(state, tmp, C1, 1);
    M2  = dec_offset(state, tmp, C2, 2);
    M3  = dec_offset(state, tmp, C3, 3);
    M4  = dec_offset(state, tmp, C4, 4);
    M5  = dec_offset(state, tmp, C5, 5);
    M6  = dec_offset(state, tmp, C6, 6);
    M7  = dec_offset(state, tmp, C7, 7);
    M8  = dec_offset(state, tmp, C8, 8);
    M9  = dec_offset(state, tmp, C9, 9);
    M10 = dec_offset(state, tmp, C10, 10);
    M11 = dec_offset(state, tmp, C11, 11);
    M12 = dec_offset(state, tmp, C12, 12);
    M13 = dec_offset(state, tmp, C13, 13);
    M14 = dec_offset(state, tmp, C14, 14);
    M15 = dec_offset(state, tmp, C15, 15);

    // Prefetch output location
    PREFETCH_WRITE(mi + PREFETCH_DISTANCE, 1);

    // Store 16 blocks of plaintext
    STORE_1BLOCK_offset_dec(M0, 0);
    STORE_1BLOCK_offset_dec(M1, 1);
    STORE_1BLOCK_offset_dec(M2, 2);
    STORE_1BLOCK_offset_dec(M3, 3);
    STORE_1BLOCK_offset_dec(M4, 4);
    STORE_1BLOCK_offset_dec(M5, 5);
    STORE_1BLOCK_offset_dec(M6, 6);
    STORE_1BLOCK_offset_dec(M7, 7);
    STORE_1BLOCK_offset_dec(M8, 8);
    STORE_1BLOCK_offset_dec(M9, 9);
    STORE_1BLOCK_offset_dec(M10, 10);
    STORE_1BLOCK_offset_dec(M11, 11);
    STORE_1BLOCK_offset_dec(M12, 12);
    STORE_1BLOCK_offset_dec(M13, 13);
    STORE_1BLOCK_offset_dec(M14, 14);
    STORE_1BLOCK_offset_dec(M15, 15);

    // Rotate state
    state_shift(state, tmp);
}

static inline void
absorb_chunk(DATA128b *state, DATA128b *tmp, const uint8_t *ad)
{
    DATA128b M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12, M13, M14, M15;

    // Prefetch input data
    PREFETCH_READ(ad + PREFETCH_DISTANCE, 1);

    // Load 16 blocks of additional data
    LOAD_1BLOCK_offset_ad(M0, 0);
    LOAD_1BLOCK_offset_ad(M1, 1);
    LOAD_1BLOCK_offset_ad(M2, 2);
    LOAD_1BLOCK_offset_ad(M3, 3);
    LOAD_1BLOCK_offset_ad(M4, 4);
    LOAD_1BLOCK_offset_ad(M5, 5);
    LOAD_1BLOCK_offset_ad(M6, 6);
    LOAD_1BLOCK_offset_ad(M7, 7);
    LOAD_1BLOCK_offset_ad(M8, 8);
    LOAD_1BLOCK_offset_ad(M9, 9);
    LOAD_1BLOCK_offset_ad(M10, 10);
    LOAD_1BLOCK_offset_ad(M11, 11);
    LOAD_1BLOCK_offset_ad(M12, 12);
    LOAD_1BLOCK_offset_ad(M13, 13);
    LOAD_1BLOCK_offset_ad(M14, 14);
    LOAD_1BLOCK_offset_ad(M15, 15);

    // Absorb 16 blocks in parallel
    update_state_offset(state, tmp, M0, 0);
    update_state_offset(state, tmp, M1, 1);
    update_state_offset(state, tmp, M2, 2);
    update_state_offset(state, tmp, M3, 3);
    update_state_offset(state, tmp, M4, 4);
    update_state_offset(state, tmp, M5, 5);
    update_state_offset(state, tmp, M6, 6);
    update_state_offset(state, tmp, M7, 7);
    update_state_offset(state, tmp, M8, 8);
    update_state_offset(state, tmp, M9, 9);
    update_state_offset(state, tmp, M10, 10);
    update_state_offset(state, tmp, M11, 11);
    update_state_offset(state, tmp, M12, 12);
    update_state_offset(state, tmp, M13, 13);
    update_state_offset(state, tmp, M14, 14);
    update_state_offset(state, tmp, M15, 15);

    // Rotate state
    state_shift(state, tmp);
}

static void
init_software(HiAEt_state_t *state, const uint8_t key[32], const uint8_t nonce[16])
{
    DATA128b s[STATE];
    DATA128b tmp[STATE];

    DATA128b C0_vec = SIMD_LOAD(C0);
    DATA128b C1_vec = SIMD_LOAD(C1);

    DATA128b K0 = SIMD_LOAD(key);
    DATA128b K1 = SIMD_LOAD(key + 16);
    DATA128b N  = SIMD_LOAD(nonce);

    // Initialize states with constants, key, and nonce
    for (int i = 0; i < STATE; i++) {
        s[i] = SIMD_XOR3(C0_vec, K0, N);
        s[i] = SIMD_XOR(s[i], vmovq_n_u8(i));
    }

    // 32 rounds of initialization with C0
    for (int round = 0; round < 32; round++) {
        for (int i = 0; i < STATE; i++) {
            update_state_offset(s, tmp, C0_vec, i);
        }
        state_shift(s, tmp);
    }

    // Inject key material
    s[P_7] = SIMD_XOR(s[P_7], K1);
    s[P_4] = SIMD_XOR(s[P_4], K0);

    // Copy state to opaque buffer
    memcpy(state->opaque, s, sizeof(s));
}

static void
absorb_software(HiAEt_state_t *state, const uint8_t *ad, size_t ad_len)
{
    DATA128b s[STATE];
    DATA128b tmp[STATE];
    memcpy(s, state->opaque, sizeof(s));

    size_t i = 0;

    // Process full 256-byte chunks
    while (i + UNROLL_BLOCK_SIZE <= ad_len) {
        absorb_chunk(s, tmp, ad + i);
        i += UNROLL_BLOCK_SIZE;
    }

    // Process remaining 16-byte blocks
    while (i + BLOCK_SIZE <= ad_len) {
        DATA128b M = SIMD_LOAD(ad + i);
        update_state_offset(s, tmp, M, 0);
        state_shift(s, tmp);
        i += BLOCK_SIZE;
    }

    // Handle partial block
    if (i < ad_len) {
        uint8_t padded[BLOCK_SIZE] = { 0 };
        size_t  remaining          = ad_len - i;
        for (size_t j = 0; j < remaining; j++) {
            padded[j] = ad[i + j];
        }
        padded[remaining] = 0x80; // Padding

        DATA128b M = SIMD_LOAD(padded);
        update_state_offset(s, tmp, M, 0);
        state_shift(s, tmp);
    }

    // Copy state back to opaque buffer
    memcpy(state->opaque, s, sizeof(s));
}

static void
enc_software(HiAEt_state_t *state, uint8_t *ciphertext, const uint8_t *plaintext, size_t msg_len)
{
    DATA128b s[STATE];
    DATA128b tmp[STATE];
    memcpy(s, state->opaque, sizeof(s));

    size_t i = 0;

    // Process full 256-byte chunks
    while (i + UNROLL_BLOCK_SIZE <= msg_len) {
        encrypt_chunk(s, tmp, plaintext + i, ciphertext + i);
        i += UNROLL_BLOCK_SIZE;
    }

    // Process remaining 16-byte blocks
    while (i + BLOCK_SIZE <= msg_len) {
        DATA128b M = SIMD_LOAD(plaintext + i);
        DATA128b C = enc_offset(s, M, 0);
        SIMD_STORE(ciphertext + i, C);
        state_shift(s, tmp);
        i += BLOCK_SIZE;
    }

    // Handle partial block
    if (i < msg_len) {
        uint8_t padded_in[BLOCK_SIZE] = { 0 };
        uint8_t padded_out[BLOCK_SIZE];
        size_t  remaining = msg_len - i;

        for (size_t j = 0; j < remaining; j++) {
            padded_in[j] = plaintext[i + j];
        }

        DATA128b M = SIMD_LOAD(padded_in);
        DATA128b C = enc_offset(s, M, 0);
        SIMD_STORE(padded_out, C);

        for (size_t j = 0; j < remaining; j++) {
            ciphertext[i + j] = padded_out[j];
        }

        state_shift(s, tmp);
    }

    // Copy state back to opaque buffer
    memcpy(state->opaque, s, sizeof(s));
}

static void
dec_software(HiAEt_state_t *state, uint8_t *plaintext, const uint8_t *ciphertext, size_t msg_len)
{
    DATA128b s[STATE];
    DATA128b tmp[STATE];
    memcpy(s, state->opaque, sizeof(s));

    size_t i = 0;

    // Process full 256-byte chunks
    while (i + UNROLL_BLOCK_SIZE <= msg_len) {
        decrypt_chunk(s, tmp, ciphertext + i, plaintext + i);
        i += UNROLL_BLOCK_SIZE;
    }

    // Process remaining 16-byte blocks
    while (i + BLOCK_SIZE <= msg_len) {
        DATA128b C = SIMD_LOAD(ciphertext + i);
        DATA128b M = dec_offset(s, tmp, C, 0);
        SIMD_STORE(plaintext + i, M);
        state_shift(s, tmp);
        i += BLOCK_SIZE;
    }

    // Handle partial block
    if (i < msg_len) {
        uint8_t padded_in[BLOCK_SIZE] = { 0 };
        uint8_t padded_out[BLOCK_SIZE];
        size_t  remaining = msg_len - i;

        for (size_t j = 0; j < remaining; j++) {
            padded_in[j] = ciphertext[i + j];
        }

        DATA128b C = SIMD_LOAD(padded_in);
        DATA128b M = dec_offset(s, tmp, C, 0);
        SIMD_STORE(padded_out, M);

        for (size_t j = 0; j < remaining; j++) {
            plaintext[i + j] = padded_out[j];
        }

        state_shift(s, tmp);
    }

    // Copy state back to opaque buffer
    memcpy(state->opaque, s, sizeof(s));
}

static void
finalize_software(HiAEt_state_t *state, uint64_t ad_len, uint64_t msg_len, uint8_t *tag)
{
    DATA128b s[STATE];
    DATA128b tmp[STATE];
    memcpy(s, state->opaque, sizeof(s));

    // Encode lengths as bit counts
    uint64_t ad_bits  = (uint64_t) ad_len * 8;
    uint64_t msg_bits = (uint64_t) msg_len * 8;

    // Create length block
    uint8_t length_block[BLOCK_SIZE] = { 0 };
    for (int i = 0; i < 8; i++) {
        length_block[i]     = (ad_bits >> (8 * i)) & 0xFF;
        length_block[i + 8] = (msg_bits >> (8 * i)) & 0xFF;
    }

    DATA128b L = SIMD_LOAD(length_block);
    update_state_offset(s, tmp, L, 0);
    state_shift(s, tmp);

    // 32 more rounds for finalization
    DATA128b C1_vec = SIMD_LOAD(C1);
    for (int round = 0; round < 32; round++) {
        for (int i = 0; i < STATE; i++) {
            update_state_offset(s, tmp, C1_vec, i);
        }
        state_shift(s, tmp);
    }

    // Generate tag by XORing all states
    DATA128b tag_state = s[0];
    for (int i = 1; i < STATE; i++) {
        tag_state = SIMD_XOR(tag_state, s[i]);
    }

    SIMD_STORE(tag, tag_state);
}

// Export implementation functions
const HiAEt_impl_t hiaet_arm_sha3_impl = { .name     = "ARM+SHA3",
                                           .init     = init_software,
                                           .absorb   = absorb_software,
                                           .enc      = enc_software,
                                           .dec      = dec_software,
                                           .finalize = finalize_software };

#    ifdef __clang__
#        pragma clang attribute pop
#    endif

#else

// Dummy implementation for non-ARM platforms
const HiAEt_impl_t hiaet_arm_sha3_impl = { .name     = "ARM+SHA3 (unsupported)",
                                           .init     = NULL,
                                           .absorb   = NULL,
                                           .enc      = NULL,
                                           .dec      = NULL,
                                           .finalize = NULL };

#endif