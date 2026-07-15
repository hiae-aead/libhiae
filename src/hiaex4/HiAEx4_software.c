#include "HiAEx4.h"
#include "HiAEx4_internal.h"

// Only compile software implementation if hardware AES+VAES+AVX512 is not available
#if !((defined(__AES__) && defined(__VAES__) && defined(__AVX512F__)) || \
      defined(__ARM_FEATURE_CRYPTO))

#    define FAVOR_PERFORMANCE
#    include "softaes.h"

typedef SoftAesBlock DATA128b;

typedef struct {
    DATA128b data[4];
} DATA512b;

static inline DATA512b
SIMD_LOAD(const uint8_t *x)
{
    DATA512b result;
    result.data[0] = softaes_block_load(x);
    result.data[1] = softaes_block_load(x + 16);
    result.data[2] = softaes_block_load(x + 32);
    result.data[3] = softaes_block_load(x + 48);
    return result;
}

static inline DATA512b
SIMD_LOADx4(const uint8_t *x)
{
    DATA512b result;
    result.data[0] = softaes_block_load(x);
    result.data[1] = result.data[0];
    result.data[2] = result.data[0];
    result.data[3] = result.data[0];
    return result;
}

static inline void
SIMD_STORE(uint8_t *dst, const DATA512b x)
{
    softaes_block_store(dst, x.data[0]);
    softaes_block_store(dst + 16, x.data[1]);
    softaes_block_store(dst + 32, x.data[2]);
    softaes_block_store(dst + 48, x.data[3]);
}

static inline void
SIMD_STORE128(uint8_t *dst, const DATA128b x)
{
    softaes_block_store(dst, x);
}

static inline DATA512b
SIMD_XOR(const DATA512b a, const DATA512b b)
{
    DATA512b result;
    result.data[0] = softaes_block_xor(a.data[0], b.data[0]);
    result.data[1] = softaes_block_xor(a.data[1], b.data[1]);
    result.data[2] = softaes_block_xor(a.data[2], b.data[2]);
    result.data[3] = softaes_block_xor(a.data[3], b.data[3]);
    return result;
}

static inline DATA512b
SIMD_AND(const DATA512b a, const DATA512b b)
{
    DATA512b result;
    result.data[0] = softaes_block_and(a.data[0], b.data[0]);
    result.data[1] = softaes_block_and(a.data[1], b.data[1]);
    result.data[2] = softaes_block_and(a.data[2], b.data[2]);
    result.data[3] = softaes_block_and(a.data[3], b.data[3]);
    return result;
}

static inline DATA128b
SIMD_FOLD(const DATA512b x)
{
    DATA128b result;
    result = softaes_block_xor(x.data[0], x.data[1]);
    result = softaes_block_xor(result, x.data[2]);
    result = softaes_block_xor(result, x.data[3]);
    return result;
}

static inline DATA512b
SIMD_ZERO_512(void)
{
    DATA512b result;
    result.data[0] = softaes_block_zero();
    result.data[1] = softaes_block_zero();
    result.data[2] = softaes_block_zero();
    result.data[3] = softaes_block_zero();
    return result;
}

#    ifndef SOFTAES_SIMD128
static inline DATA512b
AESL(const DATA512b x)
{
    DATA512b result;
    result.data[0] = softaes_block_aesl(x.data[0]);
    result.data[1] = softaes_block_aesl(x.data[1]);
    result.data[2] = softaes_block_aesl(x.data[2]);
    result.data[3] = softaes_block_aesl(x.data[3]);
    return result;
}
#    endif

static inline DATA512b
XAESL(const DATA512b x, const DATA512b y)
{
    DATA512b result;
    result.data[0] = softaes_block_xaesl(x.data[0], y.data[0]);
    result.data[1] = softaes_block_xaesl(x.data[1], y.data[1]);
    result.data[2] = softaes_block_xaesl(x.data[2], y.data[2]);
    result.data[3] = softaes_block_xaesl(x.data[3], y.data[3]);
    return result;
}

/*
 * AESL without the S-box affine constant. When two AESL outputs are XORed
 * together the 0x63 constants cancel, and a single constant can be applied
 * with one XOR where it survives. Only the SIMD backend exposes this split;
 * elsewhere the plain round is used and the explicit constant is zero.
 */
#    ifdef SOFTAES_SIMD128
static inline DATA512b
AESL_NC(const DATA512b x)
{
    DATA512b result;
    result.data[0] = softaes_block_aesl_nc(x.data[0]);
    result.data[1] = softaes_block_aesl_nc(x.data[1]);
    result.data[2] = softaes_block_aesl_nc(x.data[2]);
    result.data[3] = softaes_block_aesl_nc(x.data[3]);
    return result;
}

static inline DATA512b
XAESL_NC(const DATA512b x, const DATA512b y)
{
    return AESL_NC(SIMD_XOR(x, y));
}

static inline DATA512b
AESL_C63(void)
{
    DATA512b result;
    result.data[0] = softaes_block_c63();
    result.data[1] = softaes_block_c63();
    result.data[2] = softaes_block_c63();
    result.data[3] = softaes_block_c63();
    return result;
}
#    else
#        define AESL_NC(x)     AESL(x)
#        define XAESL_NC(x, y) XAESL(x, y)
#        define AESL_C63()     SIMD_ZERO_512()
#    endif

/*
 * On the SIMD backend the bulk functions stay out of line so the state
 * array lives in memory: engines with 16 vector registers would otherwise
 * spill it through the stack on every step.
 */
#    ifdef SOFTAES_SIMD128
#        define SOFTAES_CHUNK_FN static void __attribute__((noinline))
#    else
#        define SOFTAES_CHUNK_FN static inline void
#    endif

static inline void
update_state_offset(DATA512b *state, DATA512b M, int offset)
{
    DATA512b t = XAESL_NC(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    t                             = SIMD_XOR(t, M);
    state[(0 + offset) % STATE]   = SIMD_XOR(t, AESL_NC(state[(P_4 + offset) % STATE]));
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], M);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], M);
}

static inline DATA512b
keystream_block(DATA512b *state, DATA512b M, int offset)
{
    DATA512b tmp = XAESL(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    M            = SIMD_XOR(SIMD_XOR(tmp, M), state[(P_7 + offset) % STATE]);
    return M;
}

static inline DATA512b
enc_offset(DATA512b *state, DATA512b M, int offset)
{
    DATA512b C = XAESL_NC(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    C          = SIMD_XOR(C, M);
    state[(0 + offset) % STATE]   = SIMD_XOR(C, AESL_NC(state[(P_4 + offset) % STATE]));
    C                             = SIMD_XOR(SIMD_XOR(C, state[(P_7 + offset) % STATE]), AESL_C63());
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], M);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], M);
    return C;
}

static inline DATA512b
dec_offset(DATA512b *state, DATA512b C, int offset)
{
    DATA512b t = XAESL_NC(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    DATA512b M = SIMD_XOR(SIMD_XOR(state[(P_7 + offset) % STATE], C), AESL_C63());
    state[(0 + offset) % STATE]   = SIMD_XOR(M, AESL_NC(state[(P_4 + offset) % STATE]));
    M                             = SIMD_XOR(M, t);
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], M);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], M);
    return M;
}

#    define LOAD_1BLOCK_offset_enc(M, offset)  (M) = SIMD_LOAD(mi + i + BLOCK_SIZE * (offset));
#    define LOAD_1BLOCK_offset_dec(C, offset)  (C) = SIMD_LOAD(ci + i + BLOCK_SIZE * (offset));
#    define LOAD_1BLOCK_offset_ad(M, offset)   (M) = SIMD_LOAD(ad + i + BLOCK_SIZE * (offset));
#    define STORE_1BLOCK_offset_enc(C, offset) SIMD_STORE(ci + i + BLOCK_SIZE * (offset), (C));
#    define STORE_1BLOCK_offset_dec(M, offset) SIMD_STORE(mi + i + BLOCK_SIZE * (offset), (M));

static inline void
state_shift(DATA512b *state, DATA512b *tmp)
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

SOFTAES_CHUNK_FN
init_update(DATA512b *state, DATA512b c0, DATA512b c1)
{
    update_state_offset(state, c0, 0);
    update_state_offset(state, c1, 1);
    update_state_offset(state, c0, 2);
    update_state_offset(state, c1, 3);
    update_state_offset(state, c0, 4);
    update_state_offset(state, c1, 5);
    update_state_offset(state, c0, 6);
    update_state_offset(state, c1, 7);
    update_state_offset(state, c0, 8);
    update_state_offset(state, c1, 9);
    update_state_offset(state, c0, 10);
    update_state_offset(state, c1, 11);
    update_state_offset(state, c0, 12);
    update_state_offset(state, c1, 13);
    update_state_offset(state, c0, 14);
    update_state_offset(state, c1, 15);
}

SOFTAES_CHUNK_FN
ad_update(DATA512b *state, const uint8_t *ad, size_t i)
{
    DATA512b M;
#    define AD_STEP(o)                            \
        do {                                      \
            LOAD_1BLOCK_offset_ad(M, o);          \
            update_state_offset(state, M, o); \
        } while (0)
    AD_STEP(0);
    AD_STEP(1);
    AD_STEP(2);
    AD_STEP(3);
    AD_STEP(4);
    AD_STEP(5);
    AD_STEP(6);
    AD_STEP(7);
    AD_STEP(8);
    AD_STEP(9);
    AD_STEP(10);
    AD_STEP(11);
    AD_STEP(12);
    AD_STEP(13);
    AD_STEP(14);
    AD_STEP(15);
#    undef AD_STEP
}

SOFTAES_CHUNK_FN
encrypt_chunk(DATA512b *state, const uint8_t *mi, uint8_t *ci, size_t i)
{
    DATA512b M, C;
#    define ENC_STEP(o)                    \
        do {                               \
            LOAD_1BLOCK_offset_enc(M, o);  \
            C = enc_offset(state, M, o);   \
            STORE_1BLOCK_offset_enc(C, o); \
        } while (0)
    ENC_STEP(0);
    ENC_STEP(1);
    ENC_STEP(2);
    ENC_STEP(3);
    ENC_STEP(4);
    ENC_STEP(5);
    ENC_STEP(6);
    ENC_STEP(7);
    ENC_STEP(8);
    ENC_STEP(9);
    ENC_STEP(10);
    ENC_STEP(11);
    ENC_STEP(12);
    ENC_STEP(13);
    ENC_STEP(14);
    ENC_STEP(15);
#    undef ENC_STEP
}

SOFTAES_CHUNK_FN
decrypt_chunk(DATA512b *state, const uint8_t *ci, uint8_t *mi, size_t i)
{
    DATA512b M, C;
#    define DEC_STEP(o)                       \
        do {                                  \
            LOAD_1BLOCK_offset_dec(C, o);     \
            M = dec_offset(state, C, o); \
            STORE_1BLOCK_offset_dec(M, o);    \
        } while (0)
    DEC_STEP(0);
    DEC_STEP(1);
    DEC_STEP(2);
    DEC_STEP(3);
    DEC_STEP(4);
    DEC_STEP(5);
    DEC_STEP(6);
    DEC_STEP(7);
    DEC_STEP(8);
    DEC_STEP(9);
    DEC_STEP(10);
    DEC_STEP(11);
    DEC_STEP(12);
    DEC_STEP(13);
    DEC_STEP(14);
    DEC_STEP(15);
#    undef DEC_STEP
}

static void
HiAEx4_init_software(HiAEx4_state_t *state_opaque, const uint8_t *key, const uint8_t *nonce)
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
    state[1]    = k0;
    state[2]    = c0;
    state[3]    = N;
    state[4]    = ze;
    state[5]    = k0;
    state[6]    = ze;
    state[7]    = c1;
    state[8]    = k1;
    state[9]    = ze;
    state[10]   = SIMD_XOR(N, k1);
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

    /* 32 consecutive updates with C0 */
    init_update(state, k0, k1);
    init_update(state, k0, k1);

    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAEx4_absorb_software(HiAEx4_state_t *state_opaque, const uint8_t *ad, size_t len)
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
        ad_update(state, ad, i);
    }

    size_t pad = len % BLOCK_SIZE;
    len -= pad;
    for (; i < len; i += BLOCK_SIZE) {
        M[0] = SIMD_LOAD(ad + i);
        update_state_offset(state, M[0], 0);
        state_shift(state, tmp);
    }
    if (pad != 0) {
        uint8_t buf[BLOCK_SIZE];
        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, ad + len, pad);
        M[0] = SIMD_LOAD(buf);
        update_state_offset(state, M[0], 0);
        state_shift(state, tmp);
    }
    memcpy(state_opaque->opaque, state, sizeof(state));
}

/* Convert byte lengths to bit lengths */
static void
HiAEx4_finalize_software(HiAEx4_state_t *state_opaque,
                         uint64_t        ad_len,
                         uint64_t        msg_len,
                         uint8_t        *tag)
{
    DATA512b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    uint64_t lens[2];
    lens[0] = ad_len * 8;
    lens[1] = msg_len * 8;
    DATA512b temp;
    temp = SIMD_LOADx4((uint8_t *) lens);
    init_update(state, temp, temp);
    init_update(state, temp, temp);
    temp = state[0];
    for (size_t i = 1; i < STATE; ++i) {
        temp = SIMD_XOR(temp, state[i]);
    }
    SIMD_STORE128(tag, SIMD_FOLD(temp));
    memcpy(state_opaque->opaque, state, sizeof(state));
}

/* Enhanced MAC finalization with proper domain separation for multi-parallel implementations */
static void
HiAEx4_finalize_mac_software(HiAEx4_state_t *state_opaque, uint64_t data_len, uint8_t *tag)
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
    init_update(state, temp, temp);
    init_update(state, temp, temp);

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
        update_state_offset(state, v, 0);
        state_shift(state, tmp);
    }

    /* Step 4: Additional diffusion if degree > 1 */
    if (degree > 1) {
        uint64_t degree_lens[2];
        degree_lens[0]       = degree;
        degree_lens[1]       = HIAEX4_MACBYTES * 8;
        DATA512b degree_temp = SIMD_LOADx4((uint8_t *) degree_lens);
        init_update(state, degree_temp, degree_temp);
        init_update(state, degree_temp, degree_temp);
    }

    /* Step 5: Final MAC extraction */
    temp = state[0];
    for (size_t i = 1; i < STATE; ++i) {
        temp = SIMD_XOR(temp, state[i]);
    }
    SIMD_STORE128(tag, SIMD_FOLD(temp));
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAEx4_enc_software(HiAEx4_state_t *state_opaque, uint8_t *ci, const uint8_t *mi, size_t size)
{
    DATA512b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t rest   = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    if (size == 0)
        return;
    DATA512b M[STATE], C[STATE], tmp[STATE];

    for (size_t i = 0; i < prefix; i += UNROLL_BLOCK_SIZE) {
        encrypt_chunk(state, mi, ci, i);
    }

    size_t pad = rest % BLOCK_SIZE;
    rest -= pad;
    for (size_t i = 0; i < rest; i += BLOCK_SIZE) {
        M[0] = SIMD_LOAD(mi + i + prefix);
        C[0] = enc_offset(state, M[0], 0);
        state_shift(state, tmp);
        SIMD_STORE(ci + i + prefix, C[0]);
    }
    if (pad != 0) {
        uint8_t buf[BLOCK_SIZE];
        memcpy(buf, mi + rest + prefix, pad);
        memset(buf + pad, 0, BLOCK_SIZE - pad);
        M[0] = SIMD_LOAD(buf);
        C[0] = enc_offset(state, M[0], 0);
        state_shift(state, tmp);
        SIMD_STORE(buf, C[0]);
        memcpy(ci + rest + prefix, buf, pad);
    }
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAEx4_dec_software(HiAEx4_state_t *state_opaque, uint8_t *mi, const uint8_t *ci, size_t size)
{
    DATA512b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t rest   = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    if (size == 0)
        return;
    DATA512b M[STATE], C[STATE], tmp[STATE];

    for (size_t i = 0; i < prefix; i += UNROLL_BLOCK_SIZE) {
        decrypt_chunk(state, ci, mi, i);
    }

    size_t pad = rest % BLOCK_SIZE;
    rest -= pad;

    for (size_t i = 0; i < rest; i += BLOCK_SIZE) {
        C[0] = SIMD_LOAD(ci + i + prefix);
        M[0] = dec_offset(state, C[0], 0);
        state_shift(state, tmp);
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
        update_state_offset(state, C[0], 0);
        state_shift(state, tmp);
        SIMD_STORE(buf, C[0]);
        memcpy(mi + rest + prefix, buf, pad);
    }
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAEx4_enc_partial_noupdate_software(HiAEx4_state_t *state_opaque,
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
HiAEx4_dec_partial_noupdate_software(HiAEx4_state_t *state_opaque,
                                     uint8_t        *mi,
                                     const uint8_t  *ci,
                                     size_t          size)
{
    if (size == 0)
        return;

    DATA512b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));

    DATA512b M[1], C[1];
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
HiAEx4_encrypt_software(const uint8_t *key,
                        const uint8_t *nonce,
                        const uint8_t *msg,
                        uint8_t       *ct,
                        size_t         msg_len,
                        const uint8_t *ad,
                        size_t         ad_len,
                        uint8_t       *tag)
{
    HiAEx4_state_t state;
    HiAEx4_init_software(&state, key, nonce);
    HiAEx4_absorb_software(&state, ad, ad_len);
    HiAEx4_enc_software(&state, ct, msg, msg_len);
    HiAEx4_finalize_software(&state, ad_len, msg_len, tag);

    return 0;
}

static int
HiAEx4_decrypt_software(const uint8_t *key,
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
    HiAEx4_init_software(&state, key, nonce);
    HiAEx4_absorb_software(&state, ad, ad_len);
    HiAEx4_dec_software(&state, msg, ct, ct_len);
    HiAEx4_finalize_software(&state, ad_len, ct_len, computed_tag);

    return hiaex4_constant_time_compare(computed_tag, tag, HIAEX4_MACBYTES);
}

static int
HiAEx4_mac_software(
    const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len, uint8_t *tag)
{
    HiAEx4_state_t state;
    HiAEx4_init_software(&state, key, nonce);
    HiAEx4_absorb_software(&state, data, data_len);
    HiAEx4_finalize_mac_software(&state, data_len, tag);

    return 0;
}

const HiAEx4_impl_t hiaex4_software_impl = { .name         = "Software",
                                             .init         = HiAEx4_init_software,
                                             .absorb       = HiAEx4_absorb_software,
                                             .finalize     = HiAEx4_finalize_software,
                                             .finalize_mac = HiAEx4_finalize_mac_software,
                                             .enc          = HiAEx4_enc_software,
                                             .dec          = HiAEx4_dec_software,
                                             .enc_partial_noupdate =
                                                 HiAEx4_enc_partial_noupdate_software,
                                             .dec_partial_noupdate =
                                                 HiAEx4_dec_partial_noupdate_software,
                                             .encrypt = HiAEx4_encrypt_software,
                                             .decrypt = HiAEx4_decrypt_software,
                                             .mac     = HiAEx4_mac_software };

#endif // !defined(__AES__) && !defined(__ARM_FEATURE_CRYPTO)
