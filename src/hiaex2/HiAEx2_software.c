#include "HiAEx2.h"
#include "HiAEx2_internal.h"

// Only compile software implementation if hardware AES is not available
#if !defined(__AES__) && !defined(__ARM_FEATURE_CRYPTO)

#    define FAVOR_PERFORMANCE
#    include "softaes.h"

typedef SoftAesBlock DATA128b;

typedef struct {
    DATA128b data[2];
} DATA256b;

static inline DATA256b
SIMD_LOAD(const uint8_t *x)
{
    DATA256b result;
    result.data[0] = softaes_block_load(x);
    result.data[1] = softaes_block_load(x + 16);
    return result;
}

static inline DATA256b
SIMD_LOADx2(const uint8_t *x)
{
    DATA256b result;
    result.data[0] = softaes_block_load(x);
    result.data[1] = result.data[0];
    return result;
}

static inline void
SIMD_STORE(uint8_t *dst, const DATA256b x)
{
    softaes_block_store(dst, x.data[0]);
    softaes_block_store(dst + 16, x.data[1]);
}

static inline void
SIMD_STORE128(uint8_t *dst, const DATA128b x)
{
    softaes_block_store(dst, x);
}

static inline DATA256b
SIMD_XOR(const DATA256b a, const DATA256b b)
{
    DATA256b result;
    result.data[0] = softaes_block_xor(a.data[0], b.data[0]);
    result.data[1] = softaes_block_xor(a.data[1], b.data[1]);
    return result;
}

static inline DATA256b
SIMD_AND(const DATA256b a, const DATA256b b)
{
    DATA256b result;
    result.data[0] = softaes_block_and(a.data[0], b.data[0]);
    result.data[1] = softaes_block_and(a.data[1], b.data[1]);
    return result;
}

static inline DATA128b
SIMD_FOLD(const DATA256b x)
{
    DATA128b result;
    result = softaes_block_xor(x.data[0], x.data[1]);
    return result;
}

static inline DATA256b
SIMD_ZERO_256(void)
{
    DATA256b result;
    result.data[0] = softaes_block_zero();
    result.data[1] = softaes_block_zero();
    return result;
}

static inline DATA256b
AESL(const DATA256b x)
{
    DATA256b result;
    result.data[0] = softaes_block_aesl(x.data[0]);
    result.data[1] = softaes_block_aesl(x.data[1]);
    return result;
}

static inline DATA256b
XAESL(const DATA256b x, const DATA256b y)
{
    DATA256b result;
    result.data[0] = softaes_block_xaesl(x.data[0], y.data[0]);
    result.data[1] = softaes_block_xaesl(x.data[1], y.data[1]);
    return result;
}

static inline void
update_state_offset(DATA256b *state, DATA256b *tmp, DATA256b M, int offset)
{
    tmp[offset] = XAESL(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    tmp[offset] = SIMD_XOR(tmp[offset], M);
    state[(0 + offset) % STATE]   = SIMD_XOR(tmp[offset], AESL(state[(P_4 + offset) % STATE]));
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], M);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], M);
}

static inline DATA256b
keystream_block(DATA256b *state, DATA256b M, int offset)
{
    DATA256b tmp = XAESL(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    M            = SIMD_XOR(SIMD_XOR(tmp, M), state[(P_7 + offset) % STATE]);
    return M;
}

static inline DATA256b
enc_offset(DATA256b *state, DATA256b M, int offset)
{
    DATA256b C = XAESL(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    C          = SIMD_XOR(C, M);
    state[(0 + offset) % STATE]   = SIMD_XOR(C, AESL(state[(P_4 + offset) % STATE]));
    C                             = SIMD_XOR(C, state[(P_7 + offset) % STATE]);
    state[(I_1 + offset) % STATE] = SIMD_XOR(state[(I_1 + offset) % STATE], M);
    state[(I_2 + offset) % STATE] = SIMD_XOR(state[(I_2 + offset) % STATE], M);
    return C;
}

static inline DATA256b
dec_offset(DATA256b *state, DATA256b *tmp, DATA256b C, int offset)
{
    tmp[offset] = XAESL(state[(P_0 + offset) % STATE], state[(P_1 + offset) % STATE]);
    DATA256b M  = SIMD_XOR(state[(P_7 + offset) % STATE], C);
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
state_shift(DATA256b *state, DATA256b *tmp)
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
init_update(DATA256b *state, DATA256b *tmp, DATA256b c0)
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
ad_update(DATA256b *state, DATA256b *tmp, const uint8_t *ad, size_t i)
{
    DATA256b M[16];
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
encrypt_chunk(DATA256b *state, const uint8_t *mi, uint8_t *ci, size_t i)
{
    DATA256b M[16], C[16];
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
decrypt_chunk(DATA256b *state, DATA256b *tmp, const uint8_t *ci, uint8_t *mi, size_t i)
{
    DATA256b M[16], C[16];
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
HiAEx2_init_software(HiAEx2_state_t *state_opaque, const uint8_t *key, const uint8_t *nonce)
{
    DATA256b state[STATE];
    memset(&state, 0, sizeof state);
    DATA256b c0 = SIMD_LOAD(C0);
    DATA256b c1 = SIMD_LOAD(C1);
    DATA256b k0 = SIMD_LOADx2(key);
    DATA256b k1 = SIMD_LOADx2(key + 16);
    DATA256b N  = SIMD_LOADx2(nonce);

    DATA256b ze = SIMD_ZERO_256();
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
    const uint8_t degree                = 2;
    uint8_t       ctx_bytes[BLOCK_SIZE] = { 0 };
    for (size_t i = 0; i < degree; i++) {
        ctx_bytes[i * 16 + 0] = (uint8_t) i;
        ctx_bytes[i * 16 + 1] = degree - 1;
    }
    const DATA256b ctx = SIMD_LOAD(ctx_bytes);
    for (size_t i = 0; i < STATE; i++) {
        state[i] = SIMD_XOR(state[i], ctx);
    }

    /* 32 consecutive updates with C0 */
    DATA256b tmp[STATE];
    init_update(state, tmp, c0);
    init_update(state, tmp, c0);

    state[9]  = SIMD_XOR(state[9], k0);
    state[13] = SIMD_XOR(state[13], k1);
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAEx2_absorb_software(HiAEx2_state_t *state_opaque, const uint8_t *ad, size_t len)
{
    DATA256b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t   i      = 0;
    size_t   rest   = len % UNROLL_BLOCK_SIZE;
    size_t   prefix = len - rest;
    DATA256b tmp[STATE], M[16];
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
        state_shift(state, tmp);
    }
    if (pad != 0) {
        uint8_t buf[BLOCK_SIZE];
        memset(buf, 0x00, sizeof(buf));
        memcpy(buf, ad + len, pad);
        M[0] = SIMD_LOAD(buf);
        update_state_offset(state, tmp, M[0], 0);
        state_shift(state, tmp);
    }
    memcpy(state_opaque->opaque, state, sizeof(state));
}

/* Convert byte lengths to bit lengths */
static void
HiAEx2_finalize_software(HiAEx2_state_t *state_opaque,
                         uint64_t        ad_len,
                         uint64_t        msg_len,
                         uint8_t        *tag)
{
    DATA256b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    uint64_t lens[2];
    lens[0] = ad_len * 8;
    lens[1] = msg_len * 8;
    DATA256b temp, tmp[STATE];
    temp = SIMD_LOADx2((uint8_t *) lens);
    init_update(state, tmp, temp);
    init_update(state, tmp, temp);
    temp = state[0];
    for (size_t i = 1; i < STATE; ++i) {
        temp = SIMD_XOR(temp, state[i]);
    }
    SIMD_STORE128(tag, SIMD_FOLD(temp));
    memcpy(state_opaque->opaque, state, sizeof(state));
}

/* MAC finalization following the Zig reference implementation */
static void
HiAEx2_finalize_mac_software(HiAEx2_state_t *state_opaque, uint64_t data_len, uint8_t *tag)
{
    DATA256b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    DATA256b tmp[STATE];

    /* Step 1: Initial diffusion with data_len and tag_length */
    uint64_t lens[2];
    lens[0]       = data_len * 8;
    lens[1]       = HIAEX2_MACBYTES * 8;
    DATA256b temp = SIMD_LOADx2((uint8_t *) lens);
    init_update(state, tmp, temp);
    init_update(state, tmp, temp);

    /* Step 2: Compute MAC of all lanes (XOR all states together) */
    DATA256b tag_multi = state[0];
    for (size_t i = 1; i < STATE; ++i) {
        tag_multi = SIMD_XOR(tag_multi, state[i]);
    }

    /* Step 3: Absorb MACs from each lane (degree = 2) */
    const uint8_t degree = 2;
    uint8_t       tag_multi_bytes[32];
    SIMD_STORE(tag_multi_bytes, tag_multi);

    /* For each lane d from 1 to degree-1, absorb the MAC from that lane */
    for (size_t d = 1; d < degree; d++) {
        uint8_t v[BLOCK_SIZE];
        memset(v, 0, sizeof(v));
        memcpy(v, &tag_multi_bytes[d * HIAEX2_MACBYTES], HIAEX2_MACBYTES);

        DATA256b v_block = SIMD_LOAD(v);
        update_state_offset(state, tmp, v_block, 0);
        state_shift(state, tmp);
    }

    /* Step 4: Additional diffusion if degree > 1 */
    if (degree > 1) {
        uint64_t degree_lens[2];
        degree_lens[0]       = degree;
        degree_lens[1]       = HIAEX2_MACBYTES * 8;
        DATA256b degree_temp = SIMD_LOADx2((uint8_t *) degree_lens);
        init_update(state, tmp, degree_temp);
        init_update(state, tmp, degree_temp);
    }

    /* Step 5: Final MAC extraction (XOR all states and extract first tag_length bytes) */
    tag_multi = state[0];
    for (size_t i = 1; i < STATE; ++i) {
        tag_multi = SIMD_XOR(tag_multi, state[i]);
    }
    SIMD_STORE128(tag, SIMD_FOLD(tag_multi));

    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAEx2_enc_software(HiAEx2_state_t *state_opaque, uint8_t *ci, const uint8_t *mi, size_t size)
{
    DATA256b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t rest   = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    if (size == 0)
        return;
    DATA256b M[STATE], C[STATE], tmp[STATE];

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
HiAEx2_dec_software(HiAEx2_state_t *state_opaque, uint8_t *mi, const uint8_t *ci, size_t size)
{
    DATA256b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t rest   = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    if (size == 0)
        return;
    DATA256b M[STATE], C[STATE], tmp[STATE];

    for (size_t i = 0; i < prefix; i += UNROLL_BLOCK_SIZE) {
        decrypt_chunk(state, tmp, ci, mi, i);
    }

    size_t pad = rest % BLOCK_SIZE;
    rest -= pad;

    for (size_t i = 0; i < rest; i += BLOCK_SIZE) {
        C[0] = SIMD_LOAD(ci + i + prefix);
        M[0] = dec_offset(state, tmp, C[0], 0);
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
        update_state_offset(state, tmp, C[0], 0);
        state_shift(state, tmp);
        SIMD_STORE(buf, C[0]);
        memcpy(mi + rest + prefix, buf, pad);
    }
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAEx2_enc_partial_noupdate_software(HiAEx2_state_t *state_opaque,
                                     uint8_t        *ci,
                                     const uint8_t  *mi,
                                     size_t          size)
{
    if (size == 0)
        return;

    DATA256b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));

    DATA256b M[1], C[1];
    uint8_t  buf[BLOCK_SIZE];

    memcpy(buf, mi, size);
    memset(buf + size, 0, BLOCK_SIZE - size);
    M[0] = SIMD_LOAD(buf);
    C[0] = enc_offset(state, M[0], 0);
    SIMD_STORE(buf, C[0]);
    memcpy(ci, buf, size);
}

static void
HiAEx2_dec_partial_noupdate_software(HiAEx2_state_t *state_opaque,
                                     uint8_t        *mi,
                                     const uint8_t  *ci,
                                     size_t          size)
{
    if (size == 0)
        return;

    DATA256b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));

    DATA256b M[1], C[1];
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
HiAEx2_encrypt_software(const uint8_t *key,
                        const uint8_t *nonce,
                        const uint8_t *msg,
                        uint8_t       *ct,
                        size_t         msg_len,
                        const uint8_t *ad,
                        size_t         ad_len,
                        uint8_t       *tag)
{
    HiAEx2_state_t state;
    HiAEx2_init_software(&state, key, nonce);
    HiAEx2_absorb_software(&state, ad, ad_len);
    HiAEx2_enc_software(&state, ct, msg, msg_len);
    HiAEx2_finalize_software(&state, ad_len, msg_len, tag);

    return 0;
}

static int
HiAEx2_decrypt_software(const uint8_t *key,
                        const uint8_t *nonce,
                        uint8_t       *msg,
                        const uint8_t *ct,
                        size_t         ct_len,
                        const uint8_t *ad,
                        size_t         ad_len,
                        const uint8_t *tag)
{
    HiAEx2_state_t state;
    uint8_t        computed_tag[HIAEX2_MACBYTES];
    HiAEx2_init_software(&state, key, nonce);
    HiAEx2_absorb_software(&state, ad, ad_len);
    HiAEx2_dec_software(&state, msg, ct, ct_len);
    HiAEx2_finalize_software(&state, ad_len, ct_len, computed_tag);

    return hiaex2_constant_time_compare(computed_tag, tag, HIAEX2_MACBYTES);
}

static int
HiAEx2_mac_software(
    const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len, uint8_t *tag)
{
    HiAEx2_state_t state;
    HiAEx2_init_software(&state, key, nonce);
    HiAEx2_absorb_software(&state, data, data_len);
    HiAEx2_finalize_mac_software(&state, data_len, tag);

    return 0;
}

const HiAEx2_impl_t hiaex2_software_impl = { .name         = "Software",
                                             .init         = HiAEx2_init_software,
                                             .absorb       = HiAEx2_absorb_software,
                                             .finalize     = HiAEx2_finalize_software,
                                             .finalize_mac = HiAEx2_finalize_mac_software,
                                             .enc          = HiAEx2_enc_software,
                                             .dec          = HiAEx2_dec_software,
                                             .enc_partial_noupdate =
                                                 HiAEx2_enc_partial_noupdate_software,
                                             .dec_partial_noupdate =
                                                 HiAEx2_dec_partial_noupdate_software,
                                             .encrypt = HiAEx2_encrypt_software,
                                             .decrypt = HiAEx2_decrypt_software,
                                             .mac     = HiAEx2_mac_software };

#endif // !defined(__AES__) && !defined(__ARM_FEATURE_CRYPTO)
