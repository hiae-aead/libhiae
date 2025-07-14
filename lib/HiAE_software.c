#include "HiAE.h"
#include "HiAE_internal.h"

static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static uint8_t
gf_mul2(uint8_t a)
{
    return (a << 1) ^ ((a & 0x80) ? 0x1b : 0x00);
}

static uint8_t
gf_mul3(uint8_t a)
{
    return gf_mul2(a) ^ a;
}

typedef struct {
    uint8_t bytes[16];
} data128b_software;

static inline data128b_software
simd_load_software(const uint8_t *ptr)
{
    data128b_software result;
    memcpy(result.bytes, ptr, 16);
    return result;
}

static inline void
simd_store_software(uint8_t *ptr, data128b_software data)
{
    memcpy(ptr, data.bytes, 16);
}

static inline data128b_software
simd_xor_software(data128b_software a, data128b_software b)
{
    data128b_software result;
    for (int i = 0; i < 16; i++) {
        result.bytes[i] = a.bytes[i] ^ b.bytes[i];
    }
    return result;
}

static inline data128b_software
simd_zero_software(void)
{
    data128b_software result;
    memset(result.bytes, 0, 16);
    return result;
}

static void
aes_sub_bytes(uint8_t *state)
{
    for (int i = 0; i < 16; i++) {
        state[i] = aes_sbox[state[i]];
    }
}

static void
aes_shift_rows(uint8_t *state)
{
    const uint8_t temp[16];
    memcpy((uint8_t *) temp, state, 16);

    state[0]  = temp[0];
    state[4]  = temp[4];
    state[8]  = temp[8];
    state[12] = temp[12];

    state[1]  = temp[5];
    state[5]  = temp[9];
    state[9]  = temp[13];
    state[13] = temp[1];

    state[2]  = temp[10];
    state[6]  = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];

    state[3]  = temp[15];
    state[7]  = temp[3];
    state[11] = temp[7];
    state[15] = temp[11];
}

static void
aes_mix_columns(uint8_t *state)
{
    const uint8_t temp[16];
    memcpy((uint8_t *) temp, state, 16);

    for (int col = 0; col < 4; col++) {
        const int offset  = col * 4;
        state[offset + 0] = gf_mul2(temp[offset + 0]) ^ gf_mul3(temp[offset + 1]) ^
                            temp[offset + 2] ^ temp[offset + 3];
        state[offset + 1] = temp[offset + 0] ^ gf_mul2(temp[offset + 1]) ^
                            gf_mul3(temp[offset + 2]) ^ temp[offset + 3];
        state[offset + 2] = temp[offset + 0] ^ temp[offset + 1] ^ gf_mul2(temp[offset + 2]) ^
                            gf_mul3(temp[offset + 3]);
        state[offset + 3] = gf_mul3(temp[offset + 0]) ^ temp[offset + 1] ^ temp[offset + 2] ^
                            gf_mul2(temp[offset + 3]);
    }
}

static data128b_software
aesl_software(data128b_software x)
{
    data128b_software result = x;
    aes_sub_bytes(result.bytes);
    aes_shift_rows(result.bytes);
    aes_mix_columns(result.bytes);
    return result;
}

static data128b_software
aesenc_software(data128b_software x, data128b_software y)
{
    data128b_software temp = simd_xor_software(x, y);
    return aesl_software(temp);
}

typedef data128b_software DATA128b;
#define SIMD_LOAD(x)     simd_load_software(x)
#define SIMD_STORE(x, y) simd_store_software(x, y)
#define SIMD_XOR(x, y)   simd_xor_software(x, y)
#define SIMD_ZERO_128()  simd_zero_software()
#define AESENC(x, y)     aesenc_software(x, y)

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

#define LOAD_1BLOCK_offset_enc(M, offset)  (M) = SIMD_LOAD(mi + i + 0 + BLOCK_SIZE * offset);
#define LOAD_1BLOCK_offset_dec(C, offset)  (C) = SIMD_LOAD(ci + i + 0 + BLOCK_SIZE * offset);
#define LOAD_1BLOCK_offset_ad(M, offset)   (M) = SIMD_LOAD(ad + i + 0 + BLOCK_SIZE * offset);
#define STORE_1BLOCK_offset_enc(C, offset) SIMD_STORE(ci + i + 0 + BLOCK_SIZE * offset, (C));
#define STORE_1BLOCK_offset_dec(M, offset) SIMD_STORE(mi + i + 0 + BLOCK_SIZE * offset, (M));

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
HiAE_init_software(HiAE_state_t *state_opaque, const uint8_t *key, const uint8_t *nonce)
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

    /* 32 consecutive updates with C0 */
    DATA128b tmp[STATE];
    init_update(state, tmp, c0);
    init_update(state, tmp, c0);

    state[9]  = SIMD_XOR(state[9], k0);
    state[13] = SIMD_XOR(state[13], k1);
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAE_absorb_software(HiAE_state_t *state_opaque, const uint8_t *ad, size_t len)
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
HiAE_finalize_software(HiAE_state_t *state_opaque, uint64_t ad_len, uint64_t msg_len, uint8_t *tag)
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
HiAE_enc_software(HiAE_state_t *state_opaque, uint8_t *ci, const uint8_t *mi, size_t size)
{
    DATA128b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t rest   = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    if (size == 0)
        return;
    DATA128b M[STATE], C[STATE], tmp[STATE];

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
HiAE_dec_software(HiAE_state_t *state_opaque, uint8_t *mi, const uint8_t *ci, size_t size)
{
    DATA128b state[STATE];
    memcpy(state, state_opaque->opaque, sizeof(state));
    size_t rest   = size % UNROLL_BLOCK_SIZE;
    size_t prefix = size - rest;
    if (size == 0)
        return;
    DATA128b M[STATE], C[STATE], tmp[STATE];

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
        C[0] = keystream_block(state, tmp, C[0], 0);
        for (int j = 0; j < 16; j++) {
            C[0].bytes[j] &= M[0].bytes[j];
        }
        update_state_offset(state, tmp, C[0], 0);
        state_shift(state, tmp);
        SIMD_STORE(buf, C[0]);
        memcpy(mi + rest + prefix, buf, pad);
    }
    memcpy(state_opaque->opaque, state, sizeof(state));
}

static void
HiAE_enc_partial_noupdate_software(HiAE_state_t  *state_opaque,
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
HiAE_dec_partial_noupdate_software(HiAE_state_t  *state_opaque,
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
    for (int j = 0; j < 16; j++) {
        C[0].bytes[j] &= M[0].bytes[j];
    }
    SIMD_STORE(buf, C[0]);
    memcpy(mi, buf, size);
}

static int
HiAE_encrypt_software(const uint8_t *key,
                      const uint8_t *nonce,
                      const uint8_t *msg,
                      uint8_t       *ct,
                      size_t         msg_len,
                      const uint8_t *ad,
                      size_t         ad_len,
                      uint8_t       *tag)
{
    HiAE_state_t state;
    HiAE_init_software(&state, key, nonce);
    HiAE_absorb_software(&state, ad, ad_len);
    HiAE_enc_software(&state, ct, msg, msg_len);
    HiAE_finalize_software(&state, ad_len, msg_len, tag);

    return 0;
}

static int
HiAE_decrypt_software(const uint8_t *key,
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
    HiAE_init_software(&state, key, nonce);
    HiAE_absorb_software(&state, ad, ad_len);
    HiAE_dec_software(&state, msg, ct, ct_len);
    HiAE_finalize_software(&state, ad_len, ct_len, computed_tag);

    return hiae_constant_time_compare(computed_tag, tag, HIAE_MACBYTES);
}

static int
HiAE_mac_software(
    const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len, uint8_t *tag)
{
    HiAE_state_t state;
    HiAE_init_software(&state, key, nonce);
    HiAE_absorb_software(&state, data, data_len);
    HiAE_finalize_software(&state, data_len, 0, tag);

    return 0;
}

const HiAE_impl_t hiae_software_impl = { .name                 = "Software",
                                         .init                 = HiAE_init_software,
                                         .absorb               = HiAE_absorb_software,
                                         .finalize             = HiAE_finalize_software,
                                         .enc                  = HiAE_enc_software,
                                         .dec                  = HiAE_dec_software,
                                         .enc_partial_noupdate = HiAE_enc_partial_noupdate_software,
                                         .dec_partial_noupdate = HiAE_dec_partial_noupdate_software,
                                         .encrypt              = HiAE_encrypt_software,
                                         .decrypt              = HiAE_decrypt_software,
                                         .mac                  = HiAE_mac_software };
