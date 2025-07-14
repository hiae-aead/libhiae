#ifndef HIAE_H
#define HIAE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__clang__) && !defined(__GNUC__)
#    ifdef __attribute__
#        undef __attribute__
#    endif
#    define __attribute__(a)
#endif

/* Cryptographic parameter sizes */
#define HIAE_KEYBYTES   32 /* 256-bit key */
#define HIAE_NONCEBYTES 16 /* 128-bit nonce */
#define HIAE_MACBYTES   16 /* 128-bit authentication tag */

/* Opaque state structure - applications don't need internal details */
typedef struct {
    uint8_t opaque[256];
} HiAE_state_t;

/* ----- High-level All-at-Once APIs ----- */
int HiAE_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *msg, uint8_t *ct,
                 size_t msg_len, const uint8_t *ad, size_t ad_len, uint8_t *tag);

int HiAE_decrypt(const uint8_t *key, const uint8_t *nonce, uint8_t *msg, const uint8_t *ct,
                 size_t ct_len, const uint8_t *ad, size_t ad_len, const uint8_t *tag);

int HiAE_mac(const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len,
             uint8_t *tag);

/* ----- Utility APIs ----- */
int         HiAE_init_library(void);
const char *HiAE_get_implementation_name(void);
int         HiAE_verify_tag(const uint8_t *expected_tag, const uint8_t *actual_tag);

/* ----- High-level Streaming API ----- */
typedef enum {
    HIAE_STREAM_INIT  = 0,
    HIAE_STREAM_AD    = 1,
    HIAE_STREAM_MSG   = 2,
    HIAE_STREAM_FINAL = 3
} HiAE_stream_phase_t;

typedef enum {
    HIAE_STREAM_MODE_NONE    = 0,
    HIAE_STREAM_MODE_ENCRYPT = 1,
    HIAE_STREAM_MODE_DECRYPT = 2
} HiAE_stream_mode_t;

typedef struct {
    HiAE_state_t        state;
    uint8_t             buffer[16];
    size_t              offset;
    size_t              ad_len;
    size_t              msg_len;
    HiAE_stream_phase_t phase;
    HiAE_stream_mode_t  mode;
} HiAE_stream_state_t;

void HiAE_stream_init(HiAE_stream_state_t *stream, const uint8_t *key, const uint8_t *nonce);
void HiAE_stream_absorb(HiAE_stream_state_t *stream, const uint8_t *ad, size_t ad_len);
void HiAE_stream_encrypt(HiAE_stream_state_t *stream, uint8_t *ct, const uint8_t *pt, size_t len);
void HiAE_stream_decrypt(HiAE_stream_state_t *stream, uint8_t *pt, const uint8_t *ct, size_t len);
void HiAE_stream_finalize(HiAE_stream_state_t *stream, uint8_t *tag);
int  HiAE_stream_verify(HiAE_stream_state_t *stream, const uint8_t *expected_tag);

/* ----- Low-level Stream APIs ----- */
void HiAE_init(HiAE_state_t *state, const uint8_t *key, const uint8_t *nonce);
void HiAE_absorb(HiAE_state_t *state, const uint8_t *ad, size_t len);
void HiAE_finalize(HiAE_state_t *state, uint64_t ad_len, uint64_t msg_len, uint8_t *tag);
void HiAE_enc(HiAE_state_t *state, uint8_t *ci, const uint8_t *mi, size_t size);
void HiAE_dec(HiAE_state_t *state, uint8_t *mi, const uint8_t *ci, size_t size);
void HiAE_enc_partial_noupdate(HiAE_state_t *state, uint8_t *ci, const uint8_t *mi, size_t size);
void HiAE_dec_partial_noupdate(HiAE_state_t *state, uint8_t *mi, const uint8_t *ci, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* HIAE_H */
