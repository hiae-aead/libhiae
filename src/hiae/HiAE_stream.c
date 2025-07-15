#include "HiAE.h"
#include "HiAE_internal.h"
#include <assert.h>
#include <string.h>

void
HiAE_stream_init(HiAE_stream_state_t *stream, const uint8_t *key, const uint8_t *nonce)
{
    HiAE_init(&stream->state, key, nonce);
    memset(stream->buffer, 0, BLOCK_SIZE);
    stream->offset  = 0;
    stream->ad_len  = 0;
    stream->msg_len = 0;
    stream->phase   = HIAE_STREAM_INIT;
    stream->mode    = HIAE_STREAM_MODE_NONE;
}

void
HiAE_stream_absorb(HiAE_stream_state_t *stream, const uint8_t *ad, size_t ad_len)
{
    assert(stream->phase == HIAE_STREAM_INIT || stream->phase == HIAE_STREAM_AD);

    if (stream->phase == HIAE_STREAM_INIT) {
        stream->phase = HIAE_STREAM_AD;
    }

    stream->ad_len += ad_len;

    size_t pos = 0;

    if (stream->offset > 0) {
        size_t to_copy = BLOCK_SIZE - stream->offset;
        if (to_copy > ad_len) {
            to_copy = ad_len;
        }

        memcpy(stream->buffer + stream->offset, ad, to_copy);
        stream->offset += to_copy;
        pos += to_copy;

        if (stream->offset == BLOCK_SIZE) {
            HiAE_absorb(&stream->state, stream->buffer, BLOCK_SIZE);
            stream->offset = 0;
        }
    }

    size_t full_blocks_len = ((ad_len - pos) / BLOCK_SIZE) * BLOCK_SIZE;
    if (full_blocks_len > 0) {
        HiAE_absorb(&stream->state, ad + pos, full_blocks_len);
        pos += full_blocks_len;
    }

    if (pos < ad_len) {
        size_t remaining = ad_len - pos;
        memcpy(stream->buffer, ad + pos, remaining);
        stream->offset = remaining;
    }
}

void
HiAE_stream_encrypt(HiAE_stream_state_t *stream, uint8_t *ct, const uint8_t *pt, size_t len)
{
    assert(stream->phase != HIAE_STREAM_FINAL);

    stream->mode = HIAE_STREAM_MODE_ENCRYPT;

    if (stream->phase == HIAE_STREAM_INIT || stream->phase == HIAE_STREAM_AD) {
        if (stream->phase == HIAE_STREAM_AD && stream->offset > 0) {
            HiAE_absorb(&stream->state, stream->buffer, stream->offset);
            stream->offset = 0;
        }
        stream->phase = HIAE_STREAM_MSG;
    }

    stream->msg_len += len;

    size_t pos    = 0;
    size_t ct_pos = 0;

    if (stream->offset > 0) {
        size_t to_copy = BLOCK_SIZE - stream->offset;
        if (to_copy > len) {
            to_copy = len;
        }

        memcpy(stream->buffer + stream->offset, pt, to_copy);
        size_t new_offset = stream->offset + to_copy;

        if (new_offset == BLOCK_SIZE) {
            HiAE_enc(&stream->state, stream->buffer, stream->buffer, BLOCK_SIZE);
            memcpy(ct, stream->buffer + stream->offset, to_copy);
            stream->offset = 0;
        } else {
            uint8_t temp_out[BLOCK_SIZE];
            HiAE_enc_partial_noupdate(&stream->state, temp_out, stream->buffer, new_offset);
            memcpy(ct, temp_out + stream->offset, to_copy);
            stream->offset = new_offset;
        }

        pos += to_copy;
        ct_pos += to_copy;
    }

    size_t full_blocks_len = ((len - pos) / BLOCK_SIZE) * BLOCK_SIZE;
    if (full_blocks_len > 0) {
        HiAE_enc(&stream->state, ct + ct_pos, pt + pos, full_blocks_len);
        pos += full_blocks_len;
        ct_pos += full_blocks_len;
    }

    if (pos < len) {
        size_t remaining = len - pos;
        memcpy(stream->buffer, pt + pos, remaining);

        uint8_t temp_out[BLOCK_SIZE];
        HiAE_enc_partial_noupdate(&stream->state, temp_out, stream->buffer, remaining);
        memcpy(ct + ct_pos, temp_out, remaining);

        stream->offset = remaining;
    }
}

void
HiAE_stream_decrypt(HiAE_stream_state_t *stream, uint8_t *pt, const uint8_t *ct, size_t len)
{
    assert(stream->phase != HIAE_STREAM_FINAL);

    stream->mode = HIAE_STREAM_MODE_DECRYPT;

    if (stream->phase == HIAE_STREAM_INIT || stream->phase == HIAE_STREAM_AD) {
        if (stream->phase == HIAE_STREAM_AD && stream->offset > 0) {
            HiAE_absorb(&stream->state, stream->buffer, stream->offset);
            stream->offset = 0;
        }
        stream->phase = HIAE_STREAM_MSG;
    }

    stream->msg_len += len;

    size_t pos    = 0;
    size_t pt_pos = 0;

    if (stream->offset > 0) {
        size_t to_copy = BLOCK_SIZE - stream->offset;
        if (to_copy > len) {
            to_copy = len;
        }

        memcpy(stream->buffer + stream->offset, ct, to_copy);
        size_t new_offset = stream->offset + to_copy;

        if (new_offset == BLOCK_SIZE) {
            HiAE_dec(&stream->state, stream->buffer, stream->buffer, BLOCK_SIZE);
            memcpy(pt, stream->buffer + stream->offset, to_copy);
            stream->offset = 0;
        } else {
            uint8_t temp_out[BLOCK_SIZE];
            HiAE_dec_partial_noupdate(&stream->state, temp_out, stream->buffer, new_offset);
            memcpy(pt, temp_out + stream->offset, to_copy);
            stream->offset = new_offset;
        }

        pos += to_copy;
        pt_pos += to_copy;
    }

    size_t full_blocks_len = ((len - pos) / BLOCK_SIZE) * BLOCK_SIZE;
    if (full_blocks_len > 0) {
        HiAE_dec(&stream->state, pt + pt_pos, ct + pos, full_blocks_len);
        pos += full_blocks_len;
        pt_pos += full_blocks_len;
    }

    if (pos < len) {
        size_t remaining = len - pos;
        memcpy(stream->buffer, ct + pos, remaining);

        uint8_t temp_out[BLOCK_SIZE];
        HiAE_dec_partial_noupdate(&stream->state, temp_out, stream->buffer, remaining);
        memcpy(pt + pt_pos, temp_out, remaining);

        stream->offset = remaining;
    }
}

void
HiAE_stream_finalize(HiAE_stream_state_t *stream, uint8_t *tag)
{
    assert(stream->phase != HIAE_STREAM_FINAL);

    if (stream->phase == HIAE_STREAM_AD && stream->offset > 0) {
        HiAE_absorb(&stream->state, stream->buffer, stream->offset);
        stream->offset = 0;
    } else if (stream->phase == HIAE_STREAM_MSG && stream->offset > 0) {
        uint8_t dummy[BLOCK_SIZE];
        if (stream->mode == HIAE_STREAM_MODE_DECRYPT) {
            HiAE_dec(&stream->state, dummy, stream->buffer, stream->offset);
        } else {
            HiAE_enc(&stream->state, dummy, stream->buffer, stream->offset);
        }
        stream->offset = 0;
    }

    HiAE_finalize(&stream->state, stream->ad_len, stream->msg_len, tag);
    stream->phase = HIAE_STREAM_FINAL;
}

int
HiAE_stream_verify(HiAE_stream_state_t *stream, const uint8_t *expected_tag)
{
    assert(stream->phase != HIAE_STREAM_FINAL);
    assert(stream->mode == HIAE_STREAM_MODE_DECRYPT || stream->mode == HIAE_STREAM_MODE_NONE);

    if (stream->phase == HIAE_STREAM_AD && stream->offset > 0) {
        HiAE_absorb(&stream->state, stream->buffer, stream->offset);
        stream->offset = 0;
    } else if (stream->phase == HIAE_STREAM_MSG && stream->offset > 0) {
        uint8_t dummy[BLOCK_SIZE];
        HiAE_dec(&stream->state, dummy, stream->buffer, stream->offset);
        stream->offset = 0;
    }

    uint8_t computed_tag[HIAE_MACBYTES];
    HiAE_finalize(&stream->state, stream->ad_len, stream->msg_len, computed_tag);
    stream->phase = HIAE_STREAM_FINAL;

    return hiae_constant_time_compare(expected_tag, computed_tag, HIAE_MACBYTES);
}