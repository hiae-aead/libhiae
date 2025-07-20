#ifndef HIAET_H
#define HIAET_H

/**
 * @file HiAEt.h
 * @brief HiAEt (High-Throughput Authenticated Encryption - Tweaked variant) - A modified AEAD
 * cipher
 *
 * HiAEt is a modified version of HiAE implementing the tweaked encryption/decryption logic.
 * This is a software reference implementation that uses the computed mask 't' for state updates
 * instead of the original message 'M' in the enc_offset() and dec_offset() functions.
 *
 * The library provides identical API to HiAE with HiAEt_ prefixes.
 */

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

/**
 * @defgroup constants Cryptographic Constants
 * @brief Core cryptographic parameter sizes for HiAEt
 * @{
 */

/** @brief Key size in bytes (256 bits) */
#define HIAET_KEYBYTES 32

/** @brief Nonce/IV size in bytes (128 bits) */
#define HIAET_NONCEBYTES 16

/** @brief Authentication tag size in bytes (128 bits) */
#define HIAET_MACBYTES 16

/** @} */

/**
 * @defgroup types Data Types
 * @brief Core data structures used by HiAEt
 * @{
 */

/**
 * @brief Opaque state structure for low-level streaming operations
 */
typedef struct {
    uint8_t opaque[256];
} HiAEt_state_t;

/** @} */

/**
 * @defgroup highlevel High-Level All-at-Once API
 * @brief Simple functions for encrypting/decrypting complete messages in memory
 * @{
 */

/**
 * @brief Encrypt a message with authenticated encryption
 */
int HiAEt_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *msg, uint8_t *ct,
                  size_t msg_len, const uint8_t *ad, size_t ad_len, uint8_t *tag);

/**
 * @brief Decrypt a message with authenticated encryption
 */
int HiAEt_decrypt(const uint8_t *key, const uint8_t *nonce, uint8_t *msg, const uint8_t *ct,
                  size_t ct_len, const uint8_t *ad, size_t ad_len, const uint8_t *tag);

/**
 * @brief Compute authentication tag without encryption (MAC-only mode)
 */
int HiAEt_mac(const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len,
              uint8_t *tag);

/** @} */

/**
 * @defgroup utility Utility Functions
 * @brief Helper functions for library management and diagnostics
 * @{
 */

/**
 * @brief Initialize the HiAEt library
 */
int HiAEt_init_library(void);

/**
 * @brief Get the name of the active implementation
 */
const char *HiAEt_get_implementation_name(void);

/**
 * @brief Force a specific implementation to be used
 */
int HiAEt_force_implementation(const char *impl_name);

/**
 * @brief Constant-time comparison of authentication tags
 */
int HiAEt_verify_tag(const uint8_t *expected_tag, const uint8_t *actual_tag);

/** @} */

/**
 * @defgroup streaming High-Level Streaming API
 * @brief Streaming functions with automatic buffering for large data
 * @{
 */

/**
 * @brief Stream processing phases
 */
typedef enum {
    HIAET_STREAM_INIT  = 0, /**< Initial state after HiAEt_stream_init() */
    HIAET_STREAM_AD    = 1, /**< Processing associated data */
    HIAET_STREAM_MSG   = 2, /**< Processing message data (encrypt/decrypt) */
    HIAET_STREAM_FINAL = 3 /**< Finalized, tag generated/verified */
} HiAEt_stream_phase_t;

/**
 * @brief Stream operation mode
 */
typedef enum {
    HIAET_STREAM_MODE_NONE    = 0, /**< Not yet determined */
    HIAET_STREAM_MODE_ENCRYPT = 1, /**< Encryption mode */
    HIAET_STREAM_MODE_DECRYPT = 2 /**< Decryption mode */
} HiAEt_stream_mode_t;

/**
 * @brief High-level streaming state
 */
typedef struct {
    HiAEt_state_t        state; /**< Internal cryptographic state */
    uint8_t              buffer[16]; /**< Internal buffer for partial blocks */
    size_t               offset; /**< Current offset in buffer */
    size_t               ad_len; /**< Total associated data processed */
    size_t               msg_len; /**< Total message data processed */
    HiAEt_stream_phase_t phase; /**< Current processing phase */
    HiAEt_stream_mode_t  mode; /**< Encryption or decryption mode */
} HiAEt_stream_state_t;

/** @} */

/**
 * @brief Initialize a streaming encryption/decryption operation
 */
void HiAEt_stream_init(HiAEt_stream_state_t *stream, const uint8_t *key, const uint8_t *nonce);

/**
 * @brief Process associated data in streaming mode
 */
void HiAEt_stream_absorb(HiAEt_stream_state_t *stream, const uint8_t *ad, size_t ad_len);

/**
 * @brief Encrypt data in streaming mode
 */
void HiAEt_stream_encrypt(HiAEt_stream_state_t *stream, uint8_t *ct, const uint8_t *pt, size_t len);

/**
 * @brief Decrypt data in streaming mode
 */
void HiAEt_stream_decrypt(HiAEt_stream_state_t *stream, uint8_t *pt, const uint8_t *ct, size_t len);

/**
 * @brief Finalize streaming encryption and get authentication tag
 */
void HiAEt_stream_finalize(HiAEt_stream_state_t *stream, uint8_t *tag);

/**
 * @brief Verify authentication tag after streaming decryption
 */
int HiAEt_stream_verify(HiAEt_stream_state_t *stream, const uint8_t *expected_tag);

/** @} */

/**
 * @defgroup lowlevel Low-Level Streaming API
 * @brief Advanced functions for fine-grained control over streaming operations
 * @{
 */

/**
 * @brief Initialize low-level streaming state
 */
void HiAEt_init(HiAEt_state_t *state, const uint8_t *key, const uint8_t *nonce);

/**
 * @brief Absorb associated data
 */
void HiAEt_absorb(HiAEt_state_t *state, const uint8_t *ad, size_t len);

/**
 * @brief Finalize and generate authentication tag
 */
void HiAEt_finalize(HiAEt_state_t *state, uint64_t ad_len, uint64_t msg_len, uint8_t *tag);

/**
 * @brief Encrypt data incrementally
 */
void HiAEt_enc(HiAEt_state_t *state, uint8_t *ci, const uint8_t *mi, size_t size);

/**
 * @brief Decrypt data incrementally
 */
void HiAEt_dec(HiAEt_state_t *state, uint8_t *mi, const uint8_t *ci, size_t size);

/**
 * @brief Encrypt partial block without updating state
 */
void HiAEt_enc_partial_noupdate(HiAEt_state_t *state, uint8_t *ci, const uint8_t *mi, size_t size);

/**
 * @brief Decrypt partial block without updating state
 */
void HiAEt_dec_partial_noupdate(HiAEt_state_t *state, uint8_t *mi, const uint8_t *ci, size_t size);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* HIAET_H */