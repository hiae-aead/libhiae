#ifndef HiAEx2_H
#define HiAEx2_H

/**
 * @file HiAEx2.h
 * @brief HiAEx2 (High-Throughput Authenticated Encryption) - A high-performance AEAD cipher
 *
 * HiAEx2 is a cross-platform cryptographic library implementing an AES-based AEAD
 * (Authenticated Encryption with Associated Data) cipher with runtime CPU feature
 * detection. It automatically selects the optimal implementation:
 * - VAES+AVX512 for latest x86 processors
 * - AES-NI for x86-64 processors with hardware AES
 * - ARM Crypto Extensions for ARM64 processors
 * - Pure software universal fallback
 *
 * The library provides three API levels:
 * 1. High-Level All-at-Once: Simple functions for small to medium messages
 * 2. High-Level Streaming: Automatic buffering for large files/streams
 * 3. Low-Level Block-Oriented: Fine control with manual alignment requirements
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
 * @brief Core cryptographic parameter sizes for HiAEx2
 * @{
 */

/** @brief Key size in bytes (256 bits)
 *
 * HiAEx2 uses 256-bit (32-byte) keys for all operations.
 * Keys should be generated using a cryptographically secure random number generator.
 */
#define HIAEx2_KEYBYTES 32

/** @brief Nonce/IV size in bytes (128 bits)
 *
 * HiAEx2 uses 128-bit (16-byte) nonces (initialization vectors).
 * Each nonce must be unique for a given key to maintain security.
 * Reusing a nonce with the same key compromises the encryption.
 */
#define HIAEx2_NONCEBYTES 16

/** @brief Authentication tag size in bytes (128 bits)
 *
 * HiAEx2 produces 128-bit (16-byte) authentication tags.
 * The tag provides integrity and authenticity verification for both
 * the ciphertext and any associated data.
 */
#define HIAEx2_MACBYTES 16

/** @} */

/**
 * @defgroup types Data Types
 * @brief Core data structures used by HiAEx2
 * @{
 */

/**
 * @brief Opaque state structure for low-level streaming operations
 *
 * This structure maintains the internal state for incremental encryption/decryption
 * operations. The contents are implementation-specific and should not be accessed
 * directly by applications.
 *
 * @note The state is 256 bytes to accommodate all implementation variants
 * @note Each state instance is independent and thread-safe when used by one thread
 * @warning Never modify the contents directly or copy states between operations
 */
typedef struct {
    uint8_t opaque[512];
} HiAEx2_state_t;

/** @} */

/**
 * @defgroup highlevel High-Level All-at-Once API
 * @brief Simple functions for encrypting/decrypting complete messages in memory
 *
 * These functions are the easiest to use and are suitable for messages that
 * fit comfortably in memory. They handle all the complexity internally.
 * @{
 */

/**
 * @brief Encrypt a message with authenticated encryption
 *
 * Encrypts a plaintext message and generates an authentication tag that
 * protects both the ciphertext and optional associated data.
 *
 * @param key       Encryption key (must be HiAEx2_KEYBYTES bytes)
 * @param nonce     Unique nonce/IV for this message (must be HiAEx2_NONCEBYTES bytes)
 * @param msg       Plaintext message to encrypt
 * @param ct        Output buffer for ciphertext (same size as msg)
 * @param msg_len   Length of the message in bytes
 * @param ad        Optional associated data to authenticate (can be NULL)
 * @param ad_len    Length of associated data (0 if ad is NULL)
 * @param tag       Output buffer for authentication tag (must be HiAEx2_MACBYTES bytes)
 *
 * @return 0 on success, non-zero on error
 *
 * @warning Never reuse a nonce with the same key
 * @note The ciphertext buffer must be at least msg_len bytes
 * @note Associated data is authenticated but not encrypted
 *
 * Example:
 * @code
 * uint8_t key[HiAEx2_KEYBYTES];
 * uint8_t nonce[HiAEx2_NONCEBYTES];
 * uint8_t plaintext[] = "Secret message";
 * uint8_t ciphertext[sizeof(plaintext)];
 * uint8_t tag[HiAEx2_MACBYTES];
 * uint8_t ad[] = "metadata";
 *
 * // Generate random key and nonce (use proper CSPRNG)
 * // ...
 *
 * int ret = HiAEx2_encrypt(key, nonce, plaintext, ciphertext,
 *                        sizeof(plaintext), ad, sizeof(ad), tag);
 * if (ret != 0) {
 *     // Handle error
 * }
 * @endcode
 */
int HiAEx2_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *msg, uint8_t *ct,
                   size_t msg_len, const uint8_t *ad, size_t ad_len, uint8_t *tag);

/**
 * @brief Decrypt a message with authenticated encryption
 *
 * Decrypts a ciphertext and verifies its authenticity using the provided tag.
 * If verification fails, the output buffer contents are undefined.
 *
 * @param key       Decryption key (must match encryption key)
 * @param nonce     Nonce/IV used during encryption
 * @param msg       Output buffer for decrypted plaintext
 * @param ct        Ciphertext to decrypt
 * @param ct_len    Length of the ciphertext in bytes
 * @param ad        Associated data used during encryption (can be NULL)
 * @param ad_len    Length of associated data (0 if ad is NULL)
 * @param tag       Authentication tag from encryption
 *
 * @return 0 on success (authentication passed), non-zero on failure
 *
 * @warning ALWAYS check the return value - non-zero means authentication failed
 * @warning On authentication failure, the output buffer contents are undefined
 * @note The plaintext buffer must be at least ct_len bytes
 *
 * Example:
 * @code
 * uint8_t decrypted[sizeof(ciphertext)];
 *
 * int ret = HiAEx2_decrypt(key, nonce, decrypted, ciphertext,
 *                        sizeof(ciphertext), ad, sizeof(ad), tag);
 * if (ret != 0) {
 *     // Authentication failed! Message was tampered with
 *     // Do not use decrypted data
 *     return -1;
 * }
 * // Safe to use decrypted data
 * @endcode
 */
int HiAEx2_decrypt(const uint8_t *key, const uint8_t *nonce, uint8_t *msg, const uint8_t *ct,
                   size_t ct_len, const uint8_t *ad, size_t ad_len, const uint8_t *tag);

/**
 * @brief Compute authentication tag without encryption (MAC-only mode)
 *
 * Generates an authentication tag for data without performing encryption.
 * Useful for authenticating data that doesn't need confidentiality.
 *
 * @param key       Authentication key (must be HiAEx2_KEYBYTES bytes)
 * @param nonce     Unique nonce for this operation
 * @param data      Data to authenticate
 * @param data_len  Length of data in bytes
 * @param tag       Output buffer for authentication tag
 *
 * @return 0 on success, non-zero on error
 *
 * @note This is equivalent to HiAEx2_encrypt with a zero-length message
 * @warning Still requires unique nonces like encryption operations
 *
 * Example:
 * @code
 * uint8_t tag[HiAEx2_MACBYTES];
 * uint8_t metadata[] = "file-metadata-v1.0";
 *
 * int ret = HiAEx2_mac(key, nonce, metadata, sizeof(metadata), tag);
 * @endcode
 */
int HiAEx2_mac(const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len,
               uint8_t *tag);

/** @} */

/**
 * @defgroup utility Utility Functions
 * @brief Helper functions for library management and diagnostics
 * @{
 */

/**
 * @brief Initialize the HiAEx2 library
 *
 * Performs CPU feature detection and selects the optimal implementation.
 * This function is called automatically on first use, but can be called
 * explicitly for better control over initialization timing.
 *
 * @return 0 on success, non-zero on error
 *
 * @note Thread-safe and idempotent (safe to call multiple times)
 * @note Calling this early can avoid initialization overhead on first use
 */
int HiAEx2_init_library(void);

/**
 * @brief Get the name of the active implementation
 *
 * Returns a string describing which implementation was selected based
 * on CPU feature detection.
 *
 * @return Implementation name (e.g., "VAES+AVX512", "AES-NI", "ARM-Crypto", "Software")
 *
 * @note The returned string is static and should not be freed
 * @note Useful for debugging and performance analysis
 *
 * Example:
 * @code
 * printf("Using HiAEx2 implementation: %s\n", HiAEx2_get_implementation_name());
 * @endcode
 */
const char *HiAEx2_get_implementation_name(void);

/**
 * @brief Force a specific implementation to be used
 *
 * Forces the library to use a specific implementation instead of automatically
 * detecting the best one. Useful for testing, debugging, or when specific
 * behavior is required.
 *
 * @param impl_name Implementation name to force ("Software", "AES-NI", "VAES+AVX512", "ARM NEON",
 * "ARM SHA3")
 *
 * @return 0 on success, -1 if implementation is not available or name is invalid
 *
 * @note Must be called before any other HiAEx2 operations
 * @note Pass NULL to restore automatic detection
 * @note Not all implementations are available on all platforms
 *
 * Example:
 * @code
 * // Force software implementation for testing
 * if (HiAEx2_force_implementation("Software") != 0) {
 *     fprintf(stderr, "Failed to force software implementation\n");
 * }
 *
 * // Restore automatic detection
 * HiAEx2_force_implementation(NULL);
 * @endcode
 */
int HiAEx2_force_implementation(const char *impl_name);

/**
 * @brief Constant-time comparison of authentication tags
 *
 * Compares two authentication tags in constant time to prevent
 * timing side-channel attacks.
 *
 * @param expected_tag  The expected tag (HiAEx2_MACBYTES bytes)
 * @param actual_tag    The tag to verify (HiAEx2_MACBYTES bytes)
 *
 * @return 0 if tags match, non-zero if different
 *
 * @note Always compares exactly HiAEx2_MACBYTES bytes
 * @note Execution time is independent of tag contents
 *
 * Example:
 * @code
 * if (HiAEx2_verify_tag(expected_tag, computed_tag) != 0) {
 *     // Authentication failed
 * }
 * @endcode
 */
int HiAEx2_verify_tag(const uint8_t *expected_tag, const uint8_t *actual_tag);

/** @} */

/**
 * @defgroup streaming High-Level Streaming API
 * @brief Streaming functions with automatic buffering for large data
 *
 * This API provides streaming encryption/decryption with automatic internal
 * buffering. Unlike the low-level API, it handles partial blocks transparently
 * and accepts any chunk size.
 * @{
 */

/**
 * @brief Stream processing phases
 *
 * Tracks the current phase of streaming operation to ensure correct API usage.
 */
typedef enum {
    HiAEx2_STREAM_INIT  = 0, /**< Initial state after HiAEx2_stream_init() */
    HiAEx2_STREAM_AD    = 1, /**< Processing associated data */
    HiAEx2_STREAM_MSG   = 2, /**< Processing message data (encrypt/decrypt) */
    HiAEx2_STREAM_FINAL = 3 /**< Finalized, tag generated/verified */
} HiAEx2_stream_phase_t;

/**
 * @brief Stream operation mode
 *
 * Indicates whether the stream is used for encryption or decryption.
 */
typedef enum {
    HiAEx2_STREAM_MODE_NONE    = 0, /**< Not yet determined */
    HiAEx2_STREAM_MODE_ENCRYPT = 1, /**< Encryption mode */
    HiAEx2_STREAM_MODE_DECRYPT = 2 /**< Decryption mode */
} HiAEx2_stream_mode_t;

/**
 * @brief High-level streaming state
 *
 * Maintains state for streaming operations with automatic buffering.
 * This structure handles partial blocks internally, allowing arbitrary
 * chunk sizes without manual alignment.
 *
 * @note Do not access fields directly - use the streaming API functions
 */
typedef struct {
    HiAEx2_state_t        state; /**< Internal cryptographic state */
    uint8_t               buffer[16]; /**< Internal buffer for partial blocks */
    size_t                offset; /**< Current offset in buffer */
    size_t                ad_len; /**< Total associated data processed */
    size_t                msg_len; /**< Total message data processed */
    HiAEx2_stream_phase_t phase; /**< Current processing phase */
    HiAEx2_stream_mode_t  mode; /**< Encryption or decryption mode */
} HiAEx2_stream_state_t;

/** @} */

/**
 * @brief Initialize a streaming encryption/decryption operation
 *
 * Sets up the streaming state with the provided key and nonce.
 * After initialization, you can absorb associated data and then
 * encrypt or decrypt message data.
 *
 * @param stream  Stream state to initialize
 * @param key     Encryption/decryption key (HiAEx2_KEYBYTES bytes)
 * @param nonce   Unique nonce for this operation (HiAEx2_NONCEBYTES bytes)
 *
 * @note Must be called before any other streaming operations
 * @note The same state cannot be reused - create a new state for each operation
 *
 * Example:
 * @code
 * HiAEx2_stream_state_t stream;
 * HiAEx2_stream_init(&stream, key, nonce);
 * @endcode
 */
void HiAEx2_stream_init(HiAEx2_stream_state_t *stream, const uint8_t *key, const uint8_t *nonce);

/**
 * @brief Process associated data in streaming mode
 *
 * Absorbs associated data that will be authenticated but not encrypted.
 * Can be called multiple times with any chunk size. Must be called
 * before any encrypt/decrypt operations.
 *
 * @param stream  Stream state
 * @param ad      Associated data chunk
 * @param ad_len  Length of this chunk
 *
 * @note Call multiple times to process AD in chunks of any size
 * @note Must complete all AD before starting encryption/decryption
 *
 * Example:
 * @code
 * HiAEx2_stream_absorb(&stream, header1, 100);
 * HiAEx2_stream_absorb(&stream, header2, 57);
 * @endcode
 */
void HiAEx2_stream_absorb(HiAEx2_stream_state_t *stream, const uint8_t *ad, size_t ad_len);

/**
 * @brief Encrypt data in streaming mode
 *
 * Encrypts plaintext data incrementally. Handles partial blocks
 * automatically, accepting any chunk size.
 *
 * @param stream  Stream state
 * @param ct      Output buffer for ciphertext
 * @param pt      Input plaintext
 * @param len     Length of data to process
 *
 * @note Output buffer must be at least 'len' bytes
 * @note Can process data in chunks of any size
 * @note Cannot be mixed with decrypt operations on same stream
 *
 * Example:
 * @code
 * // Process file in arbitrary chunks
 * while ((bytes = fread(buffer, 1, sizeof(buffer), input)) > 0) {
 *     HiAEx2_stream_encrypt(&stream, output, buffer, bytes);
 *     fwrite(output, 1, bytes, output_file);
 * }
 * @endcode
 */
void HiAEx2_stream_encrypt(HiAEx2_stream_state_t *stream, uint8_t *ct, const uint8_t *pt,
                           size_t len);

/**
 * @brief Decrypt data in streaming mode
 *
 * Decrypts ciphertext data incrementally. Handles partial blocks
 * automatically, accepting any chunk size.
 *
 * @param stream  Stream state
 * @param pt      Output buffer for plaintext
 * @param ct      Input ciphertext
 * @param len     Length of data to process
 *
 * @note Output buffer must be at least 'len' bytes
 * @note Can process data in chunks of any size
 * @note Cannot be mixed with encrypt operations on same stream
 * @note Does not verify authentication until HiAEx2_stream_verify()
 */
void HiAEx2_stream_decrypt(HiAEx2_stream_state_t *stream, uint8_t *pt, const uint8_t *ct,
                           size_t len);

/**
 * @brief Finalize streaming encryption and get authentication tag
 *
 * Completes the encryption operation and generates the authentication tag.
 * Must be called after all data has been encrypted.
 *
 * @param stream  Stream state
 * @param tag     Output buffer for authentication tag (HiAEx2_MACBYTES bytes)
 *
 * @note Stream cannot be used after finalization
 * @note For decryption, use HiAEx2_stream_verify() instead
 *
 * Example:
 * @code
 * uint8_t tag[HiAEx2_MACBYTES];
 * HiAEx2_stream_finalize(&stream, tag);
 * // Save or transmit tag with ciphertext
 * @endcode
 */
void HiAEx2_stream_finalize(HiAEx2_stream_state_t *stream, uint8_t *tag);

/**
 * @brief Verify authentication tag after streaming decryption
 *
 * Completes the decryption operation and verifies the authentication tag.
 * Must be called after all data has been decrypted.
 *
 * @param stream        Stream state
 * @param expected_tag  The authentication tag to verify
 *
 * @return 0 if authentication succeeds, non-zero on failure
 *
 * @warning If this returns non-zero, the decrypted data is not authentic
 * @note Stream cannot be used after verification
 *
 * Example:
 * @code
 * if (HiAEx2_stream_verify(&stream, received_tag) != 0) {
 *     // Authentication failed - data was tampered with
 *     // Discard all decrypted data
 * }
 * @endcode
 */
int HiAEx2_stream_verify(HiAEx2_stream_state_t *stream, const uint8_t *expected_tag);

/** @} */

/**
 * @defgroup lowlevel Low-Level Streaming API
 * @brief Advanced functions for fine-grained control over streaming operations
 *
 * This API provides direct access to the underlying cipher operations.
 * It requires careful attention to block alignment: all operations except
 * the last must process multiples of 16 bytes.
 *
 * @warning Use the high-level streaming API unless you need fine control
 * @{
 */

/**
 * @brief Initialize low-level streaming state
 *
 * Prepares the state for incremental encryption/decryption operations.
 *
 * @param state   State structure to initialize
 * @param key     Encryption/decryption key (HiAEx2_KEYBYTES bytes)
 * @param nonce   Unique nonce for this operation (HiAEx2_NONCEBYTES bytes)
 *
 * @note State must not be reused - initialize fresh state for each operation
 */
void HiAEx2_init(HiAEx2_state_t *state, const uint8_t *key, const uint8_t *nonce);

/**
 * @brief Absorb associated data
 *
 * Processes associated data for authentication. Can be called multiple times.
 *
 * @param state   Current state
 * @param ad      Associated data chunk
 * @param len     Length of chunk
 *
 * @warning All calls except the last must have len as multiple of 16
 * @note Must complete all AD before any enc/dec operations
 *
 * Example:
 * @code
 * HiAEx2_absorb(&state, ad_chunk1, 64);   // Multiple of 16
 * HiAEx2_absorb(&state, ad_chunk2, 32);   // Multiple of 16
 * HiAEx2_absorb(&state, ad_chunk3, 7);    // Last chunk - any size
 * @endcode
 */
void HiAEx2_absorb(HiAEx2_state_t *state, const uint8_t *ad, size_t len);

/**
 * @brief Finalize and generate authentication tag
 *
 * Completes the operation and produces the authentication tag.
 *
 * @param state    Current state
 * @param ad_len   Total bytes of associated data processed
 * @param msg_len  Total bytes of message data processed
 * @param tag      Output buffer for tag (HiAEx2_MACBYTES bytes)
 *
 * @note The total lengths must match actual data processed
 * @note State cannot be used after finalization
 */
void HiAEx2_finalize(HiAEx2_state_t *state, uint64_t ad_len, uint64_t msg_len, uint8_t *tag);

/**
 * @brief Encrypt data incrementally
 *
 * Encrypts plaintext and updates the internal state.
 *
 * @param state  Current state
 * @param ci     Output ciphertext buffer
 * @param mi     Input plaintext
 * @param size   Number of bytes to process
 *
 * @warning All calls except the last must have size as multiple of 16
 * @note Output buffer must be at least 'size' bytes
 *
 * Example:
 * @code
 * HiAEx2_enc(&state, ct1, pt1, 256);  // Multiple of 16
 * HiAEx2_enc(&state, ct2, pt2, 64);   // Multiple of 16
 * HiAEx2_enc(&state, ct3, pt3, 13);   // Last chunk - any size
 * @endcode
 */
void HiAEx2_enc(HiAEx2_state_t *state, uint8_t *ci, const uint8_t *mi, size_t size);

/**
 * @brief Decrypt data incrementally
 *
 * Decrypts ciphertext and updates the internal state.
 *
 * @param state  Current state
 * @param mi     Output plaintext buffer
 * @param ci     Input ciphertext
 * @param size   Number of bytes to process
 *
 * @warning All calls except the last must have size as multiple of 16
 * @note Output buffer must be at least 'size' bytes
 * @note Does not verify authentication - check tag after finalize
 */
void HiAEx2_dec(HiAEx2_state_t *state, uint8_t *mi, const uint8_t *ci, size_t size);

/**
 * @brief Encrypt partial block without updating state
 *
 * Encrypts data without updating the internal state. Used for handling
 * partial blocks when more data will follow before finalization.
 *
 * @param state  Current state (not modified)
 * @param ci     Output ciphertext buffer
 * @param mi     Input plaintext
 * @param size   Number of bytes (must be < 16)
 *
 * @warning Only use for partial blocks < 16 bytes
 * @warning State is not updated - cannot be immediately followed by finalize
 * @warning Must eventually process more data to update state properly
 *
 * Example (handling non-aligned streaming):
 * @code
 * // Have 7 bytes but more data coming later
 * uint8_t buffer[16];
 * memcpy(buffer, partial_data, 7);
 * HiAEx2_enc_partial_noupdate(&state, ct_partial, buffer, 7);
 * // ... when more data arrives to complete block ...
 * memcpy(buffer + 7, more_data, 9);  // Now have full 16-byte block
 * HiAEx2_enc(&state, ct_full, buffer, 16);  // Updates state
 * @endcode
 */
void HiAEx2_enc_partial_noupdate(HiAEx2_state_t *state, uint8_t *ci, const uint8_t *mi,
                                 size_t size);

/**
 * @brief Decrypt partial block without updating state
 *
 * Decrypts data without updating the internal state. Used for handling
 * partial blocks when more data will follow before finalization.
 *
 * @param state  Current state (not modified)
 * @param mi     Output plaintext buffer
 * @param ci     Input ciphertext
 * @param size   Number of bytes (must be < 16)
 *
 * @warning Only use for partial blocks < 16 bytes
 * @warning State is not updated - cannot be immediately followed by finalize
 * @warning Must eventually process more data to update state properly
 */
void HiAEx2_dec_partial_noupdate(HiAEx2_state_t *state, uint8_t *mi, const uint8_t *ci,
                                 size_t size);

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* HiAEx2_H */
