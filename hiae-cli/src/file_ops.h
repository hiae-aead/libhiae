#ifndef FILE_OPS_H
#define FILE_OPS_H

#include "key_utils.h"
#include <stddef.h>
#include <stdint.h>

#define CHUNK_SIZE 1 * 1024 * 1024 // Process files in 1MB chunks

// Progress callback function type
typedef void (*progress_callback_t)(size_t current, size_t total);

// Progress information structure
typedef struct {
    size_t              total_bytes;
    size_t              processed_bytes;
    progress_callback_t callback;
    double              last_update_time;
} progress_info_t;

// Error codes
typedef enum {
    HIAE_CLI_SUCCESS          = 0,
    HIAE_CLI_ERR_ARGS         = 1,
    HIAE_CLI_ERR_FILE_READ    = 2,
    HIAE_CLI_ERR_FILE_WRITE   = 3,
    HIAE_CLI_ERR_KEY_FORMAT   = 4,
    HIAE_CLI_ERR_AUTH_FAILED  = 5,
    HIAE_CLI_ERR_MEMORY       = 6,
    HIAE_CLI_ERR_INVALID_SIZE = 7,
    HIAE_CLI_ERR_NONCE_REUSE  = 8
} hiae_cli_error_t;

// File metadata header for storing nonce and tag
typedef struct {
    uint8_t  magic[8]; // "HIAE\x00\x01\x00\x00"
    uint8_t  nonce[16];
    uint8_t  tag[16];
    uint64_t file_size; // Original file size
} hiae_file_header_t;

// Main encryption/decryption functions
int encrypt_file(const char *input_path, const char *output_path, const hiae_key_material_t *km,
                 const uint8_t *ad, size_t ad_len, progress_info_t *progress, int embed_metadata);

int decrypt_file(const char *input_path, const char *output_path, const hiae_key_material_t *km,
                 const uint8_t *ad, size_t ad_len, progress_info_t *progress,
                 int embedded_metadata);

// Tag file operations
int save_tag_file(const char *filename, const uint8_t *tag);
int load_tag_file(const char *filename, uint8_t *tag);

// Error message helper
const char *get_error_message(hiae_cli_error_t err);

// Default progress callback
void default_progress_callback(size_t current, size_t total);

#endif // FILE_OPS_H
