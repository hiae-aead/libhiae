#include "file_ops.h"
#include "../include/HiAE.h"
#include "platform.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t HIAE_MAGIC[8] = { 'H', 'I', 'A', 'E', 0, 1, 0, 0 };

void
default_progress_callback(size_t current, size_t total)
{
    if (total == 0)
        return;

    int percent   = (int) ((current * 100) / total);
    int bar_width = 40;
    int filled    = (bar_width * percent) / 100;

    clear_line();
    printf("[");
    for (int i = 0; i < bar_width; i++) {
        if (i < filled)
            printf("=");
        else
            printf(" ");
    }
    printf("] %3d%% (%zu/%zu MB)", percent, current / (1024 * 1024), total / (1024 * 1024));
    fflush(stdout);

    if (current == total)
        printf("\n");
}

int
encrypt_file(const char *input_path, const char *output_path, const hiae_key_material_t *km,
             const uint8_t *ad, size_t ad_len, progress_info_t *progress, int embed_metadata)
{

    if (!input_path || !output_path || !km || !km->key_loaded || !km->nonce_loaded) {
        return HIAE_CLI_ERR_ARGS;
    }

    // Open input file
    FILE *in_fp = fopen(input_path, "rb");
    if (!in_fp) {
        return HIAE_CLI_ERR_FILE_READ;
    }

    // Get file size
    int64_t file_size = get_file_size(input_path);
    if (file_size < 0) {
        fclose(in_fp);
        return HIAE_CLI_ERR_FILE_READ;
    }

    // Open output file
    FILE *out_fp = fopen(output_path, "wb");
    if (!out_fp) {
        fclose(in_fp);
        return HIAE_CLI_ERR_FILE_WRITE;
    }

    // Initialize progress
    if (progress) {
        progress->total_bytes      = (size_t) file_size;
        progress->processed_bytes  = 0;
        progress->last_update_time = get_time();
    }

    // Write header if embedding metadata
    hiae_file_header_t header;
    if (embed_metadata) {
        memcpy(header.magic, HIAE_MAGIC, 8);
        memcpy(header.nonce, km->nonce, HIAE_NONCE_SIZE);
        header.file_size = (uint64_t) file_size;
        // Tag will be filled later

        // Write header (without tag for now)
        if (fwrite(&header, 1, sizeof(header) - HIAE_TAG_SIZE, out_fp) !=
            sizeof(header) - HIAE_TAG_SIZE) {
            fclose(in_fp);
            fclose(out_fp);
            return HIAE_CLI_ERR_FILE_WRITE;
        }
    }

    // Allocate buffers
    uint8_t *plaintext  = malloc(CHUNK_SIZE);
    uint8_t *ciphertext = malloc(CHUNK_SIZE);
    if (!plaintext || !ciphertext) {
        free(plaintext);
        free(ciphertext);
        fclose(in_fp);
        fclose(out_fp);
        return HIAE_CLI_ERR_MEMORY;
    }

    // Initialize HiAE streaming state
    HiAE_stream_state_t stream;
    HiAE_stream_init(&stream, km->key, km->nonce);

    // Process additional data if provided
    if (ad && ad_len > 0) {
        HiAE_stream_absorb(&stream, ad, ad_len);
    }

    // Encrypt file in chunks
    size_t bytes_read;
    int    error = HIAE_CLI_SUCCESS;

    while ((bytes_read = fread(plaintext, 1, CHUNK_SIZE, in_fp)) > 0) {
        // Encrypt chunk
        HiAE_stream_encrypt(&stream, ciphertext, plaintext, bytes_read);

        // Write encrypted data
        if (fwrite(ciphertext, 1, bytes_read, out_fp) != bytes_read) {
            error = HIAE_CLI_ERR_FILE_WRITE;
            break;
        }

        // Update progress
        if (progress) {
            progress->processed_bytes += bytes_read;
            double current_time = get_time();
            if (current_time - progress->last_update_time > 0.1 ||
                progress->processed_bytes == progress->total_bytes) {
                if (progress->callback) {
                    progress->callback(progress->processed_bytes, progress->total_bytes);
                }
                progress->last_update_time = current_time;
            }
        }
    }

    // Check for read error
    if (ferror(in_fp)) {
        error = HIAE_CLI_ERR_FILE_READ;
    }

    // Finalize and get tag
    uint8_t tag[HIAE_TAG_SIZE];
    if (error == HIAE_CLI_SUCCESS) {
        HiAE_stream_finalize(&stream, tag);

        if (embed_metadata) {
            // Write tag at the end
            if (fwrite(tag, 1, HIAE_TAG_SIZE, out_fp) != HIAE_TAG_SIZE) {
                error = HIAE_CLI_ERR_FILE_WRITE;
            }
        } else {
            // Save tag to separate file
            char tag_filename[1024];
            snprintf(tag_filename, sizeof(tag_filename), "%s.tag", output_path);
            if (save_tag_file(tag_filename, tag) != 0) {
                error = HIAE_CLI_ERR_FILE_WRITE;
            }
        }
    }

    // Clean up
    secure_wipe(plaintext, CHUNK_SIZE);
    secure_wipe(ciphertext, CHUNK_SIZE);
    free(plaintext);
    free(ciphertext);
    fclose(in_fp);
    fclose(out_fp);

    // Remove output file on error
    if (error != HIAE_CLI_SUCCESS) {
        remove(output_path);
    }

    return error;
}

int
decrypt_file(const char *input_path, const char *output_path, const hiae_key_material_t *km,
             const uint8_t *ad, size_t ad_len, progress_info_t *progress, int embedded_metadata)
{

    if (!input_path || !output_path || !km || !km->key_loaded) {
        return HIAE_CLI_ERR_ARGS;
    }

    // Open input file
    FILE *in_fp = fopen(input_path, "rb");
    if (!in_fp) {
        return HIAE_CLI_ERR_FILE_READ;
    }

    // Get file size
    int64_t file_size = get_file_size(input_path);
    if (file_size < 0) {
        fclose(in_fp);
        return HIAE_CLI_ERR_FILE_READ;
    }

    hiae_file_header_t header;
    uint8_t            actual_nonce[HIAE_NONCE_SIZE];
    uint8_t            tag[HIAE_TAG_SIZE];
    size_t             data_offset = 0;
    size_t             data_size   = (size_t) file_size;

    if (embedded_metadata) {
        // Read header
        if (fread(&header, 1, sizeof(header) - HIAE_TAG_SIZE, in_fp) !=
            sizeof(header) - HIAE_TAG_SIZE) {
            fclose(in_fp);
            return HIAE_CLI_ERR_FILE_READ;
        }

        // Verify magic
        if (memcmp(header.magic, HIAE_MAGIC, 8) != 0) {
            fclose(in_fp);
            return HIAE_CLI_ERR_FILE_READ;
        }

        // Use nonce from header if not provided
        if (km->nonce_loaded) {
            memcpy(actual_nonce, km->nonce, HIAE_NONCE_SIZE);
        } else {
            memcpy(actual_nonce, header.nonce, HIAE_NONCE_SIZE);
        }

        data_offset = sizeof(header) - HIAE_TAG_SIZE;
        data_size   = (size_t) file_size - sizeof(header);

        // Seek to read tag at the end
        fseek(in_fp, -HIAE_TAG_SIZE, SEEK_END);
        if (fread(tag, 1, HIAE_TAG_SIZE, in_fp) != HIAE_TAG_SIZE) {
            fclose(in_fp);
            return HIAE_CLI_ERR_FILE_READ;
        }

        // Seek back to data start
        fseek(in_fp, data_offset, SEEK_SET);
    } else {
        // Nonce must be provided
        if (!km->nonce_loaded) {
            fclose(in_fp);
            return HIAE_CLI_ERR_ARGS;
        }
        memcpy(actual_nonce, km->nonce, HIAE_NONCE_SIZE);

        // Load tag from separate file
        char tag_filename[1024];
        snprintf(tag_filename, sizeof(tag_filename), "%s.tag", input_path);
        if (load_tag_file(tag_filename, tag) != 0) {
            fclose(in_fp);
            return HIAE_CLI_ERR_FILE_READ;
        }
    }

    // Open output file
    FILE *out_fp = fopen(output_path, "wb");
    if (!out_fp) {
        fclose(in_fp);
        return HIAE_CLI_ERR_FILE_WRITE;
    }

    // Initialize progress
    if (progress) {
        progress->total_bytes      = data_size;
        progress->processed_bytes  = 0;
        progress->last_update_time = get_time();
    }

    // Allocate buffers
    uint8_t *ciphertext = malloc(CHUNK_SIZE);
    uint8_t *plaintext  = malloc(CHUNK_SIZE);
    if (!ciphertext || !plaintext) {
        free(ciphertext);
        free(plaintext);
        fclose(in_fp);
        fclose(out_fp);
        return HIAE_CLI_ERR_MEMORY;
    }

    // Initialize HiAE streaming state
    HiAE_stream_state_t stream;
    HiAE_stream_init(&stream, km->key, actual_nonce);

    // Process additional data if provided
    if (ad && ad_len > 0) {
        HiAE_stream_absorb(&stream, ad, ad_len);
    }

    // Decrypt file in chunks
    size_t bytes_remaining = data_size;
    size_t bytes_read;
    int    error = HIAE_CLI_SUCCESS;

    while (bytes_remaining > 0 && error == HIAE_CLI_SUCCESS) {
        size_t to_read = (bytes_remaining < CHUNK_SIZE) ? bytes_remaining : CHUNK_SIZE;
        bytes_read     = fread(ciphertext, 1, to_read, in_fp);

        if (bytes_read != to_read) {
            error = HIAE_CLI_ERR_FILE_READ;
            break;
        }

        // Decrypt chunk
        HiAE_stream_decrypt(&stream, plaintext, ciphertext, bytes_read);

        // Write decrypted data
        if (fwrite(plaintext, 1, bytes_read, out_fp) != bytes_read) {
            error = HIAE_CLI_ERR_FILE_WRITE;
            break;
        }

        bytes_remaining -= bytes_read;

        // Update progress
        if (progress) {
            progress->processed_bytes += bytes_read;
            double current_time = get_time();
            if (current_time - progress->last_update_time > 0.1 ||
                progress->processed_bytes == progress->total_bytes) {
                if (progress->callback) {
                    progress->callback(progress->processed_bytes, progress->total_bytes);
                }
                progress->last_update_time = current_time;
            }
        }
    }

    // Verify authentication tag
    if (error == HIAE_CLI_SUCCESS) {
        int verify_result = HiAE_stream_verify(&stream, tag);
        if (verify_result != 0) {
            error = HIAE_CLI_ERR_AUTH_FAILED;
        }
    }

    // Clean up
    secure_wipe(plaintext, CHUNK_SIZE);
    secure_wipe(ciphertext, CHUNK_SIZE);
    free(plaintext);
    free(ciphertext);
    fclose(in_fp);
    fclose(out_fp);

    // Remove output file on error
    if (error != HIAE_CLI_SUCCESS) {
        remove(output_path);
    }

    return error;
}

int
save_tag_file(const char *filename, const uint8_t *tag)
{
    if (!filename || !tag)
        return -1;

    FILE *fp = fopen(filename, "wb");
    if (!fp)
        return -1;

    size_t written = fwrite(tag, 1, HIAE_TAG_SIZE, fp);
    fclose(fp);

    return (written == HIAE_TAG_SIZE) ? 0 : -1;
}

int
load_tag_file(const char *filename, uint8_t *tag)
{
    if (!filename || !tag)
        return -1;

    FILE *fp = fopen(filename, "rb");
    if (!fp)
        return -1;

    size_t bytes_read = fread(tag, 1, HIAE_TAG_SIZE, fp);
    fclose(fp);

    return (bytes_read == HIAE_TAG_SIZE) ? 0 : -1;
}

const char *
get_error_message(hiae_cli_error_t err)
{
    switch (err) {
    case HIAE_CLI_SUCCESS:
        return "Success";
    case HIAE_CLI_ERR_ARGS:
        return "Invalid arguments";
    case HIAE_CLI_ERR_FILE_READ:
        return "Failed to read file";
    case HIAE_CLI_ERR_FILE_WRITE:
        return "Failed to write file";
    case HIAE_CLI_ERR_KEY_FORMAT:
        return "Invalid key format";
    case HIAE_CLI_ERR_AUTH_FAILED:
        return "Authentication failed - file may be corrupted or tampered";
    case HIAE_CLI_ERR_MEMORY:
        return "Memory allocation failed";
    case HIAE_CLI_ERR_INVALID_SIZE:
        return "Invalid file size";
    case HIAE_CLI_ERR_NONCE_REUSE:
        return "Nonce reuse detected - security compromised";
    default:
        return "Unknown error";
    }
}