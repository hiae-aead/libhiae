#ifndef KEY_UTILS_H
#define KEY_UTILS_H

#include <stddef.h>
#include <stdint.h>

#define HIAE_KEY_SIZE   32 // 256-bit key
#define HIAE_NONCE_SIZE 16 // 128-bit nonce
#define HIAE_TAG_SIZE   16 // 128-bit tag

typedef struct {
    uint8_t key[HIAE_KEY_SIZE];
    uint8_t nonce[HIAE_NONCE_SIZE];
    int     key_loaded;
    int     nonce_loaded;
} hiae_key_material_t;

// Parse hex string to bytes
int parse_hex_string(const char *hex, uint8_t *bytes, size_t max_len);

// Generate random bytes
int generate_random_bytes(uint8_t *buffer, size_t len);

// Key file operations
int load_key_file(const char *filename, hiae_key_material_t *km);
int save_key_file(const char *filename, const hiae_key_material_t *km);

// Nonce operations
int load_nonce_file(const char *filename, uint8_t *nonce);
int save_nonce_file(const char *filename, const uint8_t *nonce);

// Secure memory wiping
void secure_wipe(void *ptr, size_t len);

// Utility functions
void print_hex(const char *label, const uint8_t *data, size_t len);
int  is_hex_string(const char *str);

#endif // KEY_UTILS_H