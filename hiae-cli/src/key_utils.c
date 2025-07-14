#include "key_utils.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#    include <bcrypt.h>
#    include <windows.h>
#    pragma comment(lib, "bcrypt.lib")
#else
#    include <fcntl.h>
#    include <sys/stat.h>
#    include <unistd.h>
#endif

int
parse_hex_string(const char *hex, uint8_t *bytes, size_t max_len)
{
    if (!hex || !bytes)
        return -1;

    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0)
        return -1;

    size_t byte_len = hex_len / 2;
    if (byte_len > max_len)
        return -1;

    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
            return -1;
        bytes[i] = (uint8_t) byte;
    }

    return (int) byte_len;
}

int
generate_random_bytes(uint8_t *buffer, size_t len)
{
    if (!buffer || len == 0)
        return -1;

#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, buffer, (ULONG) len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status == STATUS_SUCCESS) ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -1;

    ssize_t bytes_read = read(fd, buffer, len);
    close(fd);

    return (bytes_read == (ssize_t) len) ? 0 : -1;
#endif
}

int
load_key_file(const char *filename, hiae_key_material_t *km)
{
    if (!filename || !km)
        return -1;

    FILE *fp = fopen(filename, "rb");
    if (!fp)
        return -1;

    // Try to read as binary first
    size_t bytes_read = fread(km->key, 1, HIAE_KEY_SIZE, fp);
    if (bytes_read == HIAE_KEY_SIZE) {
        km->key_loaded = 1;

        // Try to read nonce if present
        bytes_read = fread(km->nonce, 1, HIAE_NONCE_SIZE, fp);
        if (bytes_read == HIAE_NONCE_SIZE) {
            km->nonce_loaded = 1;
        }
        fclose(fp);
        return 0;
    }

    // Try as hex file
    rewind(fp);
    char hex_buffer[256];
    if (fgets(hex_buffer, sizeof(hex_buffer), fp)) {
        // Remove newline
        hex_buffer[strcspn(hex_buffer, "\r\n")] = 0;

        // Parse hex key
        int key_len = parse_hex_string(hex_buffer, km->key, HIAE_KEY_SIZE);
        if (key_len == HIAE_KEY_SIZE) {
            km->key_loaded = 1;

            // Try to read hex nonce
            if (fgets(hex_buffer, sizeof(hex_buffer), fp)) {
                hex_buffer[strcspn(hex_buffer, "\r\n")] = 0;
                int nonce_len = parse_hex_string(hex_buffer, km->nonce, HIAE_NONCE_SIZE);
                if (nonce_len == HIAE_NONCE_SIZE) {
                    km->nonce_loaded = 1;
                }
            }
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

int
save_key_file(const char *filename, const hiae_key_material_t *km)
{
    if (!filename || !km || !km->key_loaded)
        return -1;

    FILE *fp = fopen(filename, "wb");
    if (!fp)
        return -1;

    // Save in binary format
    size_t written = fwrite(km->key, 1, HIAE_KEY_SIZE, fp);
    if (written != HIAE_KEY_SIZE) {
        fclose(fp);
        return -1;
    }

    if (km->nonce_loaded) {
        written = fwrite(km->nonce, 1, HIAE_NONCE_SIZE, fp);
        if (written != HIAE_NONCE_SIZE) {
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);

    // Set restrictive permissions on Unix-like systems
#ifndef _WIN32
    chmod(filename, 0600);
#endif

    return 0;
}

int
load_nonce_file(const char *filename, uint8_t *nonce)
{
    if (!filename || !nonce)
        return -1;

    FILE *fp = fopen(filename, "rb");
    if (!fp)
        return -1;

    // Try binary first
    size_t bytes_read = fread(nonce, 1, HIAE_NONCE_SIZE, fp);
    if (bytes_read == HIAE_NONCE_SIZE) {
        fclose(fp);
        return 0;
    }

    // Try hex
    rewind(fp);
    char hex_buffer[64];
    if (fgets(hex_buffer, sizeof(hex_buffer), fp)) {
        hex_buffer[strcspn(hex_buffer, "\r\n")] = 0;
        int len = parse_hex_string(hex_buffer, nonce, HIAE_NONCE_SIZE);
        fclose(fp);
        return (len == HIAE_NONCE_SIZE) ? 0 : -1;
    }

    fclose(fp);
    return -1;
}

int
save_nonce_file(const char *filename, const uint8_t *nonce)
{
    if (!filename || !nonce)
        return -1;

    FILE *fp = fopen(filename, "wb");
    if (!fp)
        return -1;

    size_t written = fwrite(nonce, 1, HIAE_NONCE_SIZE, fp);
    fclose(fp);

    return (written == HIAE_NONCE_SIZE) ? 0 : -1;
}

void
secure_wipe(void *ptr, size_t len)
{
    if (!ptr || len == 0)
        return;

    volatile uint8_t *p = (volatile uint8_t *) ptr;
    while (len--) {
        *p++ = 0;
    }
}

void
print_hex(const char *label, const uint8_t *data, size_t len)
{
    if (label)
        printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int
is_hex_string(const char *str)
{
    if (!str)
        return 0;
    size_t len = strlen(str);
    if (len % 2 != 0)
        return 0;

    for (size_t i = 0; i < len; i++) {
        if (!isxdigit(str[i]))
            return 0;
    }
    return 1;
}