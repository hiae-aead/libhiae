/*
 * HiAEx2 Test Vector Validation
 * Test vectors for HiAEx2 cipher implementation
 */

#include "HiAEx2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Helper function to convert hex string to bytes
static int
hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len)
{
    size_t len = strlen(hex);
    if (len % 2 != 0)
        return -1;

    size_t byte_len = len / 2;
    if (byte_len > max_len)
        return -1;

    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte;
        if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
            return -1;
        bytes[i] = (uint8_t) byte;
    }
    return byte_len;
}

// Helper function to print hex bytes
static void
print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Test vector structure
typedef struct {
    const char *name;
    const char *key;
    const char *nonce;
    const char *ad;
    const char *plaintext;
    const char *ciphertext;
    const char *tag;
} TestVector;

static const TestVector test_vectors[] = {
    // Test Vector 1 - Empty plaintext, no AD
    { .name       = "Test Vector 1",
      .key        = "4b7a9c3ef8d2165a0b3e5f8c9d4a7b1e2c5f8a9d3b6e4c7f0a1d2e5b8c9f4a7d",
      .nonce      = "a5b8c2d9e3f4a7b1c8d5e9f2a3b6c7d8",
      .ad         = "",
      .plaintext  = "",
      .ciphertext = "",
      .tag        = "814466e804ffb89e586130ef8c5a09eb" },

    // Test Vector 2 - Single block plaintext, no AD
    { .name       = "Test Vector 2",
      .key        = "2f8e4d7c3b9a5e1f8d2c6b4a9f3e7d5c1b8a6f4e3d2c9b5a8f7e6d4c3b2a1f9e",
      .nonce      = "7c3e9f5a1d8b4c6f2e9a5d7b3f8c1e4a",
      .ad         = "",
      .plaintext  = "55f00fcc339669aa55f00fcc339669aa",
      .ciphertext = "b1b159fa6b6d3088a4fdb2d70aae888e",
      .tag        = "c07f5633f8125b73839805aa0e029f9e" },

    // Test Vector 3 - Empty plaintext with AD
    { .name       = "Test Vector 3",
      .key        = "9f3e7d5c4b8a2f1e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e",
      .nonce      = "3d8c7f2a5b9e4c1f8a6d3b7e5c2f9a4d",
      .ad         = "394a5b6c7d8e9fb0c1d2e3f405162738495a6b7c8d9eafc0d1e2f30415263748",
      .plaintext  = "",
      .ciphertext = "",
      .tag        = "0802b8d956e7c9cce970750b984aa2c7" },

    // Test Vector 4 - 32-byte aligned plaintext
    { .name       = "Test Vector 4",
      .key        = "6c8f2d5a9e3b7f4c1d8a5e9f3c7b2d6a4f8e1c9b5d3a7e2f4c8b6d9a1e5f3c7d",
      .nonce      = "9a5c7e3f1b8d4a6c2e9f5b7d3a8c1e6f",
      .ad         = "",
      .plaintext  = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      .ciphertext = "ad8a0a8a056d1584022c656b23bba01b9b39f54495681ef0764c838796b0ab90",
      .tag        = "fd86bc44dda4966a386923bd29fac27c" },

    // Test Vector 5 - Single byte plaintext
    { .name       = "Test Vector 5",
      .key        = "7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a",
      .nonce      = "2e7c9f5d3b8a4c6f1e9b5d7a3f8c2e4a",
      .ad         = "",
      .plaintext  = "ff",
      .ciphertext = "32",
      .tag        = "15a55f0bbffc3d6bc6c192db1cb19768" }
};

static const size_t num_test_vectors = sizeof(test_vectors) / sizeof(test_vectors[0]);

// Run a single test vector
static int
run_test_vector(const TestVector *tv)
{
    uint8_t key[HIAEX2_KEYBYTES], nonce[HIAEX2_NONCEBYTES], tag[HIAEX2_MACBYTES];
    uint8_t ad[2048], plaintext[2048], ciphertext[2048];
    uint8_t computed_ciphertext[2048], computed_tag[HIAEX2_MACBYTES];
    uint8_t decrypted[2048];

    // Parse inputs
    if (hex_to_bytes(tv->key, key, sizeof(key)) != HIAEX2_KEYBYTES) {
        printf("  ERROR: Failed to parse key\n");
        return 0;
    }

    if (hex_to_bytes(tv->nonce, nonce, sizeof(nonce)) != HIAEX2_NONCEBYTES) {
        printf("  ERROR: Failed to parse nonce\n");
        return 0;
    }

    int ad_len = hex_to_bytes(tv->ad, ad, sizeof(ad));
    if (ad_len < 0) {
        printf("  ERROR: Failed to parse AD\n");
        return 0;
    }

    int pt_len = hex_to_bytes(tv->plaintext, plaintext, sizeof(plaintext));
    if (pt_len < 0) {
        printf("  ERROR: Failed to parse plaintext\n");
        return 0;
    }

    int ct_len = hex_to_bytes(tv->ciphertext, ciphertext, sizeof(ciphertext));
    if (ct_len < 0 || ct_len != pt_len) {
        printf("  ERROR: Failed to parse ciphertext or length mismatch\n");
        return 0;
    }

    if (hex_to_bytes(tv->tag, tag, sizeof(tag)) != HIAEX2_MACBYTES) {
        printf("  ERROR: Failed to parse tag\n");
        return 0;
    }

    // Test encryption
    HiAEx2_encrypt(key, nonce, plaintext, computed_ciphertext, pt_len, ad, ad_len, computed_tag);

    // Verify ciphertext
    if (memcmp(computed_ciphertext, ciphertext, ct_len) != 0) {
        printf("  ERROR: Ciphertext mismatch\n");
        printf("  Expected: ");
        print_hex("", ciphertext, ct_len > 32 ? 32 : ct_len);
        if (ct_len > 32)
            printf("  ...\n");
        printf("  Computed: ");
        print_hex("", computed_ciphertext, ct_len > 32 ? 32 : ct_len);
        if (ct_len > 32)
            printf("  ...\n");
        return 0;
    }

    // Verify tag
    if (memcmp(computed_tag, tag, HIAEX2_MACBYTES) != 0) {
        printf("  ERROR: Tag mismatch\n");
        print_hex("  Expected", tag, HIAEX2_MACBYTES);
        print_hex("  Computed", computed_tag, HIAEX2_MACBYTES);
        return 0;
    }

    // Test decryption
    int auth_result = HiAEx2_decrypt(key, nonce, decrypted, ciphertext, ct_len, ad, ad_len, tag);

    if (auth_result != 0) {
        printf("  ERROR: Authentication failed during decryption (returned %d)\n", auth_result);
        return 0;
    }

    if (memcmp(decrypted, plaintext, pt_len) != 0) {
        printf("  ERROR: Decrypted plaintext mismatch\n");
        return 0;
    }

    return 1;
}

int
main(void)
{
    printf("========================================\n");
    printf("HiAEx2 Test Vector Validation\n");
    printf("Implementation: %s\n", HiAEx2_get_implementation_name());
    printf("========================================\n\n");

    int passed = 0;
    int failed = 0;

    for (size_t i = 0; i < num_test_vectors; i++) {
        const TestVector *tv = &test_vectors[i];
        printf("%s:\n", tv->name);
        printf("  AD length: %zu bytes\n", strlen(tv->ad) / 2);
        printf("  Message length: %zu bytes\n", strlen(tv->plaintext) / 2);

        if (run_test_vector(tv)) {
            printf("  PASSED\n");
            passed++;
        } else {
            printf("  FAILED\n");
            failed++;
        }
        printf("\n");
    }

    printf("========================================\n");
    printf("Summary: %d passed, %d failed\n", passed, failed);
    printf("========================================\n");

    return failed > 0 ? 1 : 0;
}