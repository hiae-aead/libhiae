#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../include/HiAEt.h"

void
print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int
test_basic_encryption_decryption()
{
    printf("=== Basic Encryption/Decryption Test ===\n");

    uint8_t key[32]       = { 0 };
    uint8_t nonce[16]     = { 0 };
    uint8_t plaintext[64] = "Hello, World! This is a test message for HiAEt encryption.";
    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    uint8_t tag[16];
    uint8_t ad[16] = "additional data";

    // Fill key with test pattern
    for (int i = 0; i < 32; i++) {
        key[i] = i;
    }

    // Fill nonce with test pattern
    for (int i = 0; i < 16; i++) {
        nonce[i] = i + 32;
    }

    printf("Using implementation: %s\n", HiAEt_get_implementation_name());

    // Encrypt
    int ret =
        HiAEt_encrypt(key, nonce, plaintext, ciphertext, sizeof(plaintext), ad, sizeof(ad), tag);
    if (ret != 0) {
        printf("Encryption failed with code %d\n", ret);
        return 1;
    }

    print_hex("Key", key, 32);
    print_hex("Nonce", nonce, 16);
    print_hex("Plaintext", plaintext, 64);
    print_hex("AD", ad, 16);
    print_hex("Ciphertext", ciphertext, 64);
    print_hex("Tag", tag, 16);

    // Decrypt
    ret = HiAEt_decrypt(key, nonce, decrypted, ciphertext, sizeof(ciphertext), ad, sizeof(ad), tag);
    if (ret != 0) {
        printf("Decryption failed with code %d\n", ret);
        return 1;
    }

    print_hex("Decrypted", decrypted, 64);

    // Verify
    if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
        printf("✓ Basic encryption/decryption test PASSED\n");
        return 0;
    } else {
        printf("✗ Basic encryption/decryption test FAILED\n");
        return 1;
    }
}

int
test_streaming_api()
{
    printf("\n=== Streaming API Test ===\n");

    uint8_t key[32]   = { 0 };
    uint8_t nonce[16] = { 0 };
    uint8_t plaintext[100] =
        "This is a longer test message for the streaming API. It should be processed correctly.";
    uint8_t ciphertext[100];
    uint8_t decrypted[100];
    uint8_t tag1[16], tag2[16];
    uint8_t ad[20] = "streaming test data";

    // Fill key and nonce
    for (int i = 0; i < 32; i++)
        key[i] = i;
    for (int i = 0; i < 16; i++)
        nonce[i] = i + 64;

    // Encrypt with streaming API
    HiAEt_stream_state_t enc_stream;
    HiAEt_stream_init(&enc_stream, key, nonce);
    HiAEt_stream_absorb(&enc_stream, ad, sizeof(ad));
    HiAEt_stream_encrypt(&enc_stream, ciphertext, plaintext, sizeof(plaintext));
    HiAEt_stream_finalize(&enc_stream, tag1);

    print_hex("Stream Ciphertext", ciphertext, 100);
    print_hex("Stream Tag", tag1, 16);

    // Decrypt with streaming API
    HiAEt_stream_state_t dec_stream;
    HiAEt_stream_init(&dec_stream, key, nonce);
    HiAEt_stream_absorb(&dec_stream, ad, sizeof(ad));
    HiAEt_stream_decrypt(&dec_stream, decrypted, ciphertext, sizeof(ciphertext));
    HiAEt_stream_finalize(&dec_stream, tag2);

    print_hex("Stream Decrypted", decrypted, 100);
    print_hex("Stream Dec Tag", tag2, 16);

    // Verify tags match
    if (memcmp(tag1, tag2, 16) != 0) {
        printf("✗ Streaming API tags don't match\n");
        return 1;
    }

    // Verify plaintext recovered
    if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
        printf("✓ Streaming API test PASSED\n");
        return 0;
    } else {
        printf("✗ Streaming API test FAILED\n");
        return 1;
    }
}

int
test_low_level_api()
{
    printf("\n=== Low-Level API Test ===\n");

    uint8_t key[32]       = { 0 };
    uint8_t nonce[16]     = { 0 };
    uint8_t plaintext[48] = "Low-level API test with exact multiple of 16.";
    uint8_t ciphertext[48];
    uint8_t decrypted[48];
    uint8_t tag1[16], tag2[16];
    uint8_t ad[16] = "low level test";

    // Fill key and nonce
    for (int i = 0; i < 32; i++)
        key[i] = i + 100;
    for (int i = 0; i < 16; i++)
        nonce[i] = i + 132;

    // Encrypt with low-level API
    HiAEt_state_t enc_state;
    HiAEt_init(&enc_state, key, nonce);
    HiAEt_absorb(&enc_state, ad, sizeof(ad));
    HiAEt_enc(&enc_state, ciphertext, plaintext, sizeof(plaintext));
    HiAEt_finalize(&enc_state, sizeof(ad), sizeof(plaintext), tag1);

    print_hex("Low-level Ciphertext", ciphertext, 48);
    print_hex("Low-level Tag", tag1, 16);

    // Decrypt with low-level API
    HiAEt_state_t dec_state;
    HiAEt_init(&dec_state, key, nonce);
    HiAEt_absorb(&dec_state, ad, sizeof(ad));
    HiAEt_dec(&dec_state, decrypted, ciphertext, sizeof(ciphertext));
    HiAEt_finalize(&dec_state, sizeof(ad), sizeof(ciphertext), tag2);

    print_hex("Low-level Decrypted", decrypted, 48);
    print_hex("Low-level Dec Tag", tag2, 16);

    // Verify tags match
    if (memcmp(tag1, tag2, 16) != 0) {
        printf("✗ Low-level API tags don't match\n");
        return 1;
    }

    // Verify plaintext recovered
    if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
        printf("✓ Low-level API test PASSED\n");
        return 0;
    } else {
        printf("✗ Low-level API test FAILED\n");
        return 1;
    }
}

int
test_empty_message()
{
    printf("\n=== Empty Message Test ===\n");

    uint8_t key[32]   = { 0 };
    uint8_t nonce[16] = { 0 };
    uint8_t tag[16];
    uint8_t ad[8] = "empty";

    // Fill key and nonce
    for (int i = 0; i < 32; i++)
        key[i] = i + 200;
    for (int i = 0; i < 16; i++)
        nonce[i] = i + 232;

    // Test encryption with empty message
    int ret = HiAEt_encrypt(key, nonce, NULL, NULL, 0, ad, sizeof(ad), tag);
    if (ret != 0) {
        printf("Empty message encryption failed with code %d\n", ret);
        return 1;
    }

    print_hex("Empty Message Tag", tag, 16);

    // Test decryption with empty message
    ret = HiAEt_decrypt(key, nonce, NULL, NULL, 0, ad, sizeof(ad), tag);
    if (ret != 0) {
        printf("Empty message decryption failed with code %d\n", ret);
        return 1;
    }

    printf("✓ Empty message test PASSED\n");
    return 0;
}

int
test_authentication_failure()
{
    printf("\n=== Authentication Failure Test ===\n");

    uint8_t key[32]       = { 0 };
    uint8_t nonce[16]     = { 0 };
    uint8_t plaintext[32] = "Authentication failure test";
    uint8_t ciphertext[32];
    uint8_t decrypted[32];
    uint8_t tag[16];
    uint8_t ad[16] = "auth test";

    // Fill key and nonce
    for (int i = 0; i < 32; i++)
        key[i] = i;
    for (int i = 0; i < 16; i++)
        nonce[i] = i + 32;

    // Encrypt
    int ret =
        HiAEt_encrypt(key, nonce, plaintext, ciphertext, sizeof(plaintext), ad, sizeof(ad), tag);
    if (ret != 0) {
        printf("Encryption failed with code %d\n", ret);
        return 1;
    }

    // Corrupt the tag
    tag[0] ^= 1;

    // Try to decrypt with corrupted tag
    ret = HiAEt_decrypt(key, nonce, decrypted, ciphertext, sizeof(ciphertext), ad, sizeof(ad), tag);
    if (ret == 0) {
        printf("✗ Authentication failure test FAILED - should have rejected corrupted tag\n");
        return 1;
    } else {
        printf("✓ Authentication failure test PASSED - correctly rejected corrupted tag\n");
        return 0;
    }
}

int
main()
{
    printf("HiAEt Function Tests\n");
    printf("Implementation: %s\n", HiAEt_get_implementation_name());
    printf("====================\n");

    int failures = 0;

    failures += test_basic_encryption_decryption();
    failures += test_streaming_api();
    failures += test_low_level_api();
    failures += test_empty_message();
    failures += test_authentication_failure();

    printf("\n====================\n");
    if (failures == 0) {
        printf("All tests PASSED!\n");
        return 0;
    } else {
        printf("%d test(s) FAILED!\n", failures);
        return 1;
    }
}