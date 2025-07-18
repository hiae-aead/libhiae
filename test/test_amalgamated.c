/*
 * Test for HiAE Amalgamated Version
 *
 * This test verifies that the amalgamated file can be built and works correctly.
 * It tests basic functionality by compiling with the amalgamated source and
 * running encryption/decryption operations.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Include the amalgamated file
#include "../HiAE_amalgamated.c"

// Simple test function to verify basic functionality
static int
test_basic_functionality(void)
{
    // Test data
    uint8_t key[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    uint8_t nonce[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t plaintext[64] = { 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64,
                              0x21, 0x20, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61,
                              0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61,
                              0x67, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x48, 0x69, 0x41, 0x45,
                              0x20, 0x61, 0x6d, 0x61, 0x6c, 0x67, 0x61, 0x6d, 0x61, 0x74, 0x65,
                              0x64, 0x20, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67 };

    uint8_t ciphertext[64];
    uint8_t decrypted[64];
    uint8_t tag[16];

    printf("Testing HiAE amalgamated version...\n");
    printf("Implementation: %s\n", HiAE_get_implementation_name());

    // Test encryption
    int ret = HiAE_encrypt(key, nonce, plaintext, ciphertext, 64, NULL, 0, tag);
    if (ret != 0) {
        printf("ERROR: HiAE_encrypt failed with return code %d\n", ret);
        return 1;
    }
    printf("✓ Encryption successful\n");

    // Test decryption
    ret = HiAE_decrypt(key, nonce, decrypted, ciphertext, 64, NULL, 0, tag);
    if (ret != 0) {
        printf("ERROR: HiAE_decrypt failed with return code %d\n", ret);
        return 1;
    }
    printf("✓ Decryption successful\n");

    // Verify plaintext matches decrypted
    if (memcmp(plaintext, decrypted, 64) != 0) {
        printf("ERROR: Decrypted text does not match original plaintext\n");
        return 1;
    }
    printf("✓ Plaintext verification successful\n");

    return 0;
}

static int
test_streaming_api(void)
{
    printf("\nTesting streaming API...\n");

    uint8_t key[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    uint8_t nonce[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t plaintext[100] =
        "This is a test message for streaming API functionality in the amalgamated version.";
    uint8_t ciphertext[100];
    uint8_t decrypted[100];
    uint8_t tag[16];

    HiAE_stream_state_t stream;

    // Test streaming encryption
    HiAE_stream_init(&stream, key, nonce);
    HiAE_stream_encrypt(&stream, ciphertext, plaintext, 100);
    HiAE_stream_finalize(&stream, tag);
    printf("✓ Streaming encryption successful\n");

    // Test streaming decryption
    HiAE_stream_init(&stream, key, nonce);
    HiAE_stream_decrypt(&stream, decrypted, ciphertext, 100);

    int ret = HiAE_stream_verify(&stream, tag);
    if (ret != 0) {
        printf("ERROR: HiAE_stream_verify failed with return code %d\n", ret);
        return 1;
    }
    printf("✓ Streaming decryption successful\n");

    // Verify plaintext matches decrypted
    if (memcmp(plaintext, decrypted, 100) != 0) {
        printf("ERROR: Streaming decrypted text does not match original plaintext\n");
        return 1;
    }
    printf("✓ Streaming plaintext verification successful\n");

    return 0;
}

static int
test_mac_only(void)
{
    printf("\nTesting MAC-only functionality...\n");

    uint8_t key[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    uint8_t nonce[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    uint8_t data[50] = "This is a test message for MAC-only functionality";
    uint8_t tag[16];

    int ret = HiAE_mac(key, nonce, data, 50, tag);
    if (ret != 0) {
        printf("ERROR: HiAE_mac failed with return code %d\n", ret);
        return 1;
    }
    printf("✓ MAC-only operation successful\n");

    return 0;
}

int
main(void)
{
    printf("HiAE Amalgamated Version Test\n");
    printf("=============================\n");

    // Run basic functionality test
    if (test_basic_functionality() != 0) {
        printf("\n❌ Basic functionality test FAILED\n");
        return 1;
    }

    // Run streaming API test
    if (test_streaming_api() != 0) {
        printf("\n❌ Streaming API test FAILED\n");
        return 1;
    }

    // Run MAC-only test
    if (test_mac_only() != 0) {
        printf("\n❌ MAC-only test FAILED\n");
        return 1;
    }

    printf("\n🎉 All tests PASSED!\n");
    printf("The amalgamated version is working correctly.\n");

    return 0;
}