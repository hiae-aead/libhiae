#include "HiAE.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_SIZE 1024

static void
print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int
test_case(const char *test_name, const uint8_t *key, const uint8_t *nonce, const uint8_t *ad,
          size_t ad_len, const uint8_t *pt, size_t pt_len, const size_t *ad_chunks,
          size_t ad_chunk_count, const size_t *msg_chunks, size_t msg_chunk_count)
{

    printf("\nTest: %s\n", test_name);
    printf("AD length: %zu, Message length: %zu\n", ad_len, pt_len);

    uint8_t ct_stream[MAX_SIZE];
    uint8_t ct_regular[MAX_SIZE];
    uint8_t tag_stream[16];
    uint8_t tag_regular[16];
    uint8_t pt_decrypted[MAX_SIZE];

    HiAE_encrypt(key, nonce, pt, ct_regular, pt_len, ad, ad_len, tag_regular);

    HiAE_stream_state_t stream;
    HiAE_stream_init(&stream, key, nonce);

    size_t ad_pos = 0;
    for (size_t i = 0; i < ad_chunk_count; i++) {
        size_t chunk_size = ad_chunks[i];
        if (ad_pos + chunk_size > ad_len) {
            chunk_size = ad_len - ad_pos;
        }
        if (chunk_size > 0) {
            HiAE_stream_absorb(&stream, ad + ad_pos, chunk_size);
            ad_pos += chunk_size;
        }
    }

    size_t msg_pos = 0;
    for (size_t i = 0; i < msg_chunk_count; i++) {
        size_t chunk_size = msg_chunks[i];
        if (msg_pos + chunk_size > pt_len) {
            chunk_size = pt_len - msg_pos;
        }
        if (chunk_size > 0) {
            HiAE_stream_encrypt(&stream, ct_stream + msg_pos, pt + msg_pos, chunk_size);
            msg_pos += chunk_size;
        }
    }

    HiAE_stream_finalize(&stream, tag_stream);

    if (memcmp(ct_stream, ct_regular, pt_len) != 0) {
        printf("FAIL: Ciphertext mismatch\n");
        print_hex("Stream CT", ct_stream, pt_len > 32 ? 32 : pt_len);
        print_hex("Regular CT", ct_regular, pt_len > 32 ? 32 : pt_len);
        return 1;
    }

    if (memcmp(tag_stream, tag_regular, 16) != 0) {
        printf("FAIL: Tag mismatch\n");
        print_hex("Stream tag", tag_stream, 16);
        print_hex("Regular tag", tag_regular, 16);
        return 1;
    }

    HiAE_stream_init(&stream, key, nonce);

    ad_pos = 0;
    for (size_t i = 0; i < ad_chunk_count; i++) {
        size_t chunk_size = ad_chunks[i];
        if (ad_pos + chunk_size > ad_len) {
            chunk_size = ad_len - ad_pos;
        }
        if (chunk_size > 0) {
            HiAE_stream_absorb(&stream, ad + ad_pos, chunk_size);
            ad_pos += chunk_size;
        }
    }

    msg_pos = 0;
    for (size_t i = 0; i < msg_chunk_count; i++) {
        size_t chunk_size = msg_chunks[i];
        if (msg_pos + chunk_size > pt_len) {
            chunk_size = pt_len - msg_pos;
        }
        if (chunk_size > 0) {
            HiAE_stream_decrypt(&stream, pt_decrypted + msg_pos, ct_stream + msg_pos, chunk_size);
            msg_pos += chunk_size;
        }
    }

    HiAE_stream_finalize(&stream, tag_stream);

    if (memcmp(pt_decrypted, pt, pt_len) != 0) {
        printf("FAIL: Decrypted plaintext mismatch\n");
        return 1;
    }

    printf("PASS\n");
    return 0;
}

int
main(void)
{
    printf("HiAE Streaming API Test\n");
    printf("Implementation: %s\n\n", HiAE_get_implementation_name());

    uint8_t key[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

    uint8_t nonce[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

    uint8_t ad[256];
    uint8_t pt[256];
    for (int i = 0; i < 256; i++) {
        ad[i] = i;
        pt[i] = 255 - i;
    }

    int failed = 0;

    {
        size_t ad_chunks[]  = { 0 };
        size_t msg_chunks[] = { 16 };
        failed += test_case("Empty AD, 16-byte message", key, nonce, ad, 0, pt, 16, ad_chunks, 0,
                            msg_chunks, 1);
    }

    {
        size_t ad_chunks[]  = { 32 };
        size_t msg_chunks[] = { 64 };
        failed += test_case("32-byte AD, 64-byte message (single chunks)", key, nonce, ad, 32, pt,
                            64, ad_chunks, 1, msg_chunks, 1);
    }

    {
        size_t ad_chunks[]  = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        size_t msg_chunks[] = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
        failed += test_case("16-byte AD byte-by-byte, 16-byte message byte-by-byte", key, nonce, ad,
                            16, pt, 16, ad_chunks, 16, msg_chunks, 16);
    }

    {
        size_t ad_chunks[]  = { 7, 9, 5, 11 };
        size_t msg_chunks[] = { 3, 13, 17, 31 };
        failed += test_case("32-byte AD odd chunks, 64-byte message odd chunks", key, nonce, ad, 32,
                            pt, 64, ad_chunks, 4, msg_chunks, 4);
    }

    {
        size_t ad_chunks[]  = { 15, 1, 16 };
        size_t msg_chunks[] = { 15, 1, 15, 1 };
        failed += test_case("32-byte AD alternating chunks, 32-byte message alternating", key,
                            nonce, ad, 32, pt, 32, ad_chunks, 3, msg_chunks, 4);
    }

    {
        size_t ad_chunks[]  = { 7 };
        size_t msg_chunks[] = { 7 };
        failed += test_case("7-byte AD, 7-byte message", key, nonce, ad, 7, pt, 7, ad_chunks, 1,
                            msg_chunks, 1);
    }

    {
        size_t ad_chunks[]  = { 17 };
        size_t msg_chunks[] = { 17 };
        failed += test_case("17-byte AD, 17-byte message", key, nonce, ad, 17, pt, 17, ad_chunks, 1,
                            msg_chunks, 1);
    }

    {
        size_t ad_chunks[]  = { 64, 7, 16, 3, 10 };
        size_t msg_chunks[] = { 100, 50, 50, 56 };
        failed += test_case("100-byte AD mixed chunks, 256-byte message mixed chunks", key, nonce,
                            ad, 100, pt, 256, ad_chunks, 5, msg_chunks, 4);
    }

    {
        size_t ad_chunks[]  = { 256 };
        size_t msg_chunks[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        failed += test_case("Empty AD, 55-byte message in increasing chunks", key, nonce, ad, 0, pt,
                            55, ad_chunks, 0, msg_chunks, 10);
    }

    {
        size_t ad_chunks[]  = { 8, 8 };
        size_t msg_chunks[] = { 0 };
        failed += test_case("16-byte AD in two 8-byte chunks, empty message", key, nonce, ad, 16,
                            pt, 0, ad_chunks, 2, msg_chunks, 0);
    }

    printf("\n%s Streaming API Test Summary:\n", HiAE_get_implementation_name());
    if (failed == 0) {
        printf("All tests PASSED!\n");
    } else {
        printf("FAILED: %d tests\n", failed);
    }

    return failed;
}