#include "HiAE.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define REPEAT 262144

const int len_test_case = 9;
size_t    test_case[9]  = { 16, 64, 256, 512, 1024, 2048, 4096, 8192, 16384 };

void
print_data(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

double
speed_test_ad_work(size_t len)
{
    uint8_t key[HIAE_KEYBYTES];
    memset(key, 1, HIAE_KEYBYTES);
    uint8_t nonce[HIAE_NONCEBYTES];
    memset(nonce, 1, HIAE_NONCEBYTES);
    size_t   ad_len = len;
    uint8_t *ad     = (uint8_t *) malloc(ad_len);
    memset(ad, 1, ad_len);
    clock_t start, end;
    uint8_t tag[HIAE_MACBYTES];
    start = clock();
    for (size_t iter = REPEAT; iter > 0; iter--) {
        HiAE_mac(key, nonce, ad, ad_len, tag);
    }
    end = clock();

    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    double speed         = ((double) REPEAT * len) / (cpu_time_used * (125000000));

    return speed;
}

double
speed_test_encode_work(size_t len, int AEAD)
{
    uint8_t key[HIAE_KEYBYTES];
    memset(key, 1, HIAE_KEYBYTES);
    uint8_t nonce[HIAE_NONCEBYTES];
    memset(nonce, 1, HIAE_NONCEBYTES);
    size_t   ad_len = 48;
    uint8_t *ad     = (uint8_t *) malloc(ad_len);
    memset(ad, 1, ad_len);
    size_t   plain_len = len;
    uint8_t *msg       = (uint8_t *) malloc(plain_len);
    uint8_t *ct        = (uint8_t *) malloc(plain_len);
    memset(msg, 0x1, plain_len);
    clock_t start, end;

    if (AEAD == 1) {
        uint8_t tag[HIAE_MACBYTES];
        start = clock();
        for (size_t iter = REPEAT; iter > 0; iter--) {
            HiAE_encrypt(key, nonce, msg, ct, plain_len, ad, ad_len, tag);
        }
        end = clock();
    } else {
        uint8_t tag[HIAE_MACBYTES];
        start = clock();
        for (size_t iter = REPEAT; iter > 0; iter--) {
            HiAE_encrypt(key, nonce, msg, ct, plain_len, NULL, 0, tag);
        }
        end = clock();
    }

    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    double speed         = ((double) REPEAT * plain_len) / (cpu_time_used * (125000000));

    return speed;
}

double
speed_test_decode_work(size_t len, int AEAD)
{
    uint8_t key[HIAE_KEYBYTES];
    memset(key, 1, HIAE_KEYBYTES);
    uint8_t nonce[HIAE_NONCEBYTES];
    memset(nonce, 1, HIAE_NONCEBYTES);
    size_t   ad_len = 48;
    uint8_t *ad     = (uint8_t *) malloc(ad_len);
    memset(ad, 1, ad_len);
    size_t   plain_len = len;
    uint8_t *msg       = (uint8_t *) malloc(plain_len);
    uint8_t *ct        = (uint8_t *) malloc(plain_len);
    memset(msg, 0x1, plain_len);
    clock_t start, end;

    if (AEAD == 1) {
        uint8_t tag[HIAE_MACBYTES];
        // Generate valid ciphertext and tag for AEAD decryption test
        HiAE_encrypt(key, nonce, msg, ct, plain_len, ad, ad_len, tag);
        start = clock();
        for (size_t iter = REPEAT; iter > 0; iter--) {
            HiAE_decrypt(key, nonce, ct, msg, plain_len, ad, ad_len, tag);
        }
        end = clock();
    } else {
        uint8_t tag[HIAE_MACBYTES];
        // Generate valid ciphertext and tag for encryption-only decryption test
        HiAE_encrypt(key, nonce, msg, ct, plain_len, NULL, 0, tag);
        start = clock();
        for (size_t iter = REPEAT; iter > 0; iter--) {
            HiAE_decrypt(key, nonce, ct, msg, plain_len, NULL, 0, tag);
        }
        end = clock();
    }
    double cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
    double speed         = ((double) REPEAT * plain_len) / (cpu_time_used * (125000000.0));

    return speed;
}

void
speed_test_encryption(void)
{
    double encrypto_speed[len_test_case];
    double decrypto_speed[len_test_case];
    printf("--------speed test Encryption Only(Gbps)----------\n");
    for (int i = 0; i < len_test_case; i++) {
        encrypto_speed[i] = speed_test_encode_work(test_case[i], 0);
        decrypto_speed[i] = speed_test_decode_work(test_case[i], 0);
        printf("length: %ld, encrypt: %.2f, decrypt: %.2f\n", test_case[i], encrypto_speed[i],
               decrypto_speed[i]);
    }
}

void
speed_test_ad_only(void)
{
    printf("--------speed test AD Only(Gbps)----------\n");
    for (int i = 0; i < len_test_case; i++) {
        double ad = speed_test_ad_work(test_case[i]);
        printf("length: %ld, AD: %.2f\n", test_case[i], ad);
    }
}

void
speed_test_aead(void)
{
    double encrypto_speed[len_test_case];
    double decrypto_speed[len_test_case];
    printf("--------speed test AEAD(Gbps)----------\n");
    for (int i = 0; i < len_test_case; i++) {
        encrypto_speed[i] = speed_test_encode_work(test_case[i], 1);
        decrypto_speed[i] = speed_test_decode_work(test_case[i], 1);
        printf("length: %ld, encrypt: %.2f, decrypt: %.2f\n", test_case[i], encrypto_speed[i],
               decrypto_speed[i]);
    }
}

int
main(void)
{
    printf("========HiAE Performance test========\n");
    printf("Implementation: %s\n", HiAE_get_implementation_name());
    speed_test_encryption();
    speed_test_ad_only();
    speed_test_aead();
}
