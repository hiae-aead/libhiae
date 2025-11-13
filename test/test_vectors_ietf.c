/*
 * HiAE Test Vector Validation
 * Test vectors from draft-pham-cfrg-hiae
 */

#include "HiAE.h"
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
      .tag        = "a25049aa37deea054de461d10ce7840b" },
    // Test Vector 2 - Single block plaintext, no AD
    { .name       = "Test Vector 2",
      .key        = "2f8e4d7c3b9a5e1f8d2c6b4a9f3e7d5c1b8a6f4e3d2c9b5a8f7e6d4c3b2a1f9e",
      .nonce      = "7c3e9f5a1d8b4c6f2e9a5d7b3f8c1e4a",
      .ad         = "",
      .plaintext  = "55f00fcc339669aa55f00fcc339669aa",
      .ciphertext = "af9bd1865daa6fc351652589abf70bff",
      .tag        = "ed9e2edc8241c3184fc08972bd8e9952" },
    // Test Vector 3 - Empty plaintext with AD
    { .name       = "Test Vector 3",
      .key        = "9f3e7d5c4b8a2f1e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e",
      .nonce      = "3d8c7f2a5b9e4c1f8a6d3b7e5c2f9a4d",
      .ad         = "394a5b6c7d8e9fb0c1d2e3f405162738495a6b7c8d9eafc0d1e2f30415263748",
      .plaintext  = "",
      .ciphertext = "",
      .tag        = "7e19c04f68f5af633bf67529cfb5e5f4" },
    // Test Vector 4 - Rate-aligned plaintext (256 bytes)
    { .name       = "Test Vector 4",
      .key        = "6c8f2d5a9e3b7f4c1d8a5e9f3c7b2d6a4f8e1c9b5d3a7e2f4c8b6d9a1e5f3c7d",
      .nonce      = "9a5c7e3f1b8d4a6c2e9f5b7d3a8c1e6f",
      .ad         = "",
      .plaintext  = "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff",
      .ciphertext = "cf9f118ccc3ae98998ddaae1a5d1f9a1"
                    "69e4ca3e732baf7178cdd9a353057166"
                    "8fe403e77111eac3da34bf2f25719cea"
                    "09445cc58197b1c6ac490626724e7372"
                    "707cfb60cdba8262f0e33a1ef8adda1f"
                    "2e390a80c58e5c055d9be9bbccdc06ad"
                    "af74f1dcaa372204bf42e5e0e0ac5943"
                    "7a353978298837023f79fac6daa1fe8f"
                    "6bcaaaf060ae2e37ed7b7da0577a7643"
                    "5f0403b8e277b6bc2ea99682f2d0d577"
                    "77fec6d901e0d8fc7cf46bb97336812a"
                    "2d8cfd39053993288cce2c077fce0c6c"
                    "00e99cf919281b261acf86b058164f10"
                    "1d9c24e8f40b4fa0ed60955eeeb4e33f"
                    "f1087519c13db8e287199a7df7e94b0d"
                    "368da9ccf3d2ecebfa46f860348f8e3c",
      .tag        = "4f42c3042cba3973153673156309dd69" },
    // Test Vector 5 - Rate + 1 byte plaintext
    { .name       = "Test Vector 5",
      .key        = "3e9d6c5b4a8f7e2d1c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d",
      .nonce      = "6f2e8a5c9b3d7f1e4a8c5b9d3f7e2a6c",
      .ad         = "6778899aabbccddeef00112233445566",
      .plaintext  = "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc339669aa55f00fcc339669aa55f00f"
                    "cc",
      .ciphertext = "522e4cd9b0881809d80e149bb4ed8b8a"
                    "dd70b7257afca6c2bc38e4da11e290cf"
                    "cabd9dd1d4ed8c514482f444f903e42e"
                    "c21a7a605ee37f95a504ec667fabec40"
                    "66eb4521cdaf9c4eb7b62d659ab0a936"
                    "3b145f1120c1b2e589ab9cb893d01be0"
                    "d22182fc7de4932f1e8652b50e4a0d48"
                    "c49a8a1232b201e2e535cd95c15cf0ee"
                    "389b75e372653579c72c4dd1906fd81c"
                    "2b9fc2483fab8b4df5a09d59753b5bd4"
                    "1334be2e5085e349b6e5aac0c555a0a8"
                    "3e94eab974052131f8d451c9d85389a3"
                    "6126f93464e6f93119c6b1bf15b4c0a9"
                    "e6c9beb52e82c846c472f87c15ac49e9"
                    "9d59248ba7e6b97ca04327769d6b8c1f"
                    "751d95dba709fb335183c21476836ea1"
                    "ab",
      .tag        = "61bac11505dd8bbf55e7fbb7489de7b0" },
    // Test Vector 6 - Rate - 1 byte plaintext
    { .name       = "Test Vector 6",
      .key        = "8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f",
      .nonce      = "4d8b2f6a9c3e7f5d1b8a4c6e9f3d5b7a",
      .ad         = "",
      .plaintext  = "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "000000000000000000000000000000",
      .ciphertext = "2ba49be54eb675efe446fd597721d4cd"
                    "ca6e01f1a51728a859d8f206d13cdb08"
                    "ba4f0fe78fbbd6885964ed54e9beceed"
                    "1ff306642c4761e67efa7a2620e57128"
                    "15b5e9f066b42e879cd62e7adc2821e5"
                    "08311b88a6ee14bedcbac7ce339994c0"
                    "09bbbadf9444748e4ab9a91acbbc7301"
                    "742dab74aa1be6847ad8e9f08c170359"
                    "b87e0ccd480812aaaf847aff03c2e858"
                    "1c55848c2b50f6c6608540fe82627a2c"
                    "0f5ee37fbe9cdeab5f6c9799702bd303"
                    "2bf733e2108d03247cd20edaa2c322e5"
                    "bf086bfecc4ac97b61096f016c57d5d0"
                    "1c24d398cefd5ae8131c1f51f172ce9c"
                    "6d3b8395d396dcbd70b4af790018796b"
                    "31f0b0ad6198f86e5e1f26e9258492",
      .tag        = "221dd1b69afb4e0c149e0a058e471a4a" },
    // Test Vector 7 - Medium plaintext with AD
    { .name       = "Test Vector 7",
      .key        = "5d9c3b7a8f2e6d4c1b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c",
      .nonce      = "8c5a7d3f9b1e6c4a2f8d5b9e3c7a1f6d",
      .ad         = "95a6b7c8d9eafb0c1d2e3f5061728394"
                    "a5b6c7d8e9fa0b1c2d3e4f60718293a4"
                    "b5c6d7e8f90a1b2c3d4e5f708192a3b4"
                    "c5d6e7f8091a2b3c4d5e6f8091a2b3c4",
      .plaintext  = "32e14453e7a776781d4c4e2c3b23bca2"
                    "441ee4213bc3df25021b5106c22c98e8"
                    "a7b310142252c8dcff70a91d55cdc910"
                    "3c1eccd9b5309ef21793a664e0d4b63c"
                    "83530dcd1a6ad0feda6ff19153e9ee62"
                    "0325c1cb979d7b32e54f41da3af1c169"
                    "a24c47c1f6673e115f0cb73e8c507f15"
                    "eedf155261962f2d175c9ba3832f4933"
                    "fb330d28ad6aae787f12788706f45c92"
                    "e72aea146959d2d4fa01869f7d072a7b"
                    "f43b2e75265e1a000dde451b64658919"
                    "e93143d2781955fb4ca2a38076ac9eb4"
                    "9adc2b92b05f0ec7",
      .ciphertext = "1d8d56867870574d1c4ac114620c6a2a"
                    "bb44680fe321dd116601e2c92540f85a"
                    "11c41dcac9814397b8f37b812cd52c93"
                    "2db6ecbaa247c3e14f228bd792334570"
                    "2fc43ad1eb1b8086e2c3c57bb602971c"
                    "29772a35dfb1c45c66f81633e67fdc8d"
                    "8005457ddbe4179312abab981049eb0a"
                    "0a555b9fa01378878d7349111e2446fd"
                    "e89ce64022d032cbf0cf2672e00d7999"
                    "ed8b631c1b9bee547cbe464673464a4b"
                    "80e8f72ad2b91a40fdcee5357980c090"
                    "b34ab5e732e2a7df7613131ee42e42ec"
                    "6ae9b05ac5683ebe",
      .tag        = "e93686b266c481196d44536eb51b5f2d" },
    // Test Vector 8 - Single byte plaintext
    { .name       = "Test Vector 8",
      .key        = "7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a",
      .nonce      = "2e7c9f5d3b8a4c6f1e9b5d7a3f8c2e4a",
      .ad         = "",
      .plaintext  = "ff",
      .ciphertext = "21",
      .tag        = "3cf9020bd1cc59cc5f2f6ce19f7cbf68" },
    // Test Vector 9 - Two blocks plaintext
    { .name       = "Test Vector 9",
      .key        = "4c8b7a9f3e5d2c6b1a8f9e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b",
      .nonce      = "7e3c9a5f1d8b4e6c2a9f5d7b3e8c1a4f",
      .ad         = "c3d4e5f60718293a4b5c6d7e8fa0b1c2"
                    "d3e4f5061728394a5b6c7d8e9fb0c1d2"
                    "e3f405162738495a6b7c8d9eafc0d1e2",
      .plaintext  = "aa55f00fcc339669aa55f00fcc339669"
                    "aa55f00fcc339669aa55f00fcc339669",
      .ciphertext = "c2e199ac8c23ce6e3778e7fd0b4f8f75"
                    "2badd4b67be0cdc3f6c98ae5f6fb0d25",
      .tag        = "7aea3fbce699ceb1d0737e0483217745" },
    // Test Vector 10 - All zeros plaintext
    { .name       = "Test Vector 10",
      .key        = "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
      .nonce      = "5f9d3b7e2c8a4f6d1b9e5c7a3d8f2b6e",
      .ad         = "daebfc0d1e2f405162738495a6b7c8d9",
      .plaintext  = "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000"
                    "00000000000000000000000000000000",
      .ciphertext = "fc7f1142f681399099c5008980e73420"
                    "65b4e62a9b9cb301bdf441d3282b6aa9"
                    "3bd7cd735ef77755b4109f86b7c09083"
                    "8e7b05f08ef4947946155a03ff483095"
                    "152ef3dec8bdddae3990d00d41d5ee6c"
                    "90dcf65dbed4b7ebbe9bb4ef096e1238"
                    "d388bf15faacdb7a68be19dddc8a5b74"
                    "216f4442bfa32d1dfccdc9c4020baec9",
      .tag        = "ad0b841c3d145a6ee86dc7b67338f113" }
};

static const size_t num_test_vectors = sizeof(test_vectors) / sizeof(test_vectors[0]);

// Run a single test vector
static int
run_test_vector(const TestVector *tv)
{
    uint8_t key[HIAE_KEYBYTES], nonce[HIAE_NONCEBYTES], tag[HIAE_MACBYTES];
    uint8_t ad[2048], plaintext[2048], ciphertext[2048];
    uint8_t computed_ciphertext[2048], computed_tag[HIAE_MACBYTES];
    uint8_t decrypted[2048];

    // Parse inputs
    if (hex_to_bytes(tv->key, key, sizeof(key)) != HIAE_KEYBYTES) {
        printf("  ERROR: Failed to parse key\n");
        return 0;
    }

    if (hex_to_bytes(tv->nonce, nonce, sizeof(nonce)) != HIAE_NONCEBYTES) {
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

    if (hex_to_bytes(tv->tag, tag, sizeof(tag)) != HIAE_MACBYTES) {
        printf("  ERROR: Failed to parse tag\n");
        return 0;
    }

    // Test encryption
    HiAE_encrypt(key, nonce, plaintext, computed_ciphertext, pt_len, ad, ad_len, computed_tag);

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
    if (memcmp(computed_tag, tag, HIAE_MACBYTES) != 0) {
        printf("  ERROR: Tag mismatch\n");
        print_hex("  Expected", tag, HIAE_MACBYTES);
        print_hex("  Computed", computed_tag, HIAE_MACBYTES);
        return 0;
    }

    // Test decryption
    int auth_result = HiAE_decrypt(key, nonce, decrypted, ciphertext, ct_len, ad, ad_len, tag);

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
    printf("HiAE IETF Test Vector Validation\n");
    printf("Test vectors from draft-pham-cfrg-hiae.md\n");
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