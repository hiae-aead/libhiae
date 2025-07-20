/*
 * HiAEt Runtime Dispatch Implementation
 *
 * This file implements runtime CPU feature detection and dispatches
 * to the appropriate optimized implementation based on available features.
 */

#include "HiAEt.h"
#include "HiAEt_internal.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __linux__
#    define HAVE_SYS_AUXV_H
#    define HAVE_GETAUXVAL
#endif
#ifdef __ANDROID_API__
#    if __ANDROID_API__ < 18
#        undef HAVE_GETAUXVAL
#    endif
#    define HAVE_ANDROID_GETCPUFEATURES
#endif
#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)
#    define HAVE_CPUID
#    define NATIVE_LITTLE_ENDIAN
#    if defined(__clang__) || defined(__GNUC__)
#        define HAVE_AVX_ASM
#    endif
#    define HAVE_AVXINTRIN_H
#    define HAVE_AVX2INTRIN_H
#    define HAVE_AVX512FINTRIN_H
#    define HAVE_TMMINTRIN_H
#    define HAVE_WMMINTRIN_H
#    define HAVE_VAESINTRIN_H
#    ifdef __GNUC__
#        if !__has_include(<vaesintrin.h>)
#            undef HAVE_VAESINTRIN_H
#        endif
#    endif
#endif

#ifdef HAVE_ANDROID_GETCPUFEATURES
#    include <cpu-features.h>
#endif
#ifdef __APPLE__
#    include <mach/machine.h>
#    include <sys/sysctl.h>
#    include <sys/types.h>
#endif
#ifdef HAVE_SYS_AUXV_H
#    include <sys/auxv.h>
#endif
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#    include <intrin.h>
#endif

// Define AT_HWCAP if not available
#ifndef AT_HWCAP
#    define AT_HWCAP 16
#endif
#ifndef AT_HWCAP2
#    define AT_HWCAP2 26
#endif

typedef struct CPUFeatures {
    int initialized;
    int has_neon;
    int has_aes;
    int has_sha3;
    int has_avx2;
    int has_avx512f;
    int has_vaes;
    int has_aesni;
} CPUFeatures;

static CPUFeatures cpu_features = { 0 };

// External declarations for all implementations
extern const HiAEt_impl_t hiaet_software_impl;

#if defined(__aarch64__) || defined(_M_ARM64)
extern const HiAEt_impl_t hiaet_arm_sha3_impl;
#endif

#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)
extern const HiAEt_impl_t hiaet_aesni_impl;
extern const HiAEt_impl_t hiaet_vaes_avx512_impl;
#endif

// Global implementation pointer
static const HiAEt_impl_t *hiaet_impl = NULL;

// CPU feature detection functions
#if defined(__aarch64__) || defined(_M_ARM64)

static void
detect_arm_features(void)
{
    cpu_features.has_neon = 1; // Always available on aarch64
    cpu_features.has_aes  = 0;
    cpu_features.has_sha3 = 0;

#    ifdef __APPLE__
    // macOS/iOS detection
    size_t size        = sizeof(int);
    int    has_feature = 0;

    if (sysctlbyname("hw.optional.arm.FEAT_AES", &has_feature, &size, NULL, 0) == 0) {
        cpu_features.has_aes = has_feature;
    }

    if (sysctlbyname("hw.optional.arm.FEAT_SHA3", &has_feature, &size, NULL, 0) == 0) {
        cpu_features.has_sha3 = has_feature;
    }
#    elif defined(__linux__)
    // Linux detection using getauxval
#        ifdef HAVE_GETAUXVAL
    unsigned long hwcap  = getauxval(AT_HWCAP);
    unsigned long hwcap2 = getauxval(AT_HWCAP2);

    // Check for AES support
#            ifdef HWCAP_AES
    if (hwcap & HWCAP_AES) {
        cpu_features.has_aes = 1;
    }
#            endif

    // Check for SHA3 support
#            ifdef HWCAP2_SHA3
    if (hwcap2 & HWCAP2_SHA3) {
        cpu_features.has_sha3 = 1;
    }
#            endif
#        endif // HAVE_GETAUXVAL
#    endif // Platform detection

    cpu_features.initialized = 1;
}

#elif defined(HAVE_CPUID)

static void
cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
#    if defined(_MSC_VER)
    int regs[4];
    __cpuid(regs, leaf);
    *eax = regs[0];
    *ebx = regs[1];
    *ecx = regs[2];
    *edx = regs[3];
#    elif defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("cpuid"
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "a"(leaf)
                     : "memory");
#    endif
}

static void
detect_x86_features(void)
{
    uint32_t eax, ebx, ecx, edx;

    // Check for AES-NI (CPUID.01H:ECX.AES[bit 25])
    cpuid(1, &eax, &ebx, &ecx, &edx);
    if (ecx & (1U << 25)) {
        cpu_features.has_aesni = 1;
    }

    // Check for AVX2 (CPUID.07H:EBX.AVX2[bit 5])
    cpuid(7, &eax, &ebx, &ecx, &edx);
    if (ebx & (1U << 5)) {
        cpu_features.has_avx2 = 1;
    }

    // Check for AVX512F (CPUID.07H:EBX.AVX512F[bit 16])
    if (ebx & (1U << 16)) {
        cpu_features.has_avx512f = 1;
    }

    // Check for VAES (CPUID.07H:ECX.VAES[bit 9])
    if (ecx & (1U << 9)) {
        cpu_features.has_vaes = 1;
    }

    cpu_features.initialized = 1;
}

#else

static void
detect_generic_features(void)
{
    // No feature detection available
    cpu_features.initialized = 1;
}

#endif

static void
detect_cpu_features(void)
{
    if (cpu_features.initialized) {
        return;
    }

#if defined(__aarch64__) || defined(_M_ARM64)
    detect_arm_features();
#elif defined(HAVE_CPUID)
    detect_x86_features();
#else
    detect_generic_features();
#endif
}

// Initialize the dispatch table
static void
hiaet_init_dispatch(void)
{
    if (hiaet_impl != NULL) {
        return; // Already initialized
    }

    detect_cpu_features();

    // Check for compile-time forced implementation first
#ifdef HIAET_FORCE_SOFTWARE
    hiaet_impl = &hiaet_software_impl;
    return;
#endif

#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)
#    ifdef HIAET_FORCE_VAES_AVX512
    if (hiaet_vaes_avx512_impl.init != NULL) {
        hiaet_impl = &hiaet_vaes_avx512_impl;
        return;
    }
#    endif
#    ifdef HIAET_FORCE_AESNI
    if (hiaet_aesni_impl.init != NULL) {
        hiaet_impl = &hiaet_aesni_impl;
        return;
    }
#    endif

    // Runtime selection for x86 (best to worst performance)
    if (cpu_features.has_vaes && cpu_features.has_avx512f && hiaet_vaes_avx512_impl.init != NULL) {
        hiaet_impl = &hiaet_vaes_avx512_impl;
        return;
    }
    if (cpu_features.has_aesni && hiaet_aesni_impl.init != NULL) {
        hiaet_impl = &hiaet_aesni_impl;
        return;
    }
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
#    ifdef HIAET_FORCE_ARM_SHA3
    if (hiaet_arm_sha3_impl.init != NULL) {
        hiaet_impl = &hiaet_arm_sha3_impl;
        return;
    }
#    endif

    // Runtime selection for ARM
    if (cpu_features.has_aes && cpu_features.has_sha3 && hiaet_arm_sha3_impl.init != NULL) {
        hiaet_impl = &hiaet_arm_sha3_impl;
        return;
    }
#endif

    // Default to software implementation
    hiaet_impl = &hiaet_software_impl;
}

// Automatic library initialization
#if defined(_MSC_VER)
#    pragma section(".CRT$XCU", read)
static void __cdecl _do_HiAEt_init_library(void);
__declspec(allocate(".CRT$XCU")) void (*HiAEt_init_library_constructor)(void) =
    _do_HiAEt_init_library;
#else
static void _do_HiAEt_init_library(void) __attribute__((constructor));
#endif

static void
_do_HiAEt_init_library(void)
{
    hiaet_init_dispatch();
}

// Public API functions

int
HiAEt_init_library(void)
{
    hiaet_init_dispatch();
    return 0;
}

const char *
HiAEt_get_implementation_name(void)
{
    if (hiaet_impl == NULL) {
        hiaet_init_dispatch();
    }
    return hiaet_impl ? hiaet_impl->name : "Unknown";
}

// Low-level API functions

void
HiAEt_init(HiAEt_state_t *state, const uint8_t *key, const uint8_t *nonce)
{
    if (hiaet_impl == NULL) {
        hiaet_init_dispatch();
    }
    assert(hiaet_impl != NULL);
    assert(hiaet_impl->init != NULL);
    hiaet_impl->init(state, key, nonce);
}

void
HiAEt_absorb(HiAEt_state_t *state, const uint8_t *ad, size_t ad_len)
{
    assert(hiaet_impl != NULL);
    assert(hiaet_impl->absorb != NULL);
    hiaet_impl->absorb(state, ad, ad_len);
}

void
HiAEt_enc(HiAEt_state_t *state, uint8_t *ciphertext, const uint8_t *plaintext, size_t msg_len)
{
    assert(hiaet_impl != NULL);
    assert(hiaet_impl->enc != NULL);
    hiaet_impl->enc(state, ciphertext, plaintext, msg_len);
}

void
HiAEt_dec(HiAEt_state_t *state, uint8_t *plaintext, const uint8_t *ciphertext, size_t msg_len)
{
    assert(hiaet_impl != NULL);
    assert(hiaet_impl->dec != NULL);
    hiaet_impl->dec(state, plaintext, ciphertext, msg_len);
}

void
HiAEt_finalize(HiAEt_state_t *state, uint64_t ad_len, uint64_t msg_len, uint8_t *tag)
{
    assert(hiaet_impl != NULL);
    assert(hiaet_impl->finalize != NULL);
    hiaet_impl->finalize(state, (size_t) ad_len, (size_t) msg_len, tag);
}

// High-level all-at-once API

int
HiAEt_encrypt(const uint8_t *key, const uint8_t *nonce, const uint8_t *plaintext,
              uint8_t *ciphertext, size_t msg_len, const uint8_t *ad, size_t ad_len,
              uint8_t *tag)
{
    HiAEt_state_t state;

    HiAEt_init(&state, key, nonce);

    if (ad_len > 0) {
        HiAEt_absorb(&state, ad, ad_len);
    }

    if (msg_len > 0) {
        HiAEt_enc(&state, ciphertext, plaintext, msg_len);
    }

    HiAEt_finalize(&state, ad_len, msg_len, tag);

    return 0;
}

int
HiAEt_decrypt(const uint8_t *key, const uint8_t *nonce, uint8_t *plaintext,
              const uint8_t *ciphertext, size_t msg_len, const uint8_t *ad, size_t ad_len,
              const uint8_t *tag)
{
    HiAEt_state_t state;
    uint8_t       computed_tag[16];

    HiAEt_init(&state, key, nonce);

    if (ad_len > 0) {
        HiAEt_absorb(&state, ad, ad_len);
    }

    if (msg_len > 0) {
        HiAEt_dec(&state, plaintext, ciphertext, msg_len);
    }

    HiAEt_finalize(&state, ad_len, msg_len, computed_tag);

    // Constant-time comparison
    int result = 0;
    for (int i = 0; i < 16; i++) {
        result |= computed_tag[i] ^ tag[i];
    }

    return (result == 0) ? 0 : -1;
}

int
HiAEt_mac(const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len,
          uint8_t *tag)
{
    return HiAEt_encrypt(key, nonce, NULL, NULL, 0, data, data_len, tag);
}

// Streaming API stubs (TODO: Implement if needed)

void
HiAEt_stream_init(HiAEt_stream_state_t *stream, const uint8_t *key, const uint8_t *nonce)
{
    // TODO: Implement streaming API
    (void) stream;
    (void) key;
    (void) nonce;
}

void
HiAEt_stream_absorb(HiAEt_stream_state_t *stream, const uint8_t *ad, size_t ad_len)
{
    // TODO: Implement streaming API
    (void) stream;
    (void) ad;
    (void) ad_len;
}

void
HiAEt_stream_encrypt(HiAEt_stream_state_t *stream, uint8_t *ciphertext, const uint8_t *plaintext,
                     size_t msg_len)
{
    // TODO: Implement streaming API
    (void) stream;
    (void) ciphertext;
    (void) plaintext;
    (void) msg_len;
}

void
HiAEt_stream_decrypt(HiAEt_stream_state_t *stream, uint8_t *plaintext, const uint8_t *ciphertext,
                     size_t msg_len)
{
    // TODO: Implement streaming API
    (void) stream;
    (void) plaintext;
    (void) ciphertext;
    (void) msg_len;
}

void
HiAEt_stream_finalize(HiAEt_stream_state_t *stream, uint8_t *tag)
{
    // TODO: Implement streaming API
    (void) stream;
    (void) tag;
}