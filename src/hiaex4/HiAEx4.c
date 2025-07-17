/*
 * HiAEx4 Runtime Dispatch Implementation
 *
 * This file implements runtime CPU feature detection and dispatches
 * to the appropriate optimized implementation based on available features.
 */

#include "HiAEx4.h"
#include "HiAEx4_internal.h"
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
#    define HAVE_AVX4INTRIN_H
#    define HAVE_AVX512FINTRIN_H
#    define HAVE_TMMINTRIN_H
#    define HAVE_WMMINTRIN_H
#    define HAVE_VAESINTRIN_H
#    ifdef __GNUC__
#        if !__has_include(<vaesintrin.h>)
#            undef HAVE_VAESINTRIN_H
#        endif
#    endif
/* target pragmas don't define these flags on clang-cl (an alternative clang driver for Windows) */
#    if defined(__clang__) && defined(_MSC_BUILD) && defined(_MSC_VER) && \
        (defined(_M_IX86) || defined(_M_AMD64)) && !defined(__SSE3__)
#        undef __SSE3__
#        undef __SSSE3__
#        undef __SSE4_1__
#        undef __AVX__
#        undef __AVX4__
#        undef __AVX512F__
#        undef __AES__
#        undef __VAES__

#        define __SSE3__    1
#        define __SSSE3__   1
#        define __SSE4_1__  1
#        define __AVX__     1
#        define __AVX4__    1
#        define __AVX512F__ 1
#        define __AES__     1
#        define __VAES__    1
#    endif

#endif

#ifdef DISABLE_AVX4
#    undef HAVE_AVXINTRIN_H
#    undef HAVE_AVX4INTRIN_H
#    undef HAVE_AVX512FINTRIN_H
#    undef HAVE_VAESINTRIN_H
#endif
#ifdef DISABLE_AVX512
#    undef HAVE_AVX512FINTRIN_H
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
    int has_neon_aes;
    int has_neon_sha3;
    int has_avx;
    int has_avx2;
    int has_avx512f;
    int has_aesni;
    int has_vaes;
    int has_altivec;
} CPUFeatures;

static CPUFeatures    _cpu_features;
static HiAEx4_impl_t *hiaex4_impl      = NULL;
static const char    *forced_impl_name = NULL;

#define CPUID_EBX_AVX4    0x00000020
#define CPUID_EBX_AVX512F 0x00010000

#define CPUID_ECX_AESNI   0x02000000
#define CPUID_ECX_XSAVE   0x04000000
#define CPUID_ECX_OSXSAVE 0x08000000
#define CPUID_ECX_AVX     0x10000000
#define CPUID_ECX_VAES    0x00000200

#define XCR0_SSE       0x00000002
#define XCR0_AVX       0x00000004
#define XCR0_OPMASK    0x00000020
#define XCR0_ZMM_HI256 0x00000040
#define XCR0_HI16_ZMM  0x00000080

// Define hwcap values ourselves: building with an old auxv header where these
// hwcap values are not defined should not prevent features from being enabled.

// Arm hwcaps.
#define HIAEX4_ARM_HWCAP_NEON (1L << 12)
#define HIAEX4_ARM_HWCAP2_AES (1L << 0)

// AArch64 hwcaps.
#define HIAEX4_AARCH64_HWCAP_ASIMD (1L << 1)
#define HIAEX4_AARCH64_HWCAP_AES   (1L << 3)
#define HIAEX4_AARCH64_HWCAP_SHA3  (1L << 17)

static void
_cpuid(unsigned int cpu_info[4U], const unsigned int cpu_info_type)
{
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86)) && \
    !defined(__cpuid) /* __cpuid is a function on MSVC, can be an incompatible macro elsewhere */
    __cpuid((int *) cpu_info, cpu_info_type);
#elif defined(HAVE_CPUID)
    cpu_info[0] = cpu_info[1] = cpu_info[2] = cpu_info[3] = 0;
#    ifdef __i386__
    __asm__ __volatile__(
        "pushfl; pushfl; "
        "popl %0; "
        "movl %0, %1; xorl %2, %0; "
        "pushl %0; "
        "popfl; pushfl; popl %0; popfl"
        : "=&r"(cpu_info[0]), "=&r"(cpu_info[1])
        : "i"(0x400000));
    if (((cpu_info[0] ^ cpu_info[1]) & 0x400000) == 0x0) {
        return; /* LCOV_EXCL_LINE */
    }
#    endif
#    ifdef __i386__
    __asm__ __volatile__("xchgl %%ebx, %k1; cpuid; xchgl %%ebx, %k1"
                         : "=a"(cpu_info[0]), "=&r"(cpu_info[1]), "=c"(cpu_info[2]),
                           "=d"(cpu_info[3])
                         : "0"(cpu_info_type), "2"(0U));
#    elif defined(__x86_64__)
    __asm__ __volatile__("xchgq %%rbx, %q1; cpuid; xchgq %%rbx, %q1"
                         : "=a"(cpu_info[0]), "=&r"(cpu_info[1]), "=c"(cpu_info[2]),
                           "=d"(cpu_info[3])
                         : "0"(cpu_info_type), "2"(0U));
#    else
    __asm__ __volatile__("cpuid"
                         : "=a"(cpu_info[0]), "=b"(cpu_info[1]), "=c"(cpu_info[2]),
                           "=d"(cpu_info[3])
                         : "0"(cpu_info_type), "2"(0U));
#    endif
#else
    (void) cpu_info_type;
    cpu_info[0] = cpu_info[1] = cpu_info[2] = cpu_info[3] = 0;
#endif
}

static int
_runtime_intel_cpu_features(CPUFeatures *const cpu_features)
{
    unsigned int cpu_info[4];
    uint32_t     xcr0 = 0U;

    _cpuid(cpu_info, 0x0);
    if (cpu_info[0] == 0U) {
        return -1; /* LCOV_EXCL_LINE */
    }
    _cpuid(cpu_info, 0x00000001);

    (void) xcr0;
#ifdef HAVE_AVXINTRIN_H
    if ((cpu_info[2] & (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) ==
        (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) {
        xcr0 = 0U;
#    if defined(HAVE__XGETBV) || \
        (defined(_MSC_VER) && defined(_XCR_XFEATURE_ENABLED_MASK) && _MSC_FULL_VER >= 160040219)
        xcr0 = (uint32_t) _xgetbv(0);
#    elif defined(_MSC_VER) && defined(_M_IX86)
        /*
         * Visual Studio documentation states that eax/ecx/edx don't need to
         * be preserved in inline assembly code. But that doesn't seem to
         * always hold true on Visual Studio 2010.
         */
        __asm {
            push eax
            push ecx
            push edx
            xor ecx, ecx
            _asm _emit 0x0f _asm _emit 0x01 _asm _emit 0xd0
            mov xcr0, eax
            pop edx
            pop ecx
            pop eax
        }
#    elif defined(HAVE_AVX_ASM)
        __asm__ __volatile__(".byte 0x0f, 0x01, 0xd0" /* XGETBV */
                             : "=a"(xcr0)
                             : "c"((uint32_t) 0U)
                             : "%edx");
#    endif
        if ((xcr0 & (XCR0_SSE | XCR0_AVX)) == (XCR0_SSE | XCR0_AVX)) {
            cpu_features->has_avx = 1;
        }
    }
#endif

#ifdef HAVE_WMMINTRIN_H
    cpu_features->has_aesni = ((cpu_info[2] & CPUID_ECX_AESNI) != 0x0);
#endif

#ifdef HAVE_AVX4INTRIN_H
    if (cpu_features->has_avx) {
        unsigned int cpu_info7[4];

        _cpuid(cpu_info7, 0x00000007);
        cpu_features->has_avx2 = ((cpu_info7[1] & CPUID_EBX_AVX4) != 0x0);
        cpu_features->has_vaes =
            cpu_features->has_aesni && ((cpu_info7[2] & CPUID_ECX_VAES) != 0x0);
    }
#endif

    cpu_features->has_avx512f = 0;
#ifdef HAVE_AVX512FINTRIN_H
    if (cpu_features->has_avx2) {
        unsigned int cpu_info7[4];

        _cpuid(cpu_info7, 0x00000007);
        /* LCOV_EXCL_START */
        if ((cpu_info7[1] & CPUID_EBX_AVX512F) == CPUID_EBX_AVX512F &&
            (xcr0 & (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM)) ==
                (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM)) {
            cpu_features->has_avx512f = 1;
        }
        /* LCOV_EXCL_STOP */
    }
#endif

    return 0;
}

#if defined(__APPLE__) && defined(CPU_TYPE_ARM64) && defined(CPU_SUBTYPE_ARM64E)
// sysctlbyname() parameter documentation for instruction set characteristics:
// https://developer.apple.com/documentation/kernel/1387446-sysctlbyname/determining_instruction_set_characteristics
__attribute__((unused)) static inline int
_have_feature(const char *feature)
{
    int64_t feature_present = 0;
    size_t  size            = sizeof(feature_present);
    if (sysctlbyname(feature, &feature_present, &size, NULL, 0) != 0) {
        return 0;
    }
    return feature_present;
}

#elif (defined(__arm__) || defined(__aarch64__) || defined(_M_ARM64)) && defined(AT_HWCAP)
static inline int
_have_hwcap(int hwcap_id, int bit)
{
    unsigned long buf = 0;
#    ifdef HAVE_GETAUXVAL
    buf = getauxval(hwcap_id);
#    elif defined(HAVE_ELF_AUX_INFO)
    unsigned long buf;
    if (elf_aux_info(hwcap_id, (void *) &buf, (int) sizeof buf) != 0) {
        return 0;
    }
#    endif
    return (buf & bit) != 0;
}
#endif

static int
_runtime_arm_cpu_features(CPUFeatures *const cpu_features)
{
#ifndef __ARM_ARCH
    return -1; /* LCOV_EXCL_LINE */
#endif

#if defined(__ARM_NEON) || defined(__aarch64__) || defined(_M_ARM64)
    cpu_features->has_neon = 1;
#elif defined(HAVE_ANDROID_GETCPUFEATURES) && defined(ANDROID_CPU_ARM_FEATURE_NEON)
    cpu_features->has_neon = (android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_NEON) != 0x0;
#elif (defined(__aarch64__) || defined(_M_ARM64)) && defined(AT_HWCAP)
    cpu_features->has_neon = _have_hwcap(AT_HWCAP, HIAEX4_AARCH64_HWCAP_ASIMD);
#elif defined(__arm__) && defined(AT_HWCAP)
    cpu_features->has_neon = _have_hwcap(AT_HWCAP, HIAEX4_ARM_HWCAP_NEON);
#endif

    if (cpu_features->has_neon == 0) {
        return 0;
    }

#if __ARM_FEATURE_CRYPTO || __ARM_FEATURE_AES
    cpu_features->has_neon_aes = 1;
#elif defined(_M_ARM64)
    // Assuming all CPUs supported by Arm Windows have the crypto extensions.
    cpu_features->has_neon_aes = 1;
#elif defined(__APPLE__) && defined(CPU_TYPE_ARM64) && defined(CPU_SUBTYPE_ARM64E)
    cpu_features->has_neon_aes = _have_feature("hw.optional.arm.FEAT_AES");
#elif defined(HAVE_ANDROID_GETCPUFEATURES) && defined(ANDROID_CPU_ARM_FEATURE_AES)
    cpu_features->has_neon_aes = (android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_AES) != 0x0;
#elif (defined(__aarch64__) || defined(_M_ARM64)) && defined(AT_HWCAP)
    cpu_features->has_neon_aes = _have_hwcap(AT_HWCAP, HIAEX4_AARCH64_HWCAP_AES);
#elif defined(__arm__) && defined(AT_HWCAP2)
    cpu_features->has_neon_aes = _have_hwcap(AT_HWCAP2, HIAEX4_ARM_HWCAP2_AES);
#endif

    // The FEAT_SHA3 implementation assumes that FEAT_AES is also present.
    if (cpu_features->has_neon_aes == 0) {
        return 0;
    }

#if __ARM_FEATURE_SHA3
    cpu_features->has_neon_sha3 = 1;
#elif defined(__APPLE__) && defined(CPU_TYPE_ARM64) && defined(CPU_SUBTYPE_ARM64E)
    cpu_features->has_neon_sha3 = _have_feature("hw.optional.arm.FEAT_SHA3");
#elif (defined(__aarch64__) || defined(_M_ARM64)) && defined(AT_HWCAP)
    cpu_features->has_neon_sha3 = _have_hwcap(AT_HWCAP, HIAEX4_AARCH64_HWCAP_SHA3);
#endif

    return 0;
}

static int
_runtime_powerpc_cpu_features(CPUFeatures *const cpu_features)
{
    cpu_features->has_altivec = 0;
#if defined(__ALTIVEC__) && defined(__CRYPTO__)
    cpu_features->has_altivec = 1;
#endif
    return 0;
}

static int
hiaex4_runtime_get_cpu_features(void)
{
    int ret = -1;

    memset(&_cpu_features, 0, sizeof _cpu_features);

    ret &= _runtime_arm_cpu_features(&_cpu_features);
    ret &= _runtime_intel_cpu_features(&_cpu_features);
    ret &= _runtime_powerpc_cpu_features(&_cpu_features);
    _cpu_features.initialized = 1;

    return ret;
}

// External declarations for implementation tables
#if !defined(__AES__) && !defined(__ARM_FEATURE_CRYPTO)
extern const HiAEx4_impl_t hiaex4_software_impl;
#endif
#if defined(__x86_64__) || defined(_M_X64)
extern const HiAEx4_impl_t hiaex4_vaes_avx512_impl;
#endif
#if defined(__aarch64__) || defined(_M_ARM64) || defined(__arm64__)
extern const HiAEx4_impl_t hiaex4_arm_impl;
extern const HiAEx4_impl_t hiaex4_arm_sha3_impl;
#endif

// Helper function to get implementation by name
static HiAEx4_impl_t *
hiaex4_get_impl_by_name(const char *name)
{
    if (name == NULL) {
        return NULL;
    }

#if !defined(__AES__) && !defined(__ARM_FEATURE_CRYPTO)
    if (strcmp(name, "Software") == 0) {
        return (HiAEx4_impl_t *) &hiaex4_software_impl;
    }
#endif

#if defined(__x86_64__) || defined(_M_X64)
    if (strcmp(name, "VAES-AVX4") == 0 && hiaex4_vaes_avx512_impl.init != NULL) {
        return (HiAEx4_impl_t *) &hiaex4_vaes_avx512_impl;
    }
#elif defined(__aarch64__) || defined(_M_ARM64) || defined(__arm64__)
    if (strcmp(name, "ARM NEON") == 0 && hiaex4_arm_impl.init != NULL) {
        return (HiAEx4_impl_t *) &hiaex4_arm_impl;
    }
    if (strcmp(name, "ARM SHA3") == 0 && hiaex4_arm_sha3_impl.init != NULL) {
        return (HiAEx4_impl_t *) &hiaex4_arm_sha3_impl;
    }
#endif

    return NULL;
}

// Initialize the dispatch table
static void
hiaex4_init_dispatch(void)
{
    if (hiaex4_impl != NULL) {
        return; // Already initialized
    }

    // Check for compile-time forced implementation first
#ifdef HIAEX4_FORCED_IMPL
    hiaex4_impl = hiaex4_get_impl_by_name(HIAEX4_FORCED_IMPL);
    if (hiaex4_impl != NULL) {
        return;
    }
#endif

    // Check for runtime forced implementation
    if (forced_impl_name != NULL) {
        hiaex4_impl = hiaex4_get_impl_by_name(forced_impl_name);
        if (hiaex4_impl != NULL) {
            return;
        }
    }

    // Initialize CPU features if not already done
    if (!_cpu_features.initialized) {
        hiaex4_runtime_get_cpu_features();
    }

#if !defined(__AES__) && !defined(__ARM_FEATURE_CRYPTO)
    // Default to software implementation when hardware AES is not available
    hiaex4_impl = (HiAEx4_impl_t *) &hiaex4_software_impl;
#endif

    // Select best available implementation based on CPU features
#if defined(__x86_64__) || defined(_M_X64)
    if (_cpu_features.has_avx512f && _cpu_features.has_vaes &&
        hiaex4_vaes_avx512_impl.init != NULL) {
        hiaex4_impl = (HiAEx4_impl_t *) &hiaex4_vaes_avx512_impl;
    }
#elif defined(__aarch64__) || defined(_M_ARM64) || defined(__arm64__)
    if (_cpu_features.has_neon_sha3 && hiaex4_arm_sha3_impl.init != NULL) {
        hiaex4_impl = (HiAEx4_impl_t *) &hiaex4_arm_sha3_impl;
    } else if (_cpu_features.has_neon_aes && hiaex4_arm_impl.init != NULL) {
        hiaex4_impl = (HiAEx4_impl_t *) &hiaex4_arm_impl;
    }
#endif

#if defined(__AES__) || defined(__ARM_FEATURE_CRYPTO)
    // When hardware AES is available, ensure we have a valid implementation
    if (hiaex4_impl == NULL) {
#    if defined(__x86_64__) || defined(_M_X64)
        // Fallback to VAES-AVX512 on x86-64 if available
        if (hiaex4_vaes_avx512_impl.init != NULL) {
            hiaex4_impl = (HiAEx4_impl_t *) &hiaex4_vaes_avx512_impl;
        }
#    elif defined(__aarch64__) || defined(_M_ARM64) || defined(__arm64__)
        // Fallback to ARM NEON on ARM64 if available
        if (hiaex4_arm_impl.init != NULL) {
            hiaex4_impl = (HiAEx4_impl_t *) &hiaex4_arm_impl;
        }
#    endif
    }
#endif
}

// Public API function to initialize library
int
HiAEx4_init_library(void)
{
    hiaex4_init_dispatch();
    return 0;
}

#if defined(_MSC_VER)
#    pragma section(".CRT$XCU", read)
static void __cdecl _do_HiAEx4_init_library(void);
__declspec(allocate(".CRT$XCU")) void (*HiAEx4_init_library_constructor)(void) =
    _do_HiAEx4_init_library;
#else
static void _do_HiAEx4_init_library(void) __attribute__((constructor));
#endif

static void
_do_HiAEx4_init_library(void)
{
    (void) HiAEx4_init_library();
}

// Public API implementations that dispatch to the selected implementation
void
HiAEx4_init(HiAEx4_state_t *state, const uint8_t *key, const uint8_t *nonce)
{
    hiaex4_init_dispatch();
    hiaex4_impl->init(state, key, nonce);
}

void
HiAEx4_absorb(HiAEx4_state_t *state, const uint8_t *ad, size_t len)
{
    hiaex4_init_dispatch();
    hiaex4_impl->absorb(state, ad, len);
}

void
HiAEx4_finalize(HiAEx4_state_t *state, uint64_t ad_len, uint64_t msg_len, uint8_t *tag)
{
    hiaex4_init_dispatch();
    hiaex4_impl->finalize(state, ad_len, msg_len, tag);
}

void
HiAEx4_finalize_mac(HiAEx4_state_t *state, uint64_t data_len, uint8_t *tag)
{
    hiaex4_init_dispatch();
    hiaex4_impl->finalize_mac(state, data_len, tag);
}

void
HiAEx4_enc(HiAEx4_state_t *state, uint8_t *ci, const uint8_t *mi, size_t size)
{
    hiaex4_init_dispatch();
    hiaex4_impl->enc(state, ci, mi, size);
}

void
HiAEx4_dec(HiAEx4_state_t *state, uint8_t *mi, const uint8_t *ci, size_t size)
{
    hiaex4_init_dispatch();
    hiaex4_impl->dec(state, mi, ci, size);
}

void
HiAEx4_enc_partial_noupdate(HiAEx4_state_t *state, uint8_t *ci, const uint8_t *mi, size_t size)
{
    assert(size < 16);
    hiaex4_init_dispatch();
    hiaex4_impl->enc_partial_noupdate(state, ci, mi, size);
}

void
HiAEx4_dec_partial_noupdate(HiAEx4_state_t *state, uint8_t *mi, const uint8_t *ci, size_t size)
{
    assert(size < 16);
    hiaex4_init_dispatch();
    hiaex4_impl->dec_partial_noupdate(state, mi, ci, size);
}

int
HiAEx4_encrypt(const uint8_t *key,
               const uint8_t *nonce,
               const uint8_t *msg,
               uint8_t       *ct,
               size_t         msg_len,
               const uint8_t *ad,
               size_t         ad_len,
               uint8_t       *tag)
{
    hiaex4_init_dispatch();
    return hiaex4_impl->encrypt(key, nonce, msg, ct, msg_len, ad, ad_len, tag);
}

int
HiAEx4_decrypt(const uint8_t *key,
               const uint8_t *nonce,
               uint8_t       *msg,
               const uint8_t *ct,
               size_t         ct_len,
               const uint8_t *ad,
               size_t         ad_len,
               const uint8_t *tag)
{
    hiaex4_init_dispatch();
    return hiaex4_impl->decrypt(key, nonce, msg, ct, ct_len, ad, ad_len, tag);
}

int
HiAEx4_mac(
    const uint8_t *key, const uint8_t *nonce, const uint8_t *data, size_t data_len, uint8_t *tag)
{
    hiaex4_init_dispatch();
    return hiaex4_impl->mac(key, nonce, data, data_len, tag);
}

const char *
HiAEx4_get_implementation_name(void)
{
    hiaex4_init_dispatch();
    return hiaex4_impl->name;
}

int
HiAEx4_verify_tag(const uint8_t *expected_tag, const uint8_t *actual_tag)
{
    return hiaex4_constant_time_compare(expected_tag, actual_tag, HIAEX4_MACBYTES);
}

int
HiAEx4_force_implementation(const char *impl_name)
{
    // Reset current implementation to force re-initialization
    hiaex4_impl = NULL;

    if (impl_name == NULL) {
        // Clear forced implementation - restore automatic detection
        forced_impl_name = NULL;
        return 0;
    }

    // Validate that the requested implementation exists
    HiAEx4_impl_t *requested_impl = hiaex4_get_impl_by_name(impl_name);
    if (requested_impl == NULL) {
        return -1; // Implementation not available
    }

    // Set the forced implementation name
    forced_impl_name = impl_name;
    return 0;
}
