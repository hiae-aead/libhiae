#ifndef hiae_common_H
#define hiae_common_H

/*
 * Compiler / target capability detection shared by every translation unit.
 *
 * This header must be included by all implementation files and by the
 * dispatchers, so that all of them agree on which implementations exist.
 * Keeping this block in a single place is what prevents two translation
 * units from disagreeing about the availability of an implementation.
 */

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
/* target pragmas don't define these flags on clang-cl (an alternative clang driver for Windows) */
#    if defined(__clang__) && defined(_MSC_BUILD) && defined(_MSC_VER) && \
        (defined(_M_IX86) || defined(_M_AMD64)) && !defined(__SSE3__)
#        undef __SSE3__
#        undef __SSSE3__
#        undef __SSE4_1__
#        undef __AVX__
#        undef __AVX2__
#        undef __AVX512F__
#        undef __AES__
#        undef __VAES__

#        define __SSE3__    1
#        define __SSSE3__   1
#        define __SSE4_1__  1
#        define __AVX__     1
#        define __AVX2__    1
#        define __AVX512F__ 1
#        define __AES__     1
#        define __VAES__    1

/*
 * The macros above were synthesized so that the intrinsics headers expose
 * everything the target pragmas can emit. They describe the compiler, not
 * the CPU the code will run on, and must therefore never be used to decide
 * which implementations get compiled in. See cpu.h.
 */
#        define HIAE_ISA_MACROS_SYNTHESIZED 1
#    endif

#endif

#ifdef DISABLE_AVX2
#    undef HAVE_AVXINTRIN_H
#    undef HAVE_AVX2INTRIN_H
#    undef HAVE_AVX512FINTRIN_H
#    undef HAVE_VAESINTRIN_H
#endif
#ifdef DISABLE_AVX512
#    undef HAVE_AVX512FINTRIN_H
#endif

/* The C0 and C1 constants from the specification, which the parallel variants use in every lane */
#define HIAE_C0_BYTES \
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
#define HIAE_C1_BYTES \
    0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d, 0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8

#endif /* hiae_common_H */
