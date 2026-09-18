#ifndef hiae_cpu_H
#define hiae_cpu_H

#include "common.h"

/*
 * HIAE*_HAS_HW_AES is set when the compilation baseline itself guarantees that
 * a hardware implementation of the corresponding variant is present. In that
 * case the software implementation is not compiled in at all.
 *
 * Every translation unit that needs to know whether the software
 * implementation exists must test these macros, and only these macros.
 * Testing __AES__ & friends directly is not equivalent: on clang-cl they are
 * synthesized in common.h so that the intrinsics headers work, and they then
 * describe the compiler rather than the target CPU.
 */

#if defined(__ARM_FEATURE_CRYPTO)
#    define HIAE_HAS_HW_AES
#    define HIAEX2_HAS_HW_AES
#    define HIAEX4_HAS_HW_AES
#elif !defined(HIAE_ISA_MACROS_SYNTHESIZED)
#    if defined(__AES__) && defined(__VAES__) && defined(__AVX512F__)
#        define HIAE_HAS_HW_AES
#    endif
#    if defined(__AES__) && defined(__VAES__) && defined(__AVX512F__) && defined(__AVX512VL__)
#        define HIAEX4_HAS_HW_AES
#    endif
#    if defined(__AES__) && defined(__VAES__) && defined(__AVX2__)
#        define HIAEX2_HAS_HW_AES
#    endif
#endif

#endif /* hiae_cpu_H */
