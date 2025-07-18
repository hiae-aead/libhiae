# HiAE - High-Throughput Authenticated Encryption

HiAE is a high-performance, cross-platform cryptographic library implementing an AES-based authenticated encryption with associated data (AEAD) cipher. The library also includes experimental variants HiAEx2 and HiAEx4 for benchmarking purposes.

## Features

- **High Performance**: Achieves over 200 Gbps throughput on modern CPUs, including ARM CPUs
- **Main Cipher**: HiAE with VAES+AVX512 support (16 parallel states, 256-byte unroll)
- **Experimental Variants**:
  - **HiAEx2**: Benchmarking variant with VAES+AVX2 support (32-byte blocks, 512-byte unroll)
  - **HiAEx4**: Benchmarking variant optimized for AVX512 (64 parallel states, 1024-byte unroll)
- **Cross-Platform**: Supports x86-64, ARM64, and other architectures
- **Runtime Optimization**: Automatically selects the best implementation based on CPU capabilities:
  - VAES+AVX512 for latest Intel/AMD processors
  - AES-NI for x86-64 processors with hardware AES
  - ARM Crypto Extensions with optional SHA3 support for ARM64
  - Pure software fallback for universal compatibility
- **Multiple APIs**: High-level all-at-once, streaming, and low-level block-oriented APIs
- **No External Dependencies**: Only requires standard C library
- **Command-Line Tool**: Included `hiae` CLI for file encryption/decryption/authentication

## Quick Start

### Using Make (Simple)

```bash
# Build all targets
make

# Run tests
make test

# Run benchmarks
make benchmark

# Generate single-file amalgamated version
make amalgamate

# Clean
make clean
```

### Using CMake (Advanced)

```bash
# For Release build (maximum performance)
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make

# Run tests
make test
ctest --output-on-failure
```

**Build Types:**

- `Release`: Optimized for maximum performance (-O3 optimization)
- `Debug`: Includes debugging symbols and assertions (default if not specified)
- `RelWithDebInfo`: Release optimizations with debug symbols
- `MinSizeRel`: Optimized for size rather than speed

## Installation

### From Source

```bash
# Using Make
make
sudo make install  # Optional, for system-wide installation

# Using CMake
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local ..
make
sudo make install
```

This installs:

- Library: `libhiae.a` or `libhiae.so`
- Headers: `HiAE.h`, `HiAEx2.h`, `HiAEx4.h`
- CLI tool: `hiae` (if built)
- CMake package files for `find_package(hiae)`

### Direct Integration (No Build System)

You can also integrate HiAE directly into your project by simply compiling all files from the `src/hiae/` directory along with your code. No special compilation flags are required:

```bash
# Example: Compile your project with HiAE only (recommended for production)
cc -I include/ -o myapp myapp.c src/hiae/*.c

# Or include experimental variants for benchmarking:
cc -I include/ -o myapp myapp.c src/hiae/*.c src/hiaex2/*.c src/hiaex4/*.c

# Or add to your existing build (HiAE only):
SOURCES = main.c other.c src/hiae/HiAE.c src/hiae/HiAE_software.c src/hiae/HiAE_stream.c \
          src/hiae/HiAE_aesni.c src/hiae/HiAE_vaes_avx512.c src/hiae/HiAE_arm.c src/hiae/HiAE_arm_sha3.c

# Or with experimental variants:
SOURCES = main.c other.c src/hiae/HiAE.c src/hiae/HiAE_software.c src/hiae/HiAE_stream.c \
          src/hiae/HiAE_aesni.c src/hiae/HiAE_vaes_avx512.c src/hiae/HiAE_arm.c src/hiae/HiAE_arm_sha3.c \
          src/hiaex2/HiAEx2.c src/hiaex2/HiAEx2_software.c src/hiaex2/HiAEx2_stream.c \
          src/hiaex2/HiAEx2_vaes_avx2.c src/hiaex2/HiAEx2_arm.c src/hiaex2/HiAEx2_arm_sha3.c \
          src/hiaex4/HiAEx4.c src/hiaex4/HiAEx4_software.c src/hiaex4/HiAEx4_stream.c \
          src/hiaex4/HiAEx4_vaes_avx512.c src/hiaex4/HiAEx4_arm.c src/hiaex4/HiAEx4_arm_sha3.c
```

**Compiler Recommendation:** For best performance, we highly recommend using **clang** or **zig cc** instead of gcc. These compilers produce significantly better optimized code for HiAE, especially for the vectorized implementations (VAES, AES-NI, ARM Crypto). If you must use gcc, ensure you're using a recent version (GCC 14+ recommended).

This approach is ideal for:

- Embedding HiAE into existing projects
- Static linking without separate library files
- Simple projects without complex build systems
- Cross-compilation scenarios

### Single-File Amalgamated Version

For the easiest integration, HiAE provides a single-file amalgamated version that combines all source files into one compilation unit with resolved symbol conflicts:

```bash
# Generate the amalgamated file
make amalgamate

# Use it in your project (no build system or headers required)
cc -O3 -o myapp myapp.c HiAE_amalgamated.c
```

**Benefits of the amalgamated version:**
- **Zero setup**: No build system configuration needed
- **No headers**: Include the amalgamated source file directly
- **No symbol conflicts**: All internal conflicts resolved automatically
- **Embedded-friendly**: Perfect for constrained environments
- **Complete functionality**: All APIs, implementations, and runtime dispatch preserved

**Example usage:**
```c
// Include the amalgamated source directly
#include "HiAE_amalgamated.c"

int main() {
    uint8_t key[32], nonce[16], plaintext[100], ciphertext[100], tag[16];
    // ... initialize key, nonce, plaintext ...
    
    // Use HiAE normally - all APIs work exactly the same
    HiAE_encrypt(key, nonce, plaintext, ciphertext, 100, NULL, 0, tag);
    
    // Runtime dispatch still works
    printf("Using: %s\n", HiAE_get_implementation_name());
    
    return 0;
}
```

The amalgamated version is ideal for:
- Simple projects that want minimal setup
- Embedded systems with limited toolchain support
- Projects that need to vendor dependencies
- Cross-compilation scenarios where build systems are complex
- Quick prototyping and testing

## API Usage

### High-Level API (All-at-Once)

```c
#include <HiAE.h>

// Encryption
uint8_t key[32] = {...};      // 256-bit key
uint8_t nonce[16] = {...};    // 128-bit nonce/IV
uint8_t plaintext[1024] = {...};
uint8_t ciphertext[1024];
uint8_t tag[16];              // 128-bit authentication tag
uint8_t ad[64] = {...};       // Optional associated data

int ret = HiAE_encrypt(key, nonce, plaintext, ciphertext, 1024,
                       ad, 64, tag);

// Decryption with authentication
uint8_t decrypted[1024];
ret = HiAE_decrypt(key, nonce, decrypted, ciphertext, 1024,
                   ad, 64, tag);
if (ret != 0) {
    // Authentication failed!
}

// MAC-only (no encryption)
ret = HiAE_mac(key, nonce, data, data_len, tag);
```

### Streaming API

The streaming API allows processing data in chunks without size limitations:

```c
// Streaming encryption
HiAE_stream_state_t enc_stream;
uint8_t key[32] = {...};
uint8_t nonce[16] = {...};
uint8_t tag[16];

// Initialize for encryption
HiAE_stream_init(&enc_stream, key, nonce);

// Process associated data (optional, can be called multiple times)
HiAE_stream_absorb(&enc_stream, ad_chunk1, ad_chunk1_len);
HiAE_stream_absorb(&enc_stream, ad_chunk2, ad_chunk2_len);

// Encrypt data in chunks (can be called multiple times)
HiAE_stream_encrypt(&enc_stream, ciphertext1, plaintext1, plaintext1_len);
HiAE_stream_encrypt(&enc_stream, ciphertext2, plaintext2, plaintext2_len);

// Finalize and get authentication tag
HiAE_stream_finalize(&enc_stream, tag);

// Streaming decryption
HiAE_stream_state_t dec_stream;
HiAE_stream_init(&dec_stream, key, nonce);

// Process associated data (must match encryption)
HiAE_stream_absorb(&dec_stream, ad_chunk1, ad_chunk1_len);
HiAE_stream_absorb(&dec_stream, ad_chunk2, ad_chunk2_len);

// Decrypt data in chunks
HiAE_stream_decrypt(&dec_stream, plaintext1, ciphertext1, ciphertext1_len);
HiAE_stream_decrypt(&dec_stream, plaintext2, ciphertext2, ciphertext2_len);

// Verify authentication tag
if (HiAE_stream_verify(&dec_stream, tag) != 0) {
    // Authentication failed!
}
```

**Key Features:**

- No alignment requirements - handles any chunk size
- Automatic internal buffering
- Simple API with no complex state management

### Low-Level Block API

For advanced users who need fine-grained control:

```c
HiAE_state_t state;

// Initialize state
HiAE_init(&state, key, nonce);

// Process additional data (16-byte alignment required except last chunk)
HiAE_absorb(&state, ad_chunk1, 64);   // Must be multiple of 16
HiAE_absorb(&state, ad_chunk2, 32);   // Must be multiple of 16
HiAE_absorb(&state, ad_chunk3, 7);    // Last call can be any size

// Encrypt data (same alignment requirements)
HiAE_enc(&state, ct_chunk1, pt_chunk1, 256);  // Multiple of 16
HiAE_enc(&state, ct_chunk2, pt_chunk2, 64);   // Multiple of 16
HiAE_enc(&state, ct_chunk3, pt_chunk3, 13);   // Last call any size

// Finalize and get authentication tag
HiAE_finalize(&state, total_ad_len, total_msg_len, tag);
```

### Query Implementation

```c
const char *impl = HiAE_get_implementation_name();
printf("Using: %s\n", impl);  // e.g., "VAES+AVX512", "AES-NI", "ARM SHA3"
```

### Experimental Variants (HiAEx2 and HiAEx4)

**Note**: HiAEx2 and HiAEx4 are experimental variants for benchmarking purposes only and are not part of the official specification.

These variants provide identical APIs to HiAE but with different performance characteristics:

```c
#include <HiAEx2.h>
#include <HiAEx4.h>

// HiAEx2 example (experimental benchmarking variant)
HiAEx2_encrypt(key, nonce, plaintext, ciphertext, 1024, ad, 64, tag);
HiAEx2_decrypt(key, nonce, decrypted, ciphertext, 1024, ad, 64, tag);

// HiAEx4 example (experimental benchmarking variant)
HiAEx4_encrypt(key, nonce, plaintext, ciphertext, 1024, ad, 64, tag);
HiAEx4_decrypt(key, nonce, decrypted, ciphertext, 1024, ad, 64, tag);

// Streaming APIs also available
HiAEx2_stream_init(&stream, key, nonce);
HiAEx4_stream_init(&stream, key, nonce);

// Low-level APIs with different block size requirements:
// HiAE: 16-byte blocks, HiAEx2: 32-byte blocks, HiAEx4: 64-byte blocks
HiAEx2_init(&state, key, nonce);  // 32-byte alignment for multi-block calls
HiAEx4_init(&state, key, nonce);  // 64-byte alignment for multi-block calls
```

When used as a MAC, unique nonces is currently required with these variants.

**Benchmarking Characteristics:**

- **HiAE**: Standard implementation (use this for production)
- **HiAEx4**: Maximum throughput on latest processors with full AVX512 support
- **HiAEx2**: Broader compatibility for processors with AVX2 but no AVX512

## Command-Line Tool

HiAE includes a user-friendly CLI for file encryption. To build the CLI:

```bash
# Using CMake (CLI is built by default)
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make

# CLI binary will be at: build/hiae-cli/hiae
```

Usage examples:

```bash
# Generate a key
hiae keygen -o secret.key

# Encrypt a file
hiae encrypt -i document.pdf -o document.enc --keyfile secret.key -n random

# Decrypt the file
hiae decrypt -i document.enc -o document.pdf --keyfile secret.key \
  --noncefile document.enc.nonce
```

See [hiae-cli/README.md](hiae-cli/README.md) for detailed CLI documentation.

## Performance

HiAE achieves exceptional performance on modern processors. Benchmarks have been measured on both x86-64 and ARM64 architectures.

### Performance Highlights

- **ARM64 (Apple Silicon M4)**: Up to 261 Gbps AEAD encryption throughput (31 GB/s) with HiAE
- **x86-64 (AMD Zen 4)**: Up to 429 Gbps AEAD encryption throughput (51 GB/s) with HiAEx4
- Excellent performance across different processor architectures

### HiAE Performance on ARM64 (Apple Silicon M4, ARM SHA3)

#### AEAD Performance

| Size (bytes) | Encrypt (Gbps) | Decrypt (Gbps) |
| ------------ | -------------- | -------------- |
| 65536        | 252.43         | 164.06         |
| 32768        | 260.32         | 167.28         |
| 16384        | 252.21         | 163.11         |
| 8192         | 238.00         | 156.08         |
| 4096         | 212.72         | 142.92         |
| 2048         | 176.91         | 120.70         |
| 1024         | 130.94         | 95.34          |
| 512          | 88.88          | 67.23          |
| 256          | 54.01          | 41.65          |
| 64           | 15.84          | 12.09          |
| 16           | 4.15           | 3.01           |

#### Encryption-Only Performance

| Size (bytes) | Encrypt (Gbps) | Decrypt (Gbps) |
| ------------ | -------------- | -------------- |
| 65536        | 259.96         | 165.61         |
| 32768        | 261.61         | 168.76         |
| 16384        | 255.11         | 163.91         |
| 8192         | 243.14         | 155.73         |
| 4096         | 222.74         | 141.97         |
| 2048         | 190.63         | 121.60         |
| 1024         | 148.15         | 97.72          |
| 512          | 103.18         | 66.64          |
| 256          | 62.58          | 42.94          |
| 64           | 19.80          | 14.13          |
| 16           | 5.24           | 3.63           |

#### MAC-Only Performance

| Size (bytes) | Throughput (Gbps) |
| ------------ | ----------------- |
| 65536        | 241.60            |
| 32768        | 239.60            |
| 16384        | 235.11            |
| 8192         | 227.03            |
| 4096         | 212.03            |
| 2048         | 187.61            |
| 1024         | 152.41            |
| 512          | 106.97            |
| 256          | 66.33             |
| 64           | 20.83             |
| 16           | 5.47              |

### Streaming API Performance on ARM64 (1MB total)

| Chunk Size | HiAE (Gbps) |
| ---------- | ----------- |
| 65536      | 257.09      |
| 32768      | 256.35      |
| 16384      | 254.48      |
| 4096       | 245.59      |
| 1024       | 215.96      |
| 256        | 133.88      |
| 64         | 64.40       |
| 16         | 18.04       |

### HiAE Performance on x86-64 (AMD Zen 4, VAES+AVX512)

#### AEAD Performance

| Size (bytes) | Encrypt (Gbps) | Decrypt (Gbps) |
| ------------ | -------------- | -------------- |
| 65536        | 251.72         | 139.37         |
| 32768        | 254.24         | 136.01         |
| 16384        | 222.32         | 129.71         |
| 8192         | 195.73         | 118.83         |
| 4096         | 155.76         | 100.61         |
| 2048         | 113.09         | 77.43          |
| 1024         | 70.85          | 53.05          |
| 512          | 40.45          | 32.58          |
| 256          | 21.76          | 18.00          |

#### MAC-Only Performance

| Size (bytes) | Throughput (Gbps) |
| ------------ | ----------------- |
| 65536        | 318.34            |
| 32768        | 308.63            |
| 16384        | 294.15            |
| 8192         | 265.85            |
| 4096         | 224.36            |

### HiAEx2 Performance on x86-64 (AMD Zen 4, VAES-AVX2)

#### AEAD Performance

| Size (bytes) | Encrypt (Gbps) | Decrypt (Gbps) |
| ------------ | -------------- | -------------- |
| 65536        | 413.20         | 267.42         |
| 32768        | 392.98         | 257.37         |
| 16384        | 338.59         | 239.28         |
| 8192         | 366.33         | 210.79         |
| 4096         | 291.35         | 170.06         |
| 2048         | 214.61         | 121.92         |
| 1024         | 131.68         | 78.69          |
| 512          | 68.36          | 45.12          |
| 256          | 41.40          | 24.28          |

#### MAC-Only Performance

| Size (bytes) | Throughput (Gbps) |
| ------------ | ----------------- |
| 65536        | 556.07            |
| 32768        | 586.48            |
| 16384        | 545.86            |
| 8192         | 464.27            |
| 4096         | 357.46            |

### HiAEx4 Performance on x86-64 (AMD Zen 4, VAES-AVX512)

#### AEAD Performance

| Size (bytes) | Encrypt (Gbps) | Decrypt (Gbps) |
| ------------ | -------------- | -------------- |
| 65536        | 429.58         | 366.26         |
| 32768        | 375.41         | 337.97         |
| 16384        | 360.00         | 292.23         |
| 8192         | 302.43         | 226.27         |
| 4096         | 206.21         | 155.56         |
| 2048         | 124.24         | 96.12          |
| 1024         | 69.28          | 54.09          |
| 512          | 34.03          | 30.06          |
| 256          | 19.27          | 15.23          |

#### MAC-Only Performance

| Size (bytes) | Throughput (Gbps) |
| ------------ | ----------------- |
| 65536        | 662.08            |
| 32768        | 603.84            |
| 16384        | 499.15            |
| 8192         | 369.09            |
| 4096         | 242.67            |

### Streaming API Performance on x86-64 (1MB total)

| Chunk Size | HiAE (Gbps) | HiAEx2 (Gbps) | HiAEx4 (Gbps) |
| ---------- | ----------- | ------------- | ------------- |
| 65536      | 251.12      | 329.47        | 359.56        |
| 32768      | 248.29      | 326.31        | 354.72        |
| 16384      | 242.24      | 320.61        | 347.00        |
| 4096       | 212.31      | 312.28        | 322.90        |
| 1024       | 144.53      | 272.73        | 257.31        |
| 256        | 66.96       | 148.45        | 126.03        |
| 64         | 16.77       | 59.92         | 40.12         |
| 16         | 4.59        | 5.78          | 4.04          |

### Performance Notes

- **HiAE** (standard implementation) provides excellent performance with the broadest compatibility
- **HiAEx2** offers higher throughput on processors with AVX2 support
- **HiAEx4** achieves maximum throughput on processors with full AVX512 support
- All implementations automatically select the best available instruction set at runtime
- Decryption is generally slower than encryption due to the algorithm design
- Performance scales well with larger data sizes
- Both x86-64 and ARM64 architectures show excellent performance characteristics

Run `make benchmark` to measure performance on your system. For CMake builds, always use `-DCMAKE_BUILD_TYPE=Release` for maximum performance.

## Testing

```bash
# Run all tests
make test

# Run specific tests
make test-vectors     # IETF test vectors
make benchmark        # Performance benchmarks (all variants)

# Individual test binaries (after building)
./bin/func_test       # Functional tests
./bin/test_vectors    # IETF test vectors
./bin/test_stream     # Streaming API tests
./bin/perf_test       # HiAE performance measurements
./bin/perf_x2_test    # HiAEx2 performance measurements
./bin/perf_x4_test    # HiAEx4 performance measurements
```

## CMake Integration

To use HiAE in your CMake project:

```cmake
find_package(hiae REQUIRED)
add_executable(myapp main.c)
target_link_libraries(myapp PRIVATE hiae::hiae)
```

## Technical Details

- **Algorithm**: HiAE AEAD cipher (see `draft-pham-cfrg-hiae.md`)
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 128 bits (16 bytes)
- **Tag Size**: 128 bits (16 bytes)
- **Block Size**: 16 bytes (AES block size)
- **Security**: 128-bit authentication, 256-bit encryption
- **Thread Safety**: Each state is independent

## References

- [Original implememntation](https://github.com/Concyclics/HiAE) by Chen Han
- IETF Draft: [The HiAE Authenticated Encryption Algorithm](https://hiae-aead.github.io/draft-pham-hiae/draft-pham-cfrg-hiae.html)
- Paper: [HiAE: A High-Throughput Authenticated Encryption Algorithm for Cross-Platform Efficiency](https://eprint.iacr.org/2025/377)
