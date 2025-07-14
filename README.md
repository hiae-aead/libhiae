# HiAE - High-Throughput Authenticated Encryption

HiAE is a high-performance, cross-platform cryptographic library implementing an AES-based authenticated encryption with associated data (AEAD) cipher. It features automatic runtime CPU feature detection to select the optimal implementation for maximum performance.

## Features

- **High Performance**: Achieves over 200 Gbps throughput on modern CPUs with VAES+AVX512
- **Cross-Platform**: Supports x86-64, ARM64, and other architectures
- **Runtime Optimization**: Automatically selects the best implementation based on CPU capabilities:
  - VAES+AVX512 for latest Intel/AMD processors
  - AES-NI for x86-64 processors with hardware AES
  - ARM Crypto Extensions with optional SHA3 support for ARM64
  - Pure software fallback for universal compatibility
- **Multiple APIs**: High-level all-at-once, streaming, and low-level block-oriented APIs
- **No External Dependencies**: Only requires standard C library
- **Command-Line Tool**: Included `hiae` CLI for file encryption/decryption

## Quick Start

### Using Make (Simple)

```bash
# Build all targets
make

# Run tests
make test

# Run benchmarks
make benchmark

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
- Headers: `HiAE.h`
- CLI tool: `hiae` (if built)
- CMake package files for `find_package(hiae)`

### Direct Integration (No Build System)

You can also integrate HiAE directly into your project by simply compiling all files from the `lib/` directory along with your code. No special compilation flags are required:

```bash
# Example: Compile your project with HiAE
cc -I include/ -o myapp myapp.c lib/*.c

# Or add to your existing build:
SOURCES = main.c other.c lib/HiAE.c lib/HiAE_software.c lib/HiAE_stream.c \
          lib/HiAE_aesni.c lib/HiAE_vaes_avx512.c lib/HiAE_arm.c lib/HiAE_arm_sha3.c
```

This approach is ideal for:

- Embedding HiAE into existing projects
- Static linking without separate library files
- Simple projects without complex build systems
- Cross-compilation scenarios

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

## Command-Line Tool

HiAE includes a user-friendly CLI for file encryption:

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

Run `make benchmark` to measure performance on your system. For CMake builds, always use `-DCMAKE_BUILD_TYPE=Release` for maximum performance.

## Testing

```bash
# Run all tests
make test

# Run specific tests
make test-vectors     # IETF test vectors
make benchmark        # Performance benchmarks

# Individual test binaries (after building)
./bin/func_test       # Functional tests
./bin/test_vectors    # IETF test vectors
./bin/test_stream     # Streaming API tests
./bin/perf_test       # Performance measurements
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
