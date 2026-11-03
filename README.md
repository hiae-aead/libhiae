# HiAE - High-Throughput Authenticated Encryption

HiAE is a high-performance, cross-platform cryptographic library implementing an AES-based authenticated encryption with associated data (AEAD) cipher. The library also includes experimental variants HiAEx2 and HiAEx4 for benchmarking purposes.

## Features

- High Performance: Achieves very high throughput on modern CPUs, including ARM CPUs
- Main Cipher: HiAE with VAES+AVX512 support (16 parallel states, 256-byte unroll)
- Experimental Variants:
  - HiAEx2: Benchmarking variant with VAES+AVX2 support (32-byte blocks, 512-byte unroll)
  - HiAEx4: Benchmarking variant optimized for AVX512 (64 parallel states, 1024-byte unroll)
- Cross-Platform: Supports x86-64, ARM64, and other architectures
- Runtime Dispatch: Selects among compiled-in backends, subject to the binary's minimum CPU requirements:
  - HiAE on x86: VAES+AVX512, AES-NI with AVX, or software
  - HiAEx2 on x86: VAES+AVX2, AES-NI+AVX, or software
  - HiAEx4 on x86: VAES+AVX512 or software
  - All three on ARM64: Crypto Extensions with optional SHA3 support, or software
  - WebAssembly: Software AES with optional compile-time SIMD128 and relaxed SIMD
- Multiple APIs: High-level all-at-once, streaming, and low-level block-oriented APIs
- No External Library Dependencies: Hosted builds use the standard C library; freestanding WebAssembly builds do not require it
- Command-Line Tool: Included `hiae` CLI for file encryption/decryption/authentication

Software fallback is available in generic builds, but may be omitted when compiler target flags guarantee a hardware backend.
Runtime dispatch cannot make a CPU-specific build portable to older hardware.

## Quick Start

### Using Make

```bash
# Build tests, benchmarks, and the CLI in bin/
make

# Build the static library (bin/libhiae.a)
make libhiae

# Run tests
make test

# Run benchmarks
make benchmark

# Generate single-file amalgamated version
make amalgamate

# Clean
make clean
```

### Using CMake

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Run correctness tests without the performance benchmarks
ctest --test-dir build --output-on-failure -LE performance
```

Build Types:

- `Release`: Default when no build type is specified; uses `-O3` on non-MSVC compilers
- `Debug`: Includes debugging symbols and assertions
- `RelWithDebInfo`: Release optimizations with debug symbols
- `MinSizeRel`: Optimized for size rather than speed

CMake builds tests and the CLI by default.
Use `-DBUILD_TESTS=OFF` and/or `-DBUILD_CLI=OFF` to omit them.
Plain `ctest` also runs the registered performance benchmarks; the `performance` label is not an automatic exclusion.

### Using Zig

```bash
# Build the static library, headers, tests, and benchmarks in zig-out/
zig build --release

# Run the correctness tests registered in build.zig
zig build test --release
```

## Installation

### From Source

With Make:

```bash
make libhiae
sudo make install
```

Make installs `libhiae.a` and `HiAE.h` under `/usr/local` by default.
Override `PREFIX` to change the destination.
It does not install the experimental headers, CLI, or CMake package files.

With CMake:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build build
sudo cmake --install build
```

CMake installs the library, all three public headers, CMake package files for `find_package(hiae)`, and the CLI when `BUILD_CLI` is enabled.
The library is static by default; pass `-DBUILD_SHARED_LIBS=ON` for a shared library.

### Direct Integration (No Build System)

Compile the source files alongside your application, which should include `HiAE.h`.
Keep the `src/common/` headers available in the source tree; the implementation includes them by relative path.
For a supported native compiler, no global CPU-specific flags are required:

```bash
# Main HiAE cipher
cc -O3 -I include -o myapp myapp.c src/hiae/*.c

# Main cipher plus experimental benchmarking variants
cc -O3 -I include -o myapp myapp.c src/hiae/*.c src/hiaex2/*.c src/hiaex4/*.c
```

Use a recent Clang, GCC, or `zig cc`, and measure performance with your compiler and target flags.
Flags such as `-march=native` can make the resulting binary unsuitable for older CPUs.

For WebAssembly, `-msimd128` enables the vector-permute software AES path.
Add `-mrelaxed-simd` only when the deployment runtime supports relaxed SIMD.
These are compile-time requirements, not features selected at runtime.

### Single-File Amalgamated Version

`HiAE_amalgamated.c` contains the main HiAE cipher, including its public API, streaming helpers, and runtime dispatch.
It does not include HiAEx2 or HiAEx4.
Regenerating it requires Python 3:

```bash
make amalgamate
```

Save this example as `myapp.c` next to the generated file:

```c
#include <stdio.h>
#include "HiAE_amalgamated.c"

int main(void)
{
    // Fixed inputs are for this demonstration only, not real encryption
    uint8_t key[32] = { 0 }, nonce[16] = { 0 };
    uint8_t plaintext[100] = { 0 }, ciphertext[100], tag[16];

    if (HiAE_encrypt(key, nonce, plaintext, ciphertext, sizeof plaintext, NULL, 0, tag) != 0) {
        return 1;
    }
    printf("Using: %s\n", HiAE_get_implementation_name());
    return 0;
}
```

Compile only `myapp.c`, since it already includes the amalgamation:

```bash
cc -O3 -o myapp myapp.c
```

Alternatively, include `HiAE.h` in your application and compile the amalgamation as a separate translation unit:

```bash
cc -O3 -I include -o myapp myapp.c HiAE_amalgamated.c
```

Use one approach or the other, not both.

## API Usage

HiAE uses a 32-byte key, a 16-byte nonce, and a 16-byte authentication tag.
Never reuse a nonce with the same key for encryption; the public MAC API also requires unique nonces.
Obtain keys from a cryptographically secure random source and manage nonces so they do not repeat.
The snippets below illustrate the API; names such as `ad_chunk1` stand for application-provided buffers.

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
    // Discard decrypted; authentication failed
    return -1;
}

// MAC-only (no encryption), using a fresh nonce
ret = HiAE_mac(key, mac_nonce, data, data_len, mac_tag);
```

Decryption returns zero only when the tag is valid.
On failure, the output buffer may contain unauthenticated plaintext and is not automatically erased.

### Streaming API

The streaming API accepts any chunk size and buffers partial blocks internally, without buffering the whole message.
Process all associated data before the message, and do not mix encryption and decryption on one state.
Total lengths are still bounded by the API's length counters and the cipher's length encoding.

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

// Buffer unauthenticated plaintext until verification succeeds
HiAE_stream_decrypt(&dec_stream, plaintext1, ciphertext1, ciphertext1_len);
HiAE_stream_decrypt(&dec_stream, plaintext2, ciphertext2, ciphertext2_len);

// Verify authentication tag
if (HiAE_stream_verify(&dec_stream, tag) != 0) {
    // Discard all plaintext returned by this stream
    return -1;
}
```

Streaming decryption returns plaintext before authentication is complete.
Do not consume or publish any of it until `HiAE_stream_verify()` succeeds.
On failure, discard every plaintext chunk; verification does not erase caller-owned output buffers.

Key Features:

- No alignment requirements - handles any chunk size
- Automatic internal buffering
- Simple API with no complex state management

### Low-Level Block API

For advanced users who need fine-grained control:

```c
HiAE_state_t state;

// Initialize state
HiAE_init(&state, key, nonce);

// Non-final associated-data chunk lengths must be multiples of 16 bytes
HiAE_absorb(&state, ad_chunk1, 64);   // Must be multiple of 16
HiAE_absorb(&state, ad_chunk2, 32);   // Must be multiple of 16
HiAE_absorb(&state, ad_chunk3, 7);    // Last call can be any size

// Non-final message chunk lengths must also be multiples of 16 bytes
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

Note: HiAEx2 and HiAEx4 are experimental variants for benchmarking purposes only and are not part of the official specification.

These variants provide analogous API families with their own function prefixes and state types.
They use the same key, nonce, and tag sizes as HiAE, but are different ciphers, not interchangeable HiAE backends:

```c
#include <HiAEx2.h>
#include <HiAEx4.h>

// HiAEx2 example (experimental benchmarking variant)
HiAEx2_encrypt(key, nonce, plaintext, ciphertext, 1024, ad, 64, tag);
HiAEx2_decrypt(key, nonce, decrypted, ciphertext, 1024, ad, 64, tag);

// HiAEx4 example (experimental benchmarking variant)
HiAEx4_encrypt(key, nonce, plaintext, ciphertext, 1024, ad, 64, tag);
HiAEx4_decrypt(key, nonce, decrypted, ciphertext, 1024, ad, 64, tag);

HiAEx2_stream_state_t stream2;
HiAEx4_stream_state_t stream4;
HiAEx2_stream_init(&stream2, key, nonce);
HiAEx4_stream_init(&stream4, key, nonce);

HiAEx2_state_t state2;
HiAEx4_state_t state4;
HiAEx2_init(&state2, key, nonce);
HiAEx4_init(&state4, key, nonce);
```

For low-level calls, non-final chunk lengths must be multiples of 32 bytes for HiAEx2 or 64 bytes for HiAEx4, compared with 16 bytes for HiAE.
The high-level streaming APIs handle this buffering automatically.
Always check decryption and verification results, as with HiAE.
The variant MAC APIs are explicitly marked insecure and not for production use in their public headers; unique nonces do not remove that warning.

## Command-Line Tool

The `hiae` CLI supports file encryption, decryption, key generation, and MAC computation.
Build it with Make or CMake:

```bash
make hiae
# Binary: bin/hiae

# Or use CMake (BUILD_CLI is ON by default)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
# Binary: build/hiae-cli/hiae
```

Usage examples with the Make-built binary:

```bash
# Generate a key
./bin/hiae keygen -o secret.key

# Encrypt a file with a random nonce
./bin/hiae encrypt -i document.pdf -o document.enc --keyfile secret.key -n random

# Decrypt the file
./bin/hiae decrypt -i document.enc -o document-restored.pdf --keyfile secret.key \
  --noncefile document.enc.nonce
```

By default, encryption writes `document.enc`, `document.enc.nonce`, and `document.enc.tag`.
Keep both sidecar files: decryption reads the tag from `<input>.tag` automatically and the nonce from `--noncefile`.
With `--embed` on both encryption and decryption, metadata is stored in the encrypted file instead.
Avoid `--verbose` when handling real keys: it prints key material.

See [hiae-cli/README.md](hiae-cli/README.md) for more CLI documentation.

## Performance

The tables below are previously recorded measurements on x86-64 and ARM64 systems, not results regenerated for every revision.
The original compiler versions, build flags, and source revisions are not recorded here, so treat these numbers as illustrative rather than reproducible performance guarantees.
Throughput is in gigabits per second (Gbps); divide by eight for decimal gigabytes per second (GB/s).

### Performance Highlights

- ARM64 (Apple Silicon M4): Recorded HiAE AEAD encryption peak of 260.32 Gbps (32.54 GB/s)
- x86-64 (AMD Zen 4): Recorded HiAEx4 AEAD encryption peak of 429.58 Gbps (53.70 GB/s)

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

These results are specific to the measured systems and message sizes.
They do not imply that HiAEx2 or HiAEx4 is always faster than HiAE, or that AVX2 alone enables VAES instructions.
Runtime dispatch selects among compiled-in backends; compiler target flags can restrict the CPUs on which a binary runs.

Run `make benchmark` to measure performance on your system. For CMake builds, always use `-DCMAKE_BUILD_TYPE=Release` for maximum performance.

## Testing

```bash
# Build and run functional, vector, streaming, and amalgamation tests
make test

# Run specific tests
make test-vectors     # HiAE IETF test vectors
make test-amalgamated # Single-file HiAE build and functionality
make benchmark        # Performance benchmarks (all variants)

# Individual test binaries (after building)
./bin/func_test            # Functional tests
./bin/test_vectors         # HiAE IETF test vectors
./bin/test_vectors_hiaex2  # Experimental HiAEx2 vectors
./bin/test_vectors_hiaex4  # Experimental HiAEx4 vectors
./bin/test_stream          # Streaming API tests
./bin/perf_test            # HiAE performance measurements
./bin/perf_x2_test         # HiAEx2 performance measurements
./bin/perf_x4_test         # HiAEx4 performance measurements
```

The library can also be built for freestanding WebAssembly with Zig, where it doesn't need a C library:

```bash
# Baseline SIMD128 for runtimes without relaxed SIMD
zig build --release -Dtarget=wasm32-freestanding -Dwasm-relaxed-simd=false

# Relaxed SIMD (the default); requires runtime support
zig build --release -Dtarget=wasm32-freestanding -Dwasm-relaxed-simd=true
```

The test programs do need a C library, so they are not built for that target.

## CMake Integration

To use HiAE in your CMake project:

```cmake
find_package(hiae REQUIRED)
add_executable(myapp main.c)
target_link_libraries(myapp PRIVATE hiae::hiae)
```

## Technical Details

- Key Size: 256 bits (32 bytes)
- Nonce Size: 128 bits (16 bytes)
- Tag Size: 128 bits (16 bytes)
- Block Size: 16 bytes (AES block size)
- State Sizes: HiAE 256 bytes, HiAEx2 512 bytes, HiAEx4 1024 bytes
- Thread Safety: Use separate states for independent operations; do not share a mutable state between threads

## References

- [Original implementation](https://github.com/Concyclics/HiAE) by Chen Han
- IETF Draft: [The HiAE Authenticated Encryption Algorithm](https://hiae-aead.github.io/draft-pham-hiae/draft-pham-cfrg-hiae.html)
- Paper: [HiAE: A High-Throughput Authenticated Encryption Algorithm for Cross-Platform Efficiency](https://eprint.iacr.org/2025/377)
