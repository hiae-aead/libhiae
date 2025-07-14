# HiAE CLI - Command Line Encryption Tool

A fast, portable command-line tool for encrypting and decrypting files using the HiAE (High-throughput Authenticated Encryption) algorithm.

## Features

- **High Performance**: Leverages HiAE's optimized implementations (VAES+AVX512, AES-NI, ARM Crypto)
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **User-Friendly**: Simple command-line interface with progress bars for large files
- **Secure**: 256-bit keys, unique nonces, authenticated encryption
- **Flexible**: Support for additional authenticated data and multiple key/nonce input methods

## Installation

### Building from Source

```bash
cd hiae-cli
make
```

To install system-wide (Unix-like systems):
```bash
sudo make install
```

### Windows

On Windows, ensure you have a C compiler (MinGW or Visual Studio) and run:
```bash
make
```

## Usage

### Basic Commands

#### Generate a Random Key
```bash
hiae keygen -o mykey.key
```

#### Encrypt a File
```bash
# With hex key and nonce
hiae encrypt -i document.pdf -o document.enc \
  -k 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  -n fedcba9876543210fedcba9876543210

# With key file and random nonce
hiae encrypt -i document.pdf -o document.enc --keyfile mykey.key -n random

# With progress bar for large files
hiae encrypt -i video.mp4 -o video.enc --keyfile mykey.key -n random -p
```

#### Decrypt a File
```bash
# With separate nonce file (created during encryption)
hiae decrypt -i document.enc -o document.pdf --keyfile mykey.key --noncefile document.enc.nonce

# With embedded metadata (if -e was used during encryption)
hiae decrypt -i document.enc -o document.pdf --keyfile mykey.key -e
```

### Advanced Usage

#### Additional Authenticated Data (AAD)
```bash
# Encrypt with AAD string
hiae encrypt -i data.json -o data.enc --keyfile mykey.key -n random \
  -a "metadata:2024-01-15"

# Encrypt with AAD from file
hiae encrypt -i data.json -o data.enc --keyfile mykey.key -n random \
  --adfile metadata.txt
```

#### Embedded Metadata
```bash
# Embed nonce and tag in encrypted file
hiae encrypt -i file.txt -o file.enc --keyfile mykey.key -n random -e

# Decrypt file with embedded metadata
hiae decrypt -i file.enc -o file.txt --keyfile mykey.key -e
```

### Command-Line Options

```
Commands:
  encrypt    Encrypt a file
  decrypt    Decrypt a file
  keygen     Generate a random key file
  help       Show help message
  version    Show version information

Options:
  -i, --input FILE       Input file path (required)
  -o, --output FILE      Output file path (required)
  -k, --key HEX          256-bit key as hex string (64 hex chars)
  -kf, --keyfile FILE    Read key from file (binary or hex)
  -n, --nonce HEX        128-bit nonce as hex string (32 hex chars)
                         Use "random" to generate randomly
  -nf, --noncefile FILE  Read nonce from file
  -a, --ad STRING        Additional authenticated data
  -af, --adfile FILE     Read additional data from file
  -t, --tagfile FILE     Tag file path (default: <output>.tag)
  -e, --embed            Embed metadata in encrypted file
  -p, --progress         Show progress bar for large files
  -v, --verbose          Verbose output
  -q, --quiet            Suppress non-error output
  -h, --help             Show help message
```

## Examples

### Simple File Encryption
```bash
# Generate a key
hiae keygen -o secret.key

# Encrypt a file
hiae encrypt -i report.pdf -o report.enc --keyfile secret.key -n random -p

# Decrypt the file
hiae decrypt -i report.enc -o report_decrypted.pdf --keyfile secret.key \
  --noncefile report.enc.nonce -p
```

### Batch Processing Script
```bash
#!/bin/bash
# encrypt_folder.sh - Encrypt all PDFs in current directory

# Generate key for this batch
hiae keygen -o batch_key.key

# Encrypt each PDF
for file in *.pdf; do
    echo "Encrypting $file..."
    hiae encrypt -i "$file" -o "${file}.enc" --keyfile batch_key.key -n random
done

echo "Done! Key saved to batch_key.key"
echo "Keep this key safe - you'll need it to decrypt the files!"
```

### Secure Communication Example
```bash
# Alice generates a shared key and sends it securely to Bob
hiae keygen -o shared_secret.key

# Alice encrypts a message
echo "Secret message" > message.txt
hiae encrypt -i message.txt -o message.enc --keyfile shared_secret.key -n random \
  -a "From: Alice, Date: 2024-01-15"

# Alice sends message.enc and message.enc.nonce to Bob

# Bob decrypts the message
hiae decrypt -i message.enc -o message_decrypted.txt --keyfile shared_secret.key \
  --noncefile message.enc.nonce -a "From: Alice, Date: 2024-01-15"
```

## Security Considerations

1. **Key Management**
   - Keep your key files secure and backed up
   - Never share keys over insecure channels
   - Use file permissions to protect key files (automatically set to 0600 on Unix)

2. **Nonce Requirements**
   - Never reuse a nonce with the same key
   - Use `-n random` for automatic secure nonce generation
   - Store nonces with encrypted files for decryption

3. **Authentication**
   - Always verify decryption succeeded before trusting decrypted data
   - Authentication failures indicate tampering or corruption
   - Additional authenticated data (AAD) must match exactly during decryption

## Performance

The CLI tool achieves near-native HiAE library performance:
- **VAES+AVX512**: 200+ Gbps on modern Intel/AMD CPUs
- **AES-NI**: 50+ Gbps on older x86-64 CPUs
- **ARM Crypto**: 20+ Gbps on ARM64 processors
- **Software**: 2+ Gbps fallback on any CPU

## Troubleshooting

### "Authentication failed" Error
- Ensure you're using the correct key and nonce
- Verify the file hasn't been corrupted during transfer
- Check that AAD matches exactly if used during encryption

### "Invalid key format" Error
- Keys must be exactly 32 bytes (256 bits)
- Hex keys must be 64 hexadecimal characters
- Check for spaces or newlines in key files

### Performance Issues
- Use `-p` flag to monitor progress
- Ensure you're not running on battery power (may throttle CPU)
- Check available disk space for output file

## Technical Details

- **Algorithm**: HiAE authenticated encryption
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 128 bits (16 bytes)
- **Tag Size**: 128 bits (16 bytes)
- **Block Processing**: 4KB chunks for optimal I/O

## License

This CLI tool follows the same license as the HiAE library it uses.