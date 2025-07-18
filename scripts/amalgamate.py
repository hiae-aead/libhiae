#!/usr/bin/env python3
"""
HiAE Amalgamation Script

This script creates a single-file amalgamation of all HiAE source files,
resolving symbol conflicts and preserving conditional compilation.
"""

import os
import sys
import re
from pathlib import Path

# File paths relative to repository root
INCLUDE_DIR = "include"
SOURCE_DIR = "src/hiae"
OUTPUT_FILE = "HiAE_amalgamated.c"

# Implementation-specific prefixes for conflict resolution
IMPL_PREFIXES = {
    "HiAE_software.c": "hiae_software",
    "HiAE_aesni.c": "hiae_aesni", 
    "HiAE_vaes_avx512.c": "hiae_vaes_avx512",
    "HiAE_arm.c": "hiae_arm",
    "HiAE_arm_sha3.c": "hiae_arm_sha3"
}

# Static inline functions that need prefixing
STATIC_INLINE_FUNCTIONS = [
    "update_state_offset",
    "keystream_block", 
    "enc_offset",
    "dec_offset",
    "state_shift",
    "init_update",
    "ad_update",
    "encrypt_chunk",
    "decrypt_chunk"
]

# Macros that need scoping
SCOPED_MACROS = [
    "DATA128b",
    "SIMD_LOAD",
    "SIMD_STORE", 
    "SIMD_XOR",
    "SIMD_AND",
    "SIMD_ZERO_128",
    "AESENC",
    "AESL",
    "XAESL",
    "PREFETCH_READ",
    "PREFETCH_WRITE",
    "PREFETCH_DISTANCE"
]

# Load/store macros
LOAD_STORE_MACROS = [
    "LOAD_1BLOCK_offset_enc",
    "LOAD_1BLOCK_offset_dec", 
    "LOAD_1BLOCK_offset_ad",
    "STORE_1BLOCK_offset_enc",
    "STORE_1BLOCK_offset_dec"
]

def get_repo_root():
    """Find the repository root directory."""
    current = Path(__file__).parent
    while current != current.parent:
        if (current / "include" / "HiAE.h").exists():
            return current
        current = current.parent
    raise RuntimeError("Could not find repository root")

def read_file(file_path):
    """Read a file and return its contents."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def write_file(file_path, content):
    """Write content to a file."""
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"Error writing {file_path}: {e}")
        return False

def remove_includes(content, implementation_file=None):
    """Remove #include statements that will be consolidated."""
    lines = content.split('\n')
    filtered_lines = []
    
    for line in lines:
        # Remove includes that we'll consolidate
        if line.strip().startswith('#include'):
            include_file = line.strip()
            # Keep system includes, remove local includes
            if ('"HiAE.h"' in include_file or 
                '"HiAE_internal.h"' in include_file or
                '"softaes.h"' in include_file):
                continue
            # Keep all other includes (system headers, intrinsics, etc.)
        filtered_lines.append(line)
    
    return '\n'.join(filtered_lines)

def prefix_static_functions(content, prefix):
    """Add implementation-specific prefixes to static inline functions."""
    for func_name in STATIC_INLINE_FUNCTIONS:
        # Replace function definitions
        pattern = r'(\s+)(' + re.escape(func_name) + r')(\s*\()'
        replacement = r'\1' + prefix + r'_\2\3'
        content = re.sub(pattern, replacement, content)
        
        # Replace function calls
        pattern = r'(\W)(' + re.escape(func_name) + r')(\s*\()'
        replacement = r'\1' + prefix + r'_\2\3'
        content = re.sub(pattern, replacement, content)
    
    return content

def scope_macros(content, prefix):
    """Add implementation-specific scoping to macro definitions."""
    lines = content.split('\n')
    scoped_lines = []
    
    for line in lines:
        stripped = line.strip()
        
        # Handle macro definitions
        if stripped.startswith('#define'):
            macro_match = re.match(r'#define\s+(\w+)', stripped)
            if macro_match:
                macro_name = macro_match.group(1)
                
                # Scope implementation-specific macros
                if macro_name in SCOPED_MACROS or macro_name in LOAD_STORE_MACROS:
                    # Add #undef first if this is a redefinition
                    scoped_lines.append(f"#undef {macro_name}")
                    # Then redefine with scoped name
                    scoped_line = line.replace(f"#define {macro_name}", 
                                               f"#define {prefix}_{macro_name}")
                    scoped_lines.append(scoped_line)
                    continue
        
        # Handle typedef lines
        if stripped.startswith('typedef') and 'DATA128b' in stripped:
            # Replace typedef DATA128b with prefixed version
            typedef_line = line.replace('DATA128b', f'{prefix}_DATA128b')
            scoped_lines.append(typedef_line)
            continue
        
        scoped_lines.append(line)
    
    return '\n'.join(scoped_lines)

def update_macro_usage(content, prefix):
    """Update macro usage to use prefixed versions."""
    for macro in SCOPED_MACROS + LOAD_STORE_MACROS:
        # Replace macro usage (not definitions)
        pattern = r'(\W)(' + re.escape(macro) + r')(\s*\()'
        replacement = r'\1' + prefix + r'_\2\3'
        content = re.sub(pattern, replacement, content)
        
        # Also handle standalone usage (e.g., DATA128b variable declarations)
        if macro != 'DATA128b':  # Skip DATA128b for now - handle separately
            pattern = r'(\W)(' + re.escape(macro) + r')(\s*[^(])'
            replacement = r'\1' + prefix + r'_\2\3'
            content = re.sub(pattern, replacement, content)
    
    # Handle DATA128b usage specifically (but not in typedef lines)
    lines = content.split('\n')
    updated_lines = []
    
    for line in lines:
        if 'DATA128b' in line and not line.strip().startswith('typedef'):
            updated_line = line
            # Replace all DATA128b occurrences (except in typedefs)
            updated_line = re.sub(r'\bDATA128b\b', prefix + '_DATA128b', updated_line)
            updated_lines.append(updated_line)
        else:
            updated_lines.append(line)
    
    return '\n'.join(updated_lines)

def wrap_implementation(content, impl_file):
    """Wrap implementation in unique namespace."""
    prefix = IMPL_PREFIXES[impl_file]
    
    # Remove includes first
    content = remove_includes(content, impl_file)
    
    # Add scoping to macros
    content = scope_macros(content, prefix)
    
    # Prefix static functions
    content = prefix_static_functions(content, prefix)
    
    # Update macro usage
    content = update_macro_usage(content, prefix)
    
    # Wrap in namespace comment
    wrapped = f"""
/* =====================================================
 * {impl_file} - {prefix} implementation
 * =====================================================
 */
{content}
/* End of {impl_file} */
"""
    
    return wrapped

def create_amalgamation():
    """Create the amalgamated source file."""
    repo_root = get_repo_root()
    print(f"Repository root: {repo_root}")
    
    include_path = repo_root / INCLUDE_DIR
    source_path = repo_root / SOURCE_DIR
    output_path = repo_root / OUTPUT_FILE
    
    # Start with header
    amalgamated_content = f"""/*
 * HiAE Amalgamated Implementation
 * 
 * This file is automatically generated by scripts/amalgamate.py
 * It contains all HiAE source files merged into a single compilation unit.
 * 
 * To use this file, simply compile it with your project:
 *   cc -O3 -o myapp myapp.c HiAE_amalgamated.c
 * 
 * The amalgamated version preserves all runtime dispatch functionality
 * and automatically selects the optimal implementation for your CPU.
 */

#ifndef HIAE_AMALGAMATED_H
#define HIAE_AMALGAMATED_H

/* Include guard to prevent multiple inclusions */
#pragma once

/* Standard C library includes */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

/* Platform-specific includes */
#ifdef __linux__
#    include <sys/auxv.h>
#endif
#ifdef __ANDROID_API__
#    include <cpu-features.h>
#endif
#ifdef __APPLE__
#    include <mach/machine.h>
#    include <sys/sysctl.h>
#    include <sys/types.h>
#endif
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#    include <intrin.h>
#endif

/* Architecture-specific intrinsics */
#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_AMD64)
#    include <immintrin.h>
#    include <wmmintrin.h>
#    ifdef __GNUC__
#        if __has_include(<vaesintrin.h>)
#            include <vaesintrin.h>
#        endif
#    endif
#endif

#ifdef __cplusplus
extern "C" {{
#endif

"""
    
    # Add public API header content
    hiae_header = read_file(include_path / "HiAE.h")
    if not hiae_header:
        print("Failed to read HiAE.h")
        return False
    
    # Extract just the content between header guards
    header_content = re.search(r'#define HIAE_H\s*\n(.*?)#endif /\* HIAE_H \*/', 
                               hiae_header, re.DOTALL)
    if header_content:
        # Remove the includes and extern C wrapper since we handle those
        header_body = header_content.group(1)
        # Remove standard includes and extern C wrapper
        header_body = re.sub(r'#include\s+<[^>]+>', '', header_body)
        header_body = re.sub(r'#ifdef __cplusplus.*?#endif', '', header_body, flags=re.DOTALL)
        amalgamated_content += header_body
    
    # Add internal header content
    internal_header = read_file(source_path / "HiAE_internal.h")
    if not internal_header:
        print("Failed to read HiAE_internal.h")
        return False
    
    # Extract internal definitions
    internal_content = re.search(r'#define HIAE_INTERNAL_H\s*\n(.*?)#endif /\* HIAE_INTERNAL_H \*/', 
                                 internal_header, re.DOTALL)
    if internal_content:
        internal_body = internal_content.group(1)
        # Remove includes we've already handled
        internal_body = re.sub(r'#include\s+"HiAE\.h"', '', internal_body)
        internal_body = re.sub(r'#include\s+<[^>]+>', '', internal_body)
        amalgamated_content += f"\n/* Internal definitions from HiAE_internal.h */\n{internal_body}\n"
    
    # Add softaes.h content
    softaes_header = read_file(source_path / "softaes.h")
    if softaes_header:
        softaes_content = re.search(r'#define SOFTAES_H\s*\n(.*?)#endif /\* SOFTAES_H \*/', 
                                    softaes_header, re.DOTALL)
        if softaes_content:
            softaes_body = softaes_content.group(1)
            softaes_body = re.sub(r'#include\s+<[^>]+>', '', softaes_body)
            amalgamated_content += f"\n/* Software AES implementation from softaes.h */\n{softaes_body}\n"
    
    # Add implementation files
    implementation_files = [
        "HiAE_software.c",
        "HiAE_aesni.c", 
        "HiAE_vaes_avx512.c",
        "HiAE_arm.c",
        "HiAE_arm_sha3.c"
    ]
    
    for impl_file in implementation_files:
        impl_path = source_path / impl_file
        if impl_path.exists():
            content = read_file(impl_path)
            if content:
                wrapped_content = wrap_implementation(content, impl_file)
                amalgamated_content += wrapped_content
        else:
            print(f"Warning: {impl_file} not found")
    
    # Add main dispatch file (HiAE.c)
    main_file = read_file(source_path / "HiAE.c")
    if main_file:
        main_content = remove_includes(main_file)
        amalgamated_content += f"""
/* =====================================================
 * HiAE.c - Main dispatch implementation
 * =====================================================
 */
{main_content}
"""
    
    # Add streaming implementation
    stream_file = read_file(source_path / "HiAE_stream.c")
    if stream_file:
        stream_content = remove_includes(stream_file)
        amalgamated_content += f"""
/* =====================================================
 * HiAE_stream.c - Streaming API implementation
 * =====================================================
 */
{stream_content}
"""
    
    # Close the amalgamation
    amalgamated_content += f"""
#ifdef __cplusplus
}}
#endif

#endif /* HIAE_AMALGAMATED_H */

/*
 * End of HiAE amalgamated implementation
 * Generated by scripts/amalgamate.py
 */
"""
    
    # Write the amalgamated file
    success = write_file(output_path, amalgamated_content)
    if success:
        print(f"Successfully created {output_path}")
        print(f"File size: {len(amalgamated_content)} bytes")
        return True
    else:
        print(f"Failed to write {output_path}")
        return False

def main():
    """Main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print(f"Usage: {sys.argv[0]}")
        print("Creates HiAE_amalgamated.c in the repository root")
        return
    
    try:
        success = create_amalgamation()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()