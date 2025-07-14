#ifndef PLATFORM_H
#define PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Platform detection
#ifdef _WIN32
#    define PLATFORM_WINDOWS
#elif defined(__APPLE__)
#    define PLATFORM_MACOS
#elif defined(__linux__)
#    define PLATFORM_LINUX
#else
#    define PLATFORM_UNIX
#endif

// File operations
void    set_binary_mode(FILE *fp);
int     file_exists(const char *filename);
int64_t get_file_size(const char *filename);

// Console operations
void clear_line(void);
int  get_terminal_width(void);
int  is_terminal(FILE *fp);

// Memory operations
int lock_memory(void *addr, size_t len);
int unlock_memory(void *addr, size_t len);

// Time operations
double get_time(void);

// Path operations
const char *get_path_separator(void);
char       *normalize_path(char *path);

#endif // PLATFORM_H