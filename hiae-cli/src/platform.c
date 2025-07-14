#include "platform.h"
#include <string.h>
#include <sys/stat.h>

#ifdef PLATFORM_WINDOWS
#    include <fcntl.h>
#    include <io.h>
#    include <windows.h>
#else
#    include <sys/ioctl.h>
#    include <sys/mman.h>
#    include <sys/time.h>
#    include <termios.h>
#    include <unistd.h>
#endif

void
set_binary_mode(FILE *fp)
{
#ifdef PLATFORM_WINDOWS
    _setmode(_fileno(fp), _O_BINARY);
#else
    // Not needed on Unix-like systems
    (void) fp;
#endif
}

int
file_exists(const char *filename)
{
    struct stat st;
    return (stat(filename, &st) == 0);
}

int64_t
get_file_size(const char *filename)
{
    struct stat st;
    if (stat(filename, &st) != 0) {
        return -1;
    }
    return (int64_t) st.st_size;
}

void
clear_line(void)
{
    printf("\r\033[K");
    fflush(stdout);
}

int
get_terminal_width(void)
{
#ifdef PLATFORM_WINDOWS
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
        return csbi.srWindow.Right - csbi.srWindow.Left + 1;
    }
    return 80; // Default
#else
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) {
        return w.ws_col;
    }
    return 80; // Default
#endif
}

int
is_terminal(FILE *fp)
{
#ifdef PLATFORM_WINDOWS
    return _isatty(_fileno(fp));
#else
    return isatty(fileno(fp));
#endif
}

int
lock_memory(void *addr, size_t len)
{
#ifdef PLATFORM_WINDOWS
    return VirtualLock(addr, len) ? 0 : -1;
#elif defined(_POSIX_MEMLOCK)
    return mlock(addr, len);
#else
    // Not supported
    (void) addr;
    (void) len;
    return -1;
#endif
}

int
unlock_memory(void *addr, size_t len)
{
#ifdef PLATFORM_WINDOWS
    return VirtualUnlock(addr, len) ? 0 : -1;
#elif defined(_POSIX_MEMLOCK)
    return munlock(addr, len);
#else
    // Not supported
    (void) addr;
    (void) len;
    return -1;
#endif
}

double
get_time(void)
{
#ifdef PLATFORM_WINDOWS
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double) count.QuadPart / (double) freq.QuadPart;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
#endif
}

const char *
get_path_separator(void)
{
#ifdef PLATFORM_WINDOWS
    return "\\";
#else
    return "/";
#endif
}

char *
normalize_path(char *path)
{
    if (!path)
        return NULL;

#ifdef PLATFORM_WINDOWS
    // Convert forward slashes to backslashes on Windows
    for (char *p = path; *p; p++) {
        if (*p == '/')
            *p = '\\';
    }
#else
    // Convert backslashes to forward slashes on Unix
    for (char *p = path; *p; p++) {
        if (*p == '\\')
            *p = '/';
    }
#endif

    return path;
}