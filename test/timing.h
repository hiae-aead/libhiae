#ifndef TIMING_H
#define TIMING_H

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#    include <windows.h>
#elif defined(__APPLE__)
#    include <mach/mach_time.h>
#    include <sys/time.h>
#elif defined(_POSIX_VERSION) && (_POSIX_VERSION >= 199309L)
#    include <sys/time.h>
#    include <time.h>
#else
#    include <sys/time.h>
#endif

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#    define HAS_RDTSC 1
#endif

#if defined(__aarch64__) || defined(__arm__)
#    define HAS_ARM_COUNTER 1
#endif

typedef struct {
    double   start_time;
    double   end_time;
    uint64_t start_cycles;
    uint64_t end_cycles;
    int      has_cycles;
} hiae_timer_t;

typedef struct {
    double *values;
    size_t  count;
    size_t  capacity;
    double  min;
    double  max;
    double  sum;
    double  mean;
    double  median;
    double  stddev;
} hiae_stats_t;

static inline double
hiae_get_time(void)
{
#ifdef _WIN32
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (double) count.QuadPart / (double) freq.QuadPart;
#elif defined(__APPLE__)
    static mach_timebase_info_data_t timebase = { 0 };
    if (timebase.denom == 0) {
        mach_timebase_info(&timebase);
    }
    uint64_t time = mach_absolute_time();
    return (double) time * timebase.numer / timebase.denom / 1e9;
#elif defined(_POSIX_VERSION) && (_POSIX_VERSION >= 199309L)
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return ts.tv_sec + ts.tv_nsec / 1e9;
    }
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1e6;
#endif
}

#ifdef HAS_RDTSC
static inline uint64_t
hiae_read_cycles(void)
{
#    if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t) hi << 32) | lo;
#    elif defined(_M_X64) || defined(_M_IX86)
    return __rdtsc();
#    else
    return 0;
#    endif
}
#elif defined(HAS_ARM_COUNTER)
static inline uint64_t
hiae_read_cycles(void)
{
#    if defined(__aarch64__)
    uint64_t val;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(val));
    return val;
#    else
    return 0;
#    endif
}
#else
static inline uint64_t
hiae_read_cycles(void)
{
    return 0;
}
#endif

static inline int
hiae_has_cycle_counter(void)
{
#if defined(HAS_RDTSC) || defined(HAS_ARM_COUNTER)
    return 1;
#else
    return 0;
#endif
}

static inline void
hiae_timer_start(hiae_timer_t *timer)
{
    timer->has_cycles = hiae_has_cycle_counter();
    if (timer->has_cycles) {
        timer->start_cycles = hiae_read_cycles();
        timer->end_cycles   = timer->start_cycles;
    }
    timer->start_time = hiae_get_time();
    timer->end_time   = timer->start_time;
}

static inline void
hiae_timer_stop(hiae_timer_t *timer)
{
    timer->end_time = hiae_get_time();
    if (timer->has_cycles) {
        timer->end_cycles = hiae_read_cycles();
    }
}

static inline double
hiae_timer_elapsed_seconds(const hiae_timer_t *timer)
{
    return timer->end_time - timer->start_time;
}

static inline uint64_t
hiae_timer_elapsed_cycles(const hiae_timer_t *timer)
{
    if (!timer->has_cycles)
        return 0;
    return timer->end_cycles - timer->start_cycles;
}

static inline double
hiae_get_cpu_frequency(void)
{
    if (!hiae_has_cycle_counter())
        return 0.0;

    // Use a more accurate calibration method
    const int iterations         = 5;
    double    freq_sum           = 0.0;
    int       valid_measurements = 0;

    for (int i = 0; i < iterations; i++) {
        hiae_timer_t timer;

        // Use a known delay
        double target_time = 0.01; // 10ms
        hiae_timer_start(&timer);
        double start = hiae_get_time();

        // Busy wait for target time
        while ((hiae_get_time() - start) < target_time) {
            // Prevent optimization
            __asm__ __volatile__("" ::: "memory");
        }

        hiae_timer_stop(&timer);

        double   elapsed = hiae_timer_elapsed_seconds(&timer);
        uint64_t cycles  = hiae_timer_elapsed_cycles(&timer);

        if (elapsed > 0 && cycles > 0) {
            double freq = cycles / elapsed;
            // Sanity check: CPU frequency should be between 100 MHz and 10 GHz
            if (freq > 1e8 && freq < 1e10) {
                freq_sum += freq;
                valid_measurements++;
            }
        }
    }

    if (valid_measurements > 0) {
        return freq_sum / valid_measurements;
    }
    return 0.0;
}

static inline hiae_stats_t *
hiae_stats_create(size_t initial_capacity)
{
    hiae_stats_t *stats = (hiae_stats_t *) malloc(sizeof(hiae_stats_t));
    if (!stats)
        return NULL;

    stats->values = (double *) malloc(initial_capacity * sizeof(double));
    if (!stats->values) {
        free(stats);
        return NULL;
    }

    stats->capacity = initial_capacity;
    stats->count    = 0;
    stats->min      = INFINITY;
    stats->max      = -INFINITY;
    stats->sum      = 0.0;
    stats->mean     = 0.0;
    stats->median   = 0.0;
    stats->stddev   = 0.0;

    return stats;
}

static inline void
hiae_stats_destroy(hiae_stats_t *stats)
{
    if (stats) {
        free(stats->values);
        free(stats);
    }
}

static inline void
hiae_stats_add(hiae_stats_t *stats, double value)
{
    if (stats->count >= stats->capacity) {
        size_t  new_capacity = stats->capacity * 2;
        double *new_values   = (double *) realloc(stats->values, new_capacity * sizeof(double));
        if (!new_values)
            return;
        stats->values   = new_values;
        stats->capacity = new_capacity;
    }

    stats->values[stats->count++] = value;
    stats->sum += value;
    if (value < stats->min)
        stats->min = value;
    if (value > stats->max)
        stats->max = value;
}

static inline int
double_compare(const void *a, const void *b)
{
    double diff = *(double *) a - *(double *) b;
    return (diff > 0) - (diff < 0);
}

static inline void
hiae_stats_compute(hiae_stats_t *stats)
{
    if (stats->count == 0)
        return;

    stats->mean = stats->sum / stats->count;

    double *sorted = (double *) malloc(stats->count * sizeof(double));
    if (!sorted)
        return;
    memcpy(sorted, stats->values, stats->count * sizeof(double));
    qsort(sorted, stats->count, sizeof(double), double_compare);

    if (stats->count % 2 == 0) {
        stats->median = (sorted[stats->count / 2 - 1] + sorted[stats->count / 2]) / 2.0;
    } else {
        stats->median = sorted[stats->count / 2];
    }

    double variance = 0.0;
    for (size_t i = 0; i < stats->count; i++) {
        double diff = stats->values[i] - stats->mean;
        variance += diff * diff;
    }
    stats->stddev = sqrt(variance / stats->count);

    free(sorted);
}

static inline size_t
hiae_align_size(size_t size, size_t alignment)
{
    return (size + alignment - 1) & ~(alignment - 1);
}

static inline void *
hiae_aligned_alloc(size_t alignment, size_t size)
{
#ifdef _WIN32
    return _aligned_malloc(size, alignment);
#elif defined(__APPLE__) || defined(__FreeBSD__)
    void *ptr;
    if (posix_memalign(&ptr, alignment, size) != 0) {
        return NULL;
    }
    return ptr;
#else
    return aligned_alloc(alignment, size);
#endif
}

static inline void
hiae_aligned_free(void *ptr)
{
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

static inline size_t
hiae_select_iterations(size_t data_size, double target_time)
{
    // Estimate iterations based on data size and target time
    // Assume ~10-20 GB/s throughput for modern systems
    double estimated_throughput = 10e9; // 10 GB/s conservative estimate
    double time_per_op          = data_size / estimated_throughput;
    size_t iterations           = (size_t) (target_time / time_per_op);

    // Ensure minimum iterations for statistical significance
    if (data_size <= 64) {
        if (iterations < 50000)
            iterations = 50000;
    } else if (data_size <= 256) {
        if (iterations < 20000)
            iterations = 20000;
    } else if (data_size <= 1024) {
        if (iterations < 5000)
            iterations = 5000;
    } else if (data_size <= 4096) {
        if (iterations < 2000)
            iterations = 2000;
    } else {
        if (iterations < 500)
            iterations = 500;
    }

    // Set upper bounds to prevent excessive runtime
    if (iterations > 10000000)
        iterations = 10000000;

    return iterations;
}

#endif