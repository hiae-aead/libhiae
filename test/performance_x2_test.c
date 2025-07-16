#include "HiAEx2.h"
#include "timing.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BASE_ITERATIONS  10000 // Base iterations for size 16
#define WARMUP_TIME      0.5 // 0.5s warmup
#define COMPUTATION_TIME 1.0 // 1s computation time for measurements
#define NUM_MEASUREMENTS 5 // Number of measurement runs

const int len_test_case = 11;
size_t    test_case[11] = { 65536, 32768, 16384, 8192, 4096, 2048, 1024, 512, 256, 64, 16 };

static int csv_output = 0;

void
print_data(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

typedef struct {
    double        gbps;
    double        mbps;
    double        cycles_per_byte;
    hiae_stats_t *stats;
} perf_result_t;

static size_t
calculate_iterations(double warmup_time, size_t warmup_iterations)
{
    // Calculate iterations needed for COMPUTATION_TIME based on warmup performance
    if (warmup_time <= 0 || warmup_iterations == 0) {
        return 100; // Fallback if warmup failed
    }

    double iterations_per_second = (double) warmup_iterations / warmup_time;
    size_t target_iterations     = (size_t) (iterations_per_second * COMPUTATION_TIME);

    // Apply reasonable bounds
    if (target_iterations < 10)
        target_iterations = 10; // Minimum 10 iterations
    if (target_iterations > 100000)
        target_iterations = 100000; // Maximum 100k iterations

    return target_iterations;
}

perf_result_t
speed_test_ad_work(size_t len)
{
    perf_result_t result = { 0 };

    uint8_t key[HIAEX2_KEYBYTES];
    memset(key, 1, HIAEX2_KEYBYTES);
    uint8_t nonce[HIAEX2_NONCEBYTES];
    memset(nonce, 1, HIAEX2_NONCEBYTES);

    uint8_t *ad = hiae_aligned_alloc(16, len);
    if (!ad) {
        fprintf(stderr, "Failed to allocate memory\n");
        return result;
    }
    memset(ad, 1, len);

    uint8_t tag[HIAEX2_MACBYTES];

    // Warmup phase - run for specified time
    hiae_timer_t warmup_timer;
    hiae_timer_start(&warmup_timer);
    size_t warmup_iterations = 0;

    do {
        HiAEx2_mac(key, nonce, ad, len, tag);
        warmup_iterations++;
        hiae_timer_stop(&warmup_timer);
    } while (hiae_timer_elapsed_seconds(&warmup_timer) < WARMUP_TIME);

    // Calculate iterations based on warmup performance
    double warmup_time                = hiae_timer_elapsed_seconds(&warmup_timer);
    size_t iterations_per_measurement = calculate_iterations(warmup_time, warmup_iterations);

    result.stats = hiae_stats_create(NUM_MEASUREMENTS);
    if (!result.stats) {
        hiae_aligned_free(ad);
        return result;
    }

    for (int i = 0; i < NUM_MEASUREMENTS; i++) {
        hiae_timer_t timer;
        hiae_timer_start(&timer);

        for (size_t iter = 0; iter < iterations_per_measurement; iter++) {
            HiAEx2_mac(key, nonce, ad, len, tag);
        }

        hiae_timer_stop(&timer);

        double elapsed    = hiae_timer_elapsed_seconds(&timer);
        double throughput = ((double) iterations_per_measurement * len) / elapsed;
        hiae_stats_add(result.stats, throughput);
    }

    hiae_stats_compute(result.stats);

    result.mbps = result.stats->median / (1024.0 * 1024.0);
    result.gbps = (result.stats->median * 8.0) / 1e9;

    if (hiae_has_cycle_counter()) {
        double cpu_freq = hiae_get_cpu_frequency();
        if (cpu_freq > 0) {
            result.cycles_per_byte = cpu_freq / result.stats->median;
        }
    }

    hiae_aligned_free(ad);
    return result;
}

perf_result_t
speed_test_encode_work(size_t len, int AEAD)
{
    perf_result_t result = { 0 };

    uint8_t key[HIAEX2_KEYBYTES];
    memset(key, 1, HIAEX2_KEYBYTES);
    uint8_t nonce[HIAEX2_NONCEBYTES];
    memset(nonce, 1, HIAEX2_NONCEBYTES);

    size_t   ad_len = AEAD ? 48 : 0;
    uint8_t *ad     = NULL;
    if (ad_len > 0) {
        ad = hiae_aligned_alloc(16, ad_len);
        if (!ad) {
            fprintf(stderr, "Failed to allocate AD memory\n");
            return result;
        }
        memset(ad, 1, ad_len);
    }

    uint8_t *msg = hiae_aligned_alloc(16, len);
    uint8_t *ct  = hiae_aligned_alloc(16, len);
    if (!msg || !ct) {
        fprintf(stderr, "Failed to allocate memory\n");
        hiae_aligned_free(ad);
        hiae_aligned_free(msg);
        hiae_aligned_free(ct);
        return result;
    }
    memset(msg, 0x1, len);

    uint8_t tag[HIAEX2_MACBYTES];

    // Warmup phase - run for specified time
    hiae_timer_t warmup_timer;
    hiae_timer_start(&warmup_timer);
    size_t warmup_iterations = 0;

    do {
        HiAEx2_encrypt(key, nonce, msg, ct, len, ad, ad_len, tag);
        warmup_iterations++;
        hiae_timer_stop(&warmup_timer);
    } while (hiae_timer_elapsed_seconds(&warmup_timer) < WARMUP_TIME);

    // Calculate iterations based on warmup performance
    double warmup_time                = hiae_timer_elapsed_seconds(&warmup_timer);
    size_t iterations_per_measurement = calculate_iterations(warmup_time, warmup_iterations);

    result.stats = hiae_stats_create(NUM_MEASUREMENTS);
    if (!result.stats) {
        hiae_aligned_free(ad);
        hiae_aligned_free(msg);
        hiae_aligned_free(ct);
        return result;
    }

    for (int i = 0; i < NUM_MEASUREMENTS; i++) {
        hiae_timer_t timer;
        hiae_timer_start(&timer);

        for (size_t iter = 0; iter < iterations_per_measurement; iter++) {
            HiAEx2_encrypt(key, nonce, msg, ct, len, ad, ad_len, tag);
        }

        hiae_timer_stop(&timer);

        double elapsed    = hiae_timer_elapsed_seconds(&timer);
        double throughput = ((double) iterations_per_measurement * len) / elapsed;
        hiae_stats_add(result.stats, throughput);
    }

    hiae_stats_compute(result.stats);

    result.mbps = result.stats->median / (1024.0 * 1024.0);
    result.gbps = (result.stats->median * 8.0) / 1e9;

    if (hiae_has_cycle_counter()) {
        double cpu_freq = hiae_get_cpu_frequency();
        if (cpu_freq > 0) {
            result.cycles_per_byte = cpu_freq / result.stats->median;
        }
    }

    hiae_aligned_free(ad);
    hiae_aligned_free(msg);
    hiae_aligned_free(ct);
    return result;
}

perf_result_t
speed_test_decode_work(size_t len, int AEAD)
{
    perf_result_t result = { 0 };

    uint8_t key[HIAEX2_KEYBYTES];
    memset(key, 1, HIAEX2_KEYBYTES);
    uint8_t nonce[HIAEX2_NONCEBYTES];
    memset(nonce, 1, HIAEX2_NONCEBYTES);

    size_t   ad_len = AEAD ? 48 : 0;
    uint8_t *ad     = NULL;
    if (ad_len > 0) {
        ad = hiae_aligned_alloc(16, ad_len);
        if (!ad) {
            fprintf(stderr, "Failed to allocate AD memory\n");
            return result;
        }
        memset(ad, 1, ad_len);
    }

    uint8_t *msg = hiae_aligned_alloc(16, len);
    uint8_t *ct  = hiae_aligned_alloc(16, len);
    uint8_t *dec = hiae_aligned_alloc(16, len);
    if (!msg || !ct || !dec) {
        fprintf(stderr, "Failed to allocate memory\n");
        hiae_aligned_free(ad);
        hiae_aligned_free(msg);
        hiae_aligned_free(ct);
        hiae_aligned_free(dec);
        return result;
    }
    memset(msg, 0x1, len);

    uint8_t tag[HIAEX2_MACBYTES];
    HiAEx2_encrypt(key, nonce, msg, ct, len, ad, ad_len, tag);

    // Warmup phase - run for specified time
    hiae_timer_t warmup_timer;
    hiae_timer_start(&warmup_timer);
    size_t warmup_iterations = 0;

    do {
        HiAEx2_decrypt(key, nonce, ct, dec, len, ad, ad_len, tag);
        warmup_iterations++;
        hiae_timer_stop(&warmup_timer);
    } while (hiae_timer_elapsed_seconds(&warmup_timer) < WARMUP_TIME);

    // Calculate iterations based on warmup performance
    double warmup_time                = hiae_timer_elapsed_seconds(&warmup_timer);
    size_t iterations_per_measurement = calculate_iterations(warmup_time, warmup_iterations);

    result.stats = hiae_stats_create(NUM_MEASUREMENTS);
    if (!result.stats) {
        hiae_aligned_free(ad);
        hiae_aligned_free(msg);
        hiae_aligned_free(ct);
        hiae_aligned_free(dec);
        return result;
    }

    for (int i = 0; i < NUM_MEASUREMENTS; i++) {
        hiae_timer_t timer;
        hiae_timer_start(&timer);

        for (size_t iter = 0; iter < iterations_per_measurement; iter++) {
            HiAEx2_decrypt(key, nonce, ct, dec, len, ad, ad_len, tag);
        }

        hiae_timer_stop(&timer);

        double elapsed    = hiae_timer_elapsed_seconds(&timer);
        double throughput = ((double) iterations_per_measurement * len) / elapsed;
        hiae_stats_add(result.stats, throughput);
    }

    hiae_stats_compute(result.stats);

    result.mbps = result.stats->median / (1024.0 * 1024.0);
    result.gbps = (result.stats->median * 8.0) / 1e9;

    if (hiae_has_cycle_counter()) {
        double cpu_freq = hiae_get_cpu_frequency();
        if (cpu_freq > 0) {
            result.cycles_per_byte = cpu_freq / result.stats->median;
        }
    }

    hiae_aligned_free(ad);
    hiae_aligned_free(msg);
    hiae_aligned_free(ct);
    hiae_aligned_free(dec);
    return result;
}

void
print_result(const char *operation, size_t len, perf_result_t *result)
{
    if (csv_output) {
        printf("%zu,%s,%.2f,%.2f", len, operation, result->gbps, result->mbps);

        if (result->cycles_per_byte > 0) {
            printf(",%.2f", result->cycles_per_byte);
        } else {
            printf(",");
        }

        if (result->stats) {
            double cv = (result->stats->stddev / result->stats->mean) * 100.0;
            printf(",%.2f\n", cv);
        } else {
            printf(",\n");
        }
    } else {
        printf("%-8zu | %-10s | %8.2f | %8.2f", len, operation, result->gbps, result->mbps);

        if (result->cycles_per_byte > 0) {
            printf(" | %6.2f", result->cycles_per_byte);
        } else {
            printf(" |    N/A");
        }

        if (result->stats) {
            double cv = (result->stats->stddev / result->stats->mean) * 100.0;
            printf(" | %5.2f%%\n", cv);
        } else {
            printf(" |    N/A\n");
        }
    }
}

void
speed_test_encryption(void)
{
    if (csv_output) {
        printf("\n# Encryption Only Performance\n");
        printf("Size,Operation,Gbps,MB/s,Cycles/Byte,CV%%\n");
    } else {
        printf("\n================ Encryption Only Performance ================\n");
        printf("Size     | Operation  |   Gbps   |   MB/s   | cyc/B  | CV%%\n");
        printf("---------|------------|----------|----------|--------|-------\n");
    }

    for (int i = 0; i < len_test_case; i++) {
        perf_result_t enc_result = speed_test_encode_work(test_case[i], 0);
        perf_result_t dec_result = speed_test_decode_work(test_case[i], 0);

        print_result("encrypt", test_case[i], &enc_result);
        print_result("decrypt", test_case[i], &dec_result);

        hiae_stats_destroy(enc_result.stats);
        hiae_stats_destroy(dec_result.stats);

        if (!csv_output && i < len_test_case - 1) {
            printf("---------|------------|----------|----------|--------|-------\n");
        }
    }
}

void
speed_test_ad_only(void)
{
    if (csv_output) {
        printf("\n# AD Only (MAC) Performance\n");
        printf("Size,Operation,Gbps,MB/s,Cycles/Byte,CV%%\n");
    } else {
        printf("\n================ AD Only (MAC) Performance ==================\n");
        printf("Size     | Operation  |   Gbps   |   MB/s   | cyc/B  | CV%%\n");
        printf("---------|------------|----------|----------|--------|-------\n");
    }

    for (int i = 0; i < len_test_case; i++) {
        perf_result_t result = speed_test_ad_work(test_case[i]);
        print_result("MAC", test_case[i], &result);
        hiae_stats_destroy(result.stats);
    }
}

void
speed_test_aead(void)
{
    if (csv_output) {
        printf("\n# AEAD Performance\n");
        printf("Size,Operation,Gbps,MB/s,Cycles/Byte,CV%%\n");
    } else {
        printf("\n================== AEAD Performance =========================\n");
        printf("Size     | Operation  |   Gbps   |   MB/s   | cyc/B  | CV%%\n");
        printf("---------|------------|----------|----------|--------|-------\n");
    }

    for (int i = 0; i < len_test_case; i++) {
        perf_result_t enc_result = speed_test_encode_work(test_case[i], 1);
        perf_result_t dec_result = speed_test_decode_work(test_case[i], 1);

        print_result("encrypt", test_case[i], &enc_result);
        print_result("decrypt", test_case[i], &dec_result);

        hiae_stats_destroy(enc_result.stats);
        hiae_stats_destroy(dec_result.stats);

        if (!csv_output && i < len_test_case - 1) {
            printf("---------|------------|----------|----------|--------|-------\n");
        }
    }
}

void
speed_test_streaming(void)
{
    if (csv_output) {
        printf("\n# Streaming API Performance (1MB total)\n");
        printf("ChunkSize,Operation,Gbps,MB/s,Cycles/Byte,CV%%\n");
    } else {
        printf("\n================ Streaming API Performance ==================\n");
        printf("Testing streaming with 1MB total, various chunk sizes\n");
        printf("Chunk    | Operation  |   Gbps   |   MB/s   | cyc/B  | CV%%\n");
        printf("---------|------------|----------|----------|--------|-------\n");
    }

    const size_t total_size    = 1024 * 1024;
    size_t       chunk_sizes[] = { 16, 64, 256, 1024, 4096, 16384, 32768, 65536 };
    const int    num_chunks    = sizeof(chunk_sizes) / sizeof(chunk_sizes[0]);

    uint8_t key[HIAEX2_KEYBYTES];
    memset(key, 1, HIAEX2_KEYBYTES);
    uint8_t nonce[HIAEX2_NONCEBYTES];
    memset(nonce, 1, HIAEX2_NONCEBYTES);

    uint8_t *data = hiae_aligned_alloc(16, total_size);
    uint8_t *out  = hiae_aligned_alloc(16, total_size);
    if (!data || !out) {
        fprintf(stderr, "Failed to allocate streaming test memory\n");
        hiae_aligned_free(data);
        hiae_aligned_free(out);
        return;
    }
    memset(data, 0x1, total_size);

    for (int i = 0; i < num_chunks; i++) {
        size_t chunk_size = chunk_sizes[i];
        size_t chunks     = total_size / chunk_size;

        // Warmup phase - run for specified time
        hiae_timer_t warmup_timer;
        hiae_timer_start(&warmup_timer);
        size_t warmup_iterations = 0;

        do {
            HiAEx2_state_t state;
            HiAEx2_init(&state, key, nonce);

            for (size_t j = 0; j < chunks; j++) {
                HiAEx2_enc(&state, out + j * chunk_size, data + j * chunk_size, chunk_size);
            }

            uint8_t tag[HIAEX2_MACBYTES];
            HiAEx2_finalize(&state, 0, total_size, tag);
            warmup_iterations++;
            hiae_timer_stop(&warmup_timer);
        } while (hiae_timer_elapsed_seconds(&warmup_timer) < WARMUP_TIME);

        // Calculate iterations based on warmup performance
        double warmup_time                = hiae_timer_elapsed_seconds(&warmup_timer);
        size_t iterations_per_measurement = calculate_iterations(warmup_time, warmup_iterations);

        hiae_stats_t *stats = hiae_stats_create(NUM_MEASUREMENTS);
        if (!stats)
            continue;

        for (int run = 0; run < NUM_MEASUREMENTS; run++) {
            hiae_timer_t timer;
            hiae_timer_start(&timer);

            for (size_t iter = 0; iter < iterations_per_measurement; iter++) {
                HiAEx2_state_t state;
                HiAEx2_init(&state, key, nonce);

                for (size_t j = 0; j < chunks; j++) {
                    HiAEx2_enc(&state, out + j * chunk_size, data + j * chunk_size, chunk_size);
                }

                uint8_t tag[HIAEX2_MACBYTES];
                HiAEx2_finalize(&state, 0, total_size, tag);
            }

            hiae_timer_stop(&timer);

            double elapsed    = hiae_timer_elapsed_seconds(&timer);
            double throughput = ((double) iterations_per_measurement * total_size) / elapsed;
            hiae_stats_add(stats, throughput);
        }

        hiae_stats_compute(stats);

        perf_result_t result = { 0 };
        result.stats         = stats;
        result.mbps          = stats->median / (1024.0 * 1024.0);
        result.gbps          = (stats->median * 8.0) / 1e9;

        if (hiae_has_cycle_counter()) {
            double cpu_freq = hiae_get_cpu_frequency();
            if (cpu_freq > 0) {
                result.cycles_per_byte = cpu_freq / stats->median;
            }
        }

        print_result("stream", chunk_size, &result);
        hiae_stats_destroy(stats);
    }

    hiae_aligned_free(data);
    hiae_aligned_free(out);
}

static void
show_usage(const char *program_name)
{
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  --csv           Output results in CSV format\n");
    printf("  --no-streaming  Skip streaming API tests\n");
    printf("  --help, -h      Show this help message\n");
}

int
main(int argc, char *argv[])
{
    int streaming_test = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--csv") == 0) {
            csv_output = 1;
        } else if (strcmp(argv[i], "--no-streaming") == 0) {
            streaming_test = 0;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            show_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Error: Unknown option '%s'\n\n", argv[i]);
            show_usage(argv[0]);
            return 1;
        }
    }

    if (csv_output) {
        printf("# HiAEx2 Performance Test\n");
        printf("# Implementation: %s\n", HiAEx2_get_implementation_name());
    } else {
        printf("=============================================================\n");
        printf("                    HiAEx2 Performance Test                    \n");
        printf("=============================================================\n");
        printf("Implementation: %s\n", HiAEx2_get_implementation_name());
    }

    double       timer_resolution = 1.0;
    hiae_timer_t res_timer;
    for (int i = 0; i < 100; i++) {
        hiae_timer_start(&res_timer);
        hiae_timer_stop(&res_timer);
        double elapsed = hiae_timer_elapsed_seconds(&res_timer);
        if (elapsed > 0 && elapsed < timer_resolution) {
            timer_resolution = elapsed;
        }
    }
    if (csv_output) {
        printf("# Timer resolution: ~%.2f ns\n", timer_resolution * 1e9);

        if (hiae_has_cycle_counter()) {
            double cpu_freq = hiae_get_cpu_frequency();
            if (cpu_freq > 0) {
                printf("# CPU frequency: ~%.2f GHz\n", cpu_freq / 1e9);
            }
        }
    } else {
        printf("Timer resolution: ~%.2f ns\n", timer_resolution * 1e9);

        if (hiae_has_cycle_counter()) {
            double cpu_freq = hiae_get_cpu_frequency();
            if (cpu_freq > 0) {
                printf("CPU frequency: ~%.2f GHz\n", cpu_freq / 1e9);
            }
        }

        printf("\nNote: CV%% = Coefficient of Variation (std dev / mean * 100)\n");
        printf("      Lower CV%% indicates more consistent performance\n");
    }

    speed_test_encryption();
    speed_test_ad_only();
    speed_test_aead();

    if (streaming_test) {
        speed_test_streaming();
    }

    if (!csv_output) {
        printf("\n=============================================================\n");
    }

    return 0;
}
