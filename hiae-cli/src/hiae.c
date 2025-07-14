#include "../include/HiAE.h"
#include "file_ops.h"
#include "key_utils.h"
#include "platform.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define VERSION "1.0.0"

typedef enum {
    CMD_NONE,
    CMD_ENCRYPT,
    CMD_DECRYPT,
    CMD_KEYGEN,
    CMD_MAC,
    CMD_HELP,
    CMD_VERSION
} command_t;

typedef struct {
    command_t command;
    char     *input_file;
    char     *output_file;
    char     *key_hex;
    char     *key_file;
    char     *nonce_hex;
    char     *nonce_file;
    char     *ad_string;
    char     *ad_file;
    char     *tag_file;
    int       show_progress;
    int       verbose;
    int       quiet;
    int       embed_metadata;
} cli_options_t;

static void
print_usage(const char *program_name)
{
    printf("Usage: %s <command> [options]\n\n", program_name);
    printf("Commands:\n");
    printf("  encrypt    Encrypt a file\n");
    printf("  decrypt    Decrypt a file\n");
    printf("  keygen     Generate a random key file\n");
    printf("  mac        Compute MAC on a file\n");
    printf("  help       Show this help message\n");
    printf("  version    Show version information\n\n");
    printf("Options:\n");
    printf("  -i, --input FILE       Input file path (required)\n");
    printf("  -o, --output FILE      Output file path (required)\n");
    printf("  -k, --key HEX          256-bit key as hex string (64 hex chars)\n");
    printf("  -K, --keyfile FILE     Read key from file (binary or hex)\n");
    printf("  -n, --nonce HEX        128-bit nonce as hex string (32 hex chars)\n");
    printf("                         Use \"random\" to generate randomly\n");
    printf("  -nf, --noncefile FILE  Read nonce from file\n");
    printf("  -a, --ad STRING        Additional authenticated data\n");
    printf("  -af, --adfile FILE     Read additional data from file\n");
    printf("  -t, --tagfile FILE     Tag file path (default: <output>.tag)\n");
    printf("  -e, --embed            Embed metadata in encrypted file\n");
    printf("  -p, --progress         Show progress bar for large files\n");
    printf("  -v, --verbose          Verbose output\n");
    printf("  -q, --quiet            Suppress non-error output\n");
    printf("  -h, --help             Show this help message\n\n");
    printf("Examples:\n");
    printf("  # Basic encryption\n");
    printf("  %s encrypt -i document.pdf -o document.enc -k 0123...def -n abcd...ef\n\n",
           program_name);
    printf("  # Decrypt with key file\n");
    printf("  %s decrypt -i document.enc -o document.pdf -kf secret.key -nf nonce.bin\n\n",
           program_name);
    printf("  # Generate and use random key\n");
    printf("  %s keygen -o mykey.key\n", program_name);
    printf("  %s encrypt -i data.csv -o data.enc -kf mykey.key -n random\n\n", program_name);
    printf("  # Compute MAC\n");
    printf("  %s mac -i document.pdf -k 0123...def\n", program_name);
}

static void
print_version(void)
{
    printf("HiAE CLI version %s\n", VERSION);
    printf("Using HiAE implementation: %s\n", HiAE_get_implementation_name());
}

static command_t
parse_command(const char *cmd)
{
    if (strcmp(cmd, "encrypt") == 0)
        return CMD_ENCRYPT;
    if (strcmp(cmd, "decrypt") == 0)
        return CMD_DECRYPT;
    if (strcmp(cmd, "keygen") == 0)
        return CMD_KEYGEN;
    if (strcmp(cmd, "mac") == 0)
        return CMD_MAC;
    if (strcmp(cmd, "help") == 0)
        return CMD_HELP;
    if (strcmp(cmd, "version") == 0)
        return CMD_VERSION;
    return CMD_NONE;
}

static int
parse_options(int argc, char *argv[], cli_options_t *opts)
{
    static struct option long_options[] = { { "input", required_argument, 0, 'i' },
                                            { "output", required_argument, 0, 'o' },
                                            { "key", required_argument, 0, 'k' },
                                            { "keyfile", required_argument, 0, 'K' },
                                            { "nonce", required_argument, 0, 'n' },
                                            { "noncefile", required_argument, 0, 0 },
                                            { "ad", required_argument, 0, 'a' },
                                            { "adfile", required_argument, 0, 0 },
                                            { "tagfile", required_argument, 0, 't' },
                                            { "embed", no_argument, 0, 'e' },
                                            { "progress", no_argument, 0, 'p' },
                                            { "verbose", no_argument, 0, 'v' },
                                            { "quiet", no_argument, 0, 'q' },
                                            { "help", no_argument, 0, 'h' },
                                            { 0, 0, 0, 0 } };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "i:o:k:K:n:a:t:epvqh", long_options, &option_index)) !=
           -1) {
        switch (opt) {
        case 'i':
            opts->input_file = optarg;
            break;
        case 'o':
            opts->output_file = optarg;
            break;
        case 'k':
            opts->key_hex = optarg;
            break;
        case 'K':
            opts->key_file = optarg;
            break;
        case 'n':
            opts->nonce_hex = optarg;
            break;
        case 'a':
            opts->ad_string = optarg;
            break;
        case 't':
            opts->tag_file = optarg;
            break;
        case 'e':
            opts->embed_metadata = 1;
            break;
        case 'p':
            opts->show_progress = 1;
            break;
        case 'v':
            opts->verbose = 1;
            break;
        case 'q':
            opts->quiet = 1;
            break;
        case 'h':
            return 1;
        case 0:
            // Long option handling
            if (strcmp(long_options[option_index].name, "noncefile") == 0) {
                opts->nonce_file = optarg;
            } else if (strcmp(long_options[option_index].name, "adfile") == 0) {
                opts->ad_file = optarg;
            }
            break;
        default:
            return -1;
        }
    }

    return 0;
}

static int
load_key_material(cli_options_t *opts, hiae_key_material_t *km)
{
    memset(km, 0, sizeof(*km));

    // Load key
    if (opts->key_hex) {
        int len = parse_hex_string(opts->key_hex, km->key, HIAE_KEY_SIZE);
        if (len != HIAE_KEY_SIZE) {
            fprintf(stderr, "Error: Key must be exactly %d bytes (got %d)\n", HIAE_KEY_SIZE, len);
            return -1;
        }
        km->key_loaded = 1;
    } else if (opts->key_file) {
        if (load_key_file(opts->key_file, km) != 0) {
            fprintf(stderr, "Error: Failed to load key from file: %s\n", opts->key_file);
            return -1;
        }
    } else {
        fprintf(stderr, "Error: No key provided (use -k or -kf)\n");
        return -1;
    }

    // Load or generate nonce
    if (opts->nonce_hex) {
        if (strcmp(opts->nonce_hex, "random") == 0) {
            if (generate_random_bytes(km->nonce, HIAE_NONCE_SIZE) != 0) {
                fprintf(stderr, "Error: Failed to generate random nonce\n");
                return -1;
            }
            km->nonce_loaded = 1;

            // Save nonce to file for later use
            if (opts->output_file && !opts->embed_metadata) {
                char nonce_filename[1024];
                snprintf(nonce_filename, sizeof(nonce_filename), "%s.nonce", opts->output_file);
                save_nonce_file(nonce_filename, km->nonce);
                if (!opts->quiet) {
                    printf("Nonce saved to: %s\n", nonce_filename);
                }
            }
        } else {
            int len = parse_hex_string(opts->nonce_hex, km->nonce, HIAE_NONCE_SIZE);
            if (len != HIAE_NONCE_SIZE) {
                fprintf(stderr, "Error: Nonce must be exactly %d bytes (got %d)\n", HIAE_NONCE_SIZE,
                        len);
                return -1;
            }
            km->nonce_loaded = 1;
        }
    } else if (opts->nonce_file) {
        if (load_nonce_file(opts->nonce_file, km->nonce) != 0) {
            fprintf(stderr, "Error: Failed to load nonce from file: %s\n", opts->nonce_file);
            return -1;
        }
        km->nonce_loaded = 1;
    }

    return 0;
}

static int
load_additional_data(cli_options_t *opts, uint8_t **ad, size_t *ad_len)
{
    *ad     = NULL;
    *ad_len = 0;

    if (opts->ad_string) {
        *ad_len = strlen(opts->ad_string);
        *ad     = malloc(*ad_len);
        if (!*ad)
            return -1;
        memcpy(*ad, opts->ad_string, *ad_len);
    } else if (opts->ad_file) {
        FILE *fp = fopen(opts->ad_file, "rb");
        if (!fp) {
            fprintf(stderr, "Error: Failed to open AD file: %s\n", opts->ad_file);
            return -1;
        }

        fseek(fp, 0, SEEK_END);
        *ad_len = ftell(fp);
        rewind(fp);

        *ad = malloc(*ad_len);
        if (!*ad) {
            fclose(fp);
            return -1;
        }

        if (fread(*ad, 1, *ad_len, fp) != *ad_len) {
            free(*ad);
            fclose(fp);
            return -1;
        }
        fclose(fp);
    }

    return 0;
}

static int
cmd_encrypt(cli_options_t *opts)
{
    hiae_key_material_t km;
    uint8_t            *ad     = NULL;
    size_t              ad_len = 0;
    int                 ret    = -1;

    // Validate options
    if (!opts->input_file || !opts->output_file) {
        fprintf(stderr, "Error: Input and output files are required\n");
        return -1;
    }

    // Load key material
    if (load_key_material(opts, &km) != 0) {
        return -1;
    }

    if (!km.nonce_loaded) {
        fprintf(stderr, "Error: Nonce is required for encryption (use -n or -nf)\n");
        return -1;
    }

    // Load additional data
    if (load_additional_data(opts, &ad, &ad_len) != 0) {
        return -1;
    }

    // Setup progress
    progress_info_t progress = { 0 };
    if (opts->show_progress && is_terminal(stdout)) {
        progress.callback = default_progress_callback;
    }

    // Perform encryption
    if (!opts->quiet) {
        printf("Using HiAE implementation: %s\n", HiAE_get_implementation_name());
        if (opts->verbose) {
            printf("Encrypting: %s -> %s\n", opts->input_file, opts->output_file);
            print_hex("Key", km.key, HIAE_KEY_SIZE);
            print_hex("Nonce", km.nonce, HIAE_NONCE_SIZE);
            if (ad_len > 0) {
                printf("Additional data: %zu bytes\n", ad_len);
            }
        } else {
            printf("Encrypting: %s\n", opts->input_file);
        }
    }

    hiae_cli_error_t err = encrypt_file(opts->input_file, opts->output_file, &km, ad, ad_len,
                                        &progress, opts->embed_metadata);

    if (err == HIAE_CLI_SUCCESS) {
        if (!opts->quiet) {
            printf("Encrypted file saved to: %s\n", opts->output_file);
            if (!opts->embed_metadata) {
                printf("Tag saved to: %s.tag\n", opts->output_file);
            }
        }
        ret = 0;
    } else {
        fprintf(stderr, "Error: %s\n", get_error_message(err));
    }

    // Clean up
    secure_wipe(&km, sizeof(km));
    if (ad) {
        secure_wipe(ad, ad_len);
        free(ad);
    }

    return ret;
}

static int
cmd_decrypt(cli_options_t *opts)
{
    hiae_key_material_t km;
    uint8_t            *ad     = NULL;
    size_t              ad_len = 0;
    int                 ret    = -1;

    // Validate options
    if (!opts->input_file || !opts->output_file) {
        fprintf(stderr, "Error: Input and output files are required\n");
        return -1;
    }

    // Load key material
    if (load_key_material(opts, &km) != 0) {
        return -1;
    }

    // Load additional data
    if (load_additional_data(opts, &ad, &ad_len) != 0) {
        return -1;
    }

    // Setup progress
    progress_info_t progress = { 0 };
    if (opts->show_progress && is_terminal(stdout)) {
        progress.callback = default_progress_callback;
    }

    // Perform decryption
    if (!opts->quiet) {
        printf("Using HiAE implementation: %s\n", HiAE_get_implementation_name());
        if (opts->verbose) {
            printf("Decrypting: %s -> %s\n", opts->input_file, opts->output_file);
            print_hex("Key", km.key, HIAE_KEY_SIZE);
            if (km.nonce_loaded) {
                print_hex("Nonce", km.nonce, HIAE_NONCE_SIZE);
            }
            if (ad_len > 0) {
                printf("Additional data: %zu bytes\n", ad_len);
            }
        } else {
            printf("Decrypting: %s\n", opts->input_file);
        }
    }

    hiae_cli_error_t err = decrypt_file(opts->input_file, opts->output_file, &km, ad, ad_len,
                                        &progress, opts->embed_metadata);

    if (err == HIAE_CLI_SUCCESS) {
        if (!opts->quiet) {
            printf("Authentication successful\n");
            printf("Decrypted file saved to: %s\n", opts->output_file);
        }
        ret = 0;
    } else {
        fprintf(stderr, "Error: %s\n", get_error_message(err));
    }

    // Clean up
    secure_wipe(&km, sizeof(km));
    if (ad) {
        secure_wipe(ad, ad_len);
        free(ad);
    }

    return ret;
}

static int
cmd_keygen(cli_options_t *opts)
{
    if (!opts->output_file) {
        fprintf(stderr, "Error: Output file is required for keygen\n");
        return -1;
    }

    hiae_key_material_t km;
    memset(&km, 0, sizeof(km));

    // Generate random key
    if (generate_random_bytes(km.key, HIAE_KEY_SIZE) != 0) {
        fprintf(stderr, "Error: Failed to generate random key\n");
        return -1;
    }
    km.key_loaded = 1;

    // Optionally generate nonce too
    if (opts->nonce_hex && strcmp(opts->nonce_hex, "random") == 0) {
        if (generate_random_bytes(km.nonce, HIAE_NONCE_SIZE) != 0) {
            fprintf(stderr, "Error: Failed to generate random nonce\n");
            secure_wipe(&km, sizeof(km));
            return -1;
        }
        km.nonce_loaded = 1;
    }

    // Save key file
    if (save_key_file(opts->output_file, &km) != 0) {
        fprintf(stderr, "Error: Failed to save key file\n");
        secure_wipe(&km, sizeof(km));
        return -1;
    }

    if (!opts->quiet) {
        printf("Generated key saved to: %s\n", opts->output_file);
        if (opts->verbose) {
            print_hex("Key", km.key, HIAE_KEY_SIZE);
            if (km.nonce_loaded) {
                print_hex("Nonce", km.nonce, HIAE_NONCE_SIZE);
            }
        }
        printf("Warning: Keep this file secure and backed up!\n");
    }

    secure_wipe(&km, sizeof(km));
    return 0;
}

static int
cmd_mac(cli_options_t *opts)
{
    hiae_key_material_t km;
    uint8_t             tag[HIAE_MACBYTES];
    int                 ret = -1;

    // Validate options
    if (!opts->input_file) {
        fprintf(stderr, "Error: Input file is required\n");
        return -1;
    }

    // Load key material
    if (load_key_material(opts, &km) != 0) {
        return -1;
    }

    // If no nonce provided, use all-zero nonce
    if (!km.nonce_loaded) {
        memset(km.nonce, 0, HIAE_NONCE_SIZE);
        km.nonce_loaded = 1;
    }

    // Open input file
    FILE *fp = fopen(opts->input_file, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Failed to open input file: %s\n", opts->input_file);
        secure_wipe(&km, sizeof(km));
        return -1;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    rewind(fp);

    // Read entire file (for simplicity - could be done streaming for large files)
    uint8_t *data = malloc(file_size);
    if (!data) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        fclose(fp);
        secure_wipe(&km, sizeof(km));
        return -1;
    }

    if (fread(data, 1, file_size, fp) != file_size) {
        fprintf(stderr, "Error: Failed to read file\n");
        free(data);
        fclose(fp);
        secure_wipe(&km, sizeof(km));
        return -1;
    }
    fclose(fp);

    // Compute MAC
    if (!opts->quiet) {
        printf("Using HiAE implementation: %s\n", HiAE_get_implementation_name());
        if (opts->verbose) {
            printf("Computing MAC for: %s (%zu bytes)\n", opts->input_file, file_size);
            print_hex("Key", km.key, HIAE_KEY_SIZE);
            print_hex("Nonce", km.nonce, HIAE_NONCE_SIZE);
        }
    }

    if (HiAE_mac(km.key, km.nonce, data, file_size, tag) != 0) {
        fprintf(stderr, "Error: Failed to compute MAC\n");
        free(data);
        secure_wipe(&km, sizeof(km));
        return -1;
    }

    // Print MAC as hex
    for (int i = 0; i < HIAE_MACBYTES; i++) {
        printf("%02x", tag[i]);
    }
    printf("\n");

    ret = 0;

    // Clean up
    free(data);
    secure_wipe(&km, sizeof(km));
    secure_wipe(tag, sizeof(tag));

    return ret;
}

int
main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    // Parse command
    command_t cmd = parse_command(argv[1]);
    if (cmd == CMD_NONE) {
        fprintf(stderr, "Error: Unknown command '%s'\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    if (cmd == CMD_HELP) {
        print_usage(argv[0]);
        return 0;
    }

    if (cmd == CMD_VERSION) {
        print_version();
        return 0;
    }

    // Parse options
    cli_options_t opts = { 0 };
    opts.command       = cmd;

    // Adjust argv for getopt
    argc--;
    argv++;
    optind = 1;

    int parse_result = parse_options(argc, argv, &opts);
    if (parse_result < 0) {
        fprintf(stderr, "Error: Invalid options\n");
        return 1;
    } else if (parse_result > 0) {
        print_usage(argv[0]);
        return 0;
    }

    // Execute command
    switch (cmd) {
    case CMD_ENCRYPT:
        return cmd_encrypt(&opts);
    case CMD_DECRYPT:
        return cmd_decrypt(&opts);
    case CMD_KEYGEN:
        return cmd_keygen(&opts);
    case CMD_MAC:
        return cmd_mac(&opts);
    default:
        fprintf(stderr, "Error: Command not implemented\n");
        return 1;
    }
}