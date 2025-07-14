#ifdef _WIN32
// Minimal getopt/getopt_long implementation for Windows
#    include <stdio.h>
#    include <string.h>

char *optarg = NULL;
int   optind = 1;
int   opterr = 1;
int   optopt = 0;

// Constants for option argument requirements
#    define no_argument       0
#    define required_argument 1
#    define optional_argument 2

// Structure for long options
struct option {
    const char *name;
    int         has_arg;
    int        *flag;
    int         val;
};

int
getopt(int argc, char *const argv[], const char *optstring)
{
    static int sp = 1;
    int        c;
    char      *cp;

    if (sp == 1) {
        if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0')
            return -1;
        else if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        }
    }
    optopt = c = argv[optind][sp];
    if (c == ':' || (cp = strchr(optstring, c)) == NULL) {
        if (opterr)
            fprintf(stderr, "%s: illegal option -- %c\n", argv[0], c);
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return '?';
    }
    if (*++cp == ':') {
        if (argv[optind][sp + 1] != '\0')
            optarg = &argv[optind++][sp + 1];
        else if (++optind >= argc) {
            if (opterr)
                fprintf(stderr, "%s: option requires an argument -- %c\n", argv[0], c);
            sp = 1;
            return '?';
        } else
            optarg = argv[optind++];
        sp = 1;
    } else {
        if (argv[optind][++sp] == '\0') {
            sp = 1;
            optind++;
        }
        optarg = NULL;
    }
    return c;
}

int
getopt_long(int argc, char *const argv[], const char *optstring, const struct option *longopts,
            int *longindex)
{
    static int sp = 1;
    int        c;
    char      *cp;

    if (sp == 1) {
        if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0')
            return -1;
        else if (strcmp(argv[optind], "--") == 0) {
            optind++;
            return -1;
        }
        // Check for long option
        else if (argv[optind][0] == '-' && argv[optind][1] == '-') {
            char *name = argv[optind] + 2;
            char *eq   = strchr(name, '=');
            int   len  = eq ? (int) (eq - name) : (int) strlen(name);

            for (int i = 0; longopts[i].name != NULL; i++) {
                if (strncmp(name, longopts[i].name, len) == 0 && strlen(longopts[i].name) == len) {
                    if (longindex)
                        *longindex = i;

                    optind++;
                    if (longopts[i].has_arg == required_argument) {
                        if (eq) {
                            optarg = eq + 1;
                        } else if (optind < argc) {
                            optarg = argv[optind++];
                        } else {
                            if (opterr)
                                fprintf(stderr, "%s: option '--%s' requires an argument\n", argv[0],
                                        longopts[i].name);
                            return '?';
                        }
                    } else if (longopts[i].has_arg == optional_argument) {
                        optarg = eq ? eq + 1 : NULL;
                    } else {
                        optarg = NULL;
                    }

                    if (longopts[i].flag) {
                        *longopts[i].flag = longopts[i].val;
                        return 0;
                    }
                    return longopts[i].val;
                }
            }
            if (opterr)
                fprintf(stderr, "%s: unrecognized option '--%.*s'\n", argv[0], len, name);
            return '?';
        }
    }

    // Fall back to regular getopt for short options
    optopt = c = argv[optind][sp];
    if (c == ':' || (cp = strchr(optstring, c)) == NULL) {
        if (opterr)
            fprintf(stderr, "%s: illegal option -- %c\n", argv[0], c);
        if (argv[optind][++sp] == '\0') {
            optind++;
            sp = 1;
        }
        return '?';
    }
    if (*++cp == ':') {
        if (argv[optind][sp + 1] != '\0')
            optarg = &argv[optind++][sp + 1];
        else if (++optind >= argc) {
            if (opterr)
                fprintf(stderr, "%s: option requires an argument -- %c\n", argv[0], c);
            sp = 1;
            return '?';
        } else
            optarg = argv[optind++];
        sp = 1;
    } else {
        if (argv[optind][++sp] == '\0') {
            sp = 1;
            optind++;
        }
        optarg = NULL;
    }
    return c;
}
#endif