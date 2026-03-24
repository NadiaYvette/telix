/* POSIX getopt and getopt_long for Telix. */
#include <getopt.h>
#include <string.h>
#include <telix/types.h>

char *optarg = NULL;
int   optind = 1;
int   opterr = 1;
int   optopt = 0;

/* Internal state for scanning within a grouped short-option argument. */
static int _optpos = 0;

int getopt(int argc, char *const argv[], const char *optstring) {
    if (optind >= argc || !argv[optind])
        return -1;

    const char *arg = argv[optind];

    /* Not an option. */
    if (arg[0] != '-' || arg[1] == '\0')
        return -1;

    /* "--" terminates option parsing. */
    if (arg[1] == '-' && arg[2] == '\0') {
        optind++;
        return -1;
    }

    int pos = _optpos ? _optpos : 1;
    char c = arg[pos];
    _optpos = 0;

    const char *p = strchr(optstring, c);
    if (!p || c == ':') {
        optopt = c;
        /* Advance past this arg if we've consumed all chars. */
        if (!arg[pos + 1])
            optind++;
        else
            _optpos = pos + 1;
        return '?';
    }

    if (p[1] == ':') {
        /* Option requires an argument. */
        if (arg[pos + 1]) {
            /* Argument is the rest of this argv element. */
            optarg = (char *)&arg[pos + 1];
            optind++;
        } else if (p[2] == ':') {
            /* Optional argument (GNU extension "::"): no arg available. */
            optarg = NULL;
            optind++;
        } else {
            /* Argument is the next argv element. */
            optind++;
            if (optind >= argc) {
                optopt = c;
                return '?';
            }
            optarg = argv[optind];
            optind++;
        }
    } else {
        /* No argument. */
        optarg = NULL;
        if (!arg[pos + 1])
            optind++;
        else
            _optpos = pos + 1;
    }

    return c;
}

int getopt_long(int argc, char *const argv[], const char *optstring,
                const struct option *longopts, int *longindex) {
    if (optind >= argc || !argv[optind])
        return -1;

    const char *arg = argv[optind];

    /* Check for long option (starts with "--"). */
    if (arg[0] == '-' && arg[1] == '-' && arg[2] != '\0') {
        const char *name = arg + 2;

        /* Find '=' if present. */
        const char *eq = strchr(name, '=');
        int namelen = eq ? (int)(eq - name) : (int)strlen(name);

        for (int i = 0; longopts && longopts[i].name; i++) {
            if (strncmp(longopts[i].name, name, namelen) != 0)
                continue;
            if (longopts[i].name[namelen] != '\0')
                continue;

            /* Exact match found. */
            if (longindex)
                *longindex = i;
            optind++;

            if (longopts[i].has_arg == required_argument) {
                if (eq) {
                    optarg = (char *)(eq + 1);
                } else if (optind < argc) {
                    optarg = argv[optind];
                    optind++;
                } else {
                    optopt = longopts[i].val;
                    return '?';
                }
            } else if (longopts[i].has_arg == optional_argument) {
                optarg = eq ? (char *)(eq + 1) : NULL;
            } else {
                optarg = NULL;
            }

            if (longopts[i].flag) {
                *longopts[i].flag = longopts[i].val;
                return 0;
            }
            return longopts[i].val;
        }

        /* Unknown long option. */
        optopt = 0;
        optind++;
        return '?';
    }

    /* Fall through to short option parsing. */
    return getopt(argc, argv, optstring);
}
