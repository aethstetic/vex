#include "vex.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static void result_push(HelpParseResult *r, const char *flag, size_t flen,
                         const char *desc, size_t dlen) {
    for (size_t i = 0; i < r->count; i++) {
        if (strlen(r->flags[i].flag) == flen &&
            memcmp(r->flags[i].flag, flag, flen) == 0)
            return;
    }

    if (r->count >= r->cap) {
        r->cap = r->cap ? r->cap * 2 : 32;
        r->flags = realloc(r->flags, r->cap * sizeof(HelpFlag));
    }

    r->flags[r->count].flag = strndup(flag, flen);
    r->flags[r->count].description = dlen > 0 ? strndup(desc, dlen) : NULL;
    r->count++;
}

static void parse_line(HelpParseResult *r, const char *line, size_t len) {
    const char *p = line;
    const char *end = line + len;

    if (len == 0 || (*p != ' ' && *p != '\t')) return;

    while (p < end && (*p == ' ' || *p == '\t')) p++;
    if (p >= end || *p != '-') return;

    const char *desc = NULL;
    size_t dlen = 0;
    {
        const char *d = p;
        while (d < end) {
            if (*d == '\t' || (d + 1 < end && d[0] == ' ' && d[1] == ' ')) {
                while (d < end && (*d == ' ' || *d == '\t')) d++;
                if (d < end && *d != '-') {
                    desc = d;
                    const char *de = end;
                    while (de > desc && (de[-1] == ' ' || de[-1] == '\n' || de[-1] == '\r'))
                        de--;
                    dlen = (size_t)(de - desc);
                }
                break;
            }
            d++;
        }
    }

    while (p < end && *p != '\0') {
        if (*p == '-') {
            const char *fstart = p;

            if (p + 1 < end && p[1] == '-') {
                p += 2;
                while (p < end && (isalnum((unsigned char)*p) || *p == '-' || *p == '_'))
                    p++;
                size_t flen = (size_t)(p - fstart);
                if (flen > 2)
                    result_push(r, fstart, flen, desc, dlen);
                if (p < end && (*p == '=' || *p == '[')) {
                    while (p < end && *p != ' ' && *p != ',' && *p != '\t') p++;
                }
            } else {
                p++;
                if (p < end && isalnum((unsigned char)*p)) {
                    size_t flen = 2;
                    result_push(r, fstart, flen, desc, dlen);
                    p++;
                    if (p < end && *p == ' ' && p + 1 < end && isupper((unsigned char)p[1])) {
                        while (p < end && *p != ',' && *p != ' ') p++;
                    }
                } else {
                    p++;
                }
            }

            while (p < end && (*p == ',' || *p == ' ')) p++;

            if (p < end && *p != '-') break;
        } else {
            break;
        }
    }
}

HelpParseResult *help_parse_flags(const char *help_text) {
    HelpParseResult *r = calloc(1, sizeof(HelpParseResult));
    if (!help_text || !help_text[0]) return r;

    const char *p = help_text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t line_len = nl ? (size_t)(nl - p) : strlen(p);
        parse_line(r, p, line_len);
        if (!nl) break;
        p = nl + 1;
    }

    return r;
}

void help_parse_free(HelpParseResult *r) {
    if (!r) return;
    for (size_t i = 0; i < r->count; i++) {
        free(r->flags[i].flag);
        free(r->flags[i].description);
    }
    free(r->flags);
    free(r);
}
