#include "vex.h"
#include <stdarg.h>

VexError *vex_error_new(const char *msg) {
    VexError *e = calloc(1, sizeof(VexError));
    e->message = strdup(msg);
    return e;
}

VexError *vex_error_at(const char *msg, const char *source, uint32_t line,
                       uint16_t col, uint16_t span) {
    VexError *e = calloc(1, sizeof(VexError));
    e->message = strdup(msg);
    e->source_line = source ? strdup(source) : NULL;
    e->line = line;
    e->col = col;
    e->span_len = span;
    return e;
}

void vex_error_set_help(VexError *e, const char *help) {
    free(e->help);
    e->help = strdup(help);
}

void vex_error_set_suggestion(VexError *e, const char *suggestion) {
    free(e->did_you_mean);
    e->did_you_mean = strdup(suggestion);
}

void vex_error_print(const VexError *e, FILE *out) {
    fprintf(out, "\033[1;31mError\033[0m: %s\n", e->message);

    if (e->source_line) {
        fprintf(out, "\n");
        fprintf(out, "  %u | %s\n", e->line, e->source_line);

        fprintf(out, "  ");

        uint32_t n = e->line;
        do { fprintf(out, " "); n /= 10; } while (n > 0);
        fprintf(out, "   ");

        for (uint16_t i = 0; i < e->col; i++) fprintf(out, " ");
        fprintf(out, "\033[1;31m");
        for (uint16_t i = 0; i < (e->span_len ? e->span_len : 1); i++)
            fprintf(out, "^");
        fprintf(out, "\033[0m\n");
    }

    if (e->did_you_mean) {
        fprintf(out, "\n  Did you mean: \033[1;32m%s\033[0m\n", e->did_you_mean);
    }

    if (e->help) {
        fprintf(out, "\n  \033[1;36mHelp\033[0m: %s\n", e->help);
    }

    fprintf(out, "\n");
}

void vex_error_free(VexError *e) {
    if (!e) return;
    free(e->message);
    free(e->source_line);
    free(e->help);
    free(e->did_you_mean);
    free(e);
}

void vex_err(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "\033[1;31mError\033[0m: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

/* Damerau-Levenshtein: like Levenshtein but transposition counts as 1 edit */
size_t vex_levenshtein(const char *a, const char *b) {
    size_t alen = strlen(a);
    size_t blen = strlen(b);

    if (alen == 0) return blen;
    if (blen == 0) return alen;

    if (alen > 128 || blen > 128) return alen > blen ? alen : blen;

    size_t *pprev = malloc((blen + 1) * sizeof(size_t));
    size_t *prev = malloc((blen + 1) * sizeof(size_t));
    size_t *curr = malloc((blen + 1) * sizeof(size_t));

    for (size_t j = 0; j <= blen; j++) pprev[j] = j;
    prev[0] = 1;
    for (size_t j = 1; j <= blen; j++) {
        size_t cost = (a[0] == b[j-1]) ? 0 : 1;
        size_t del = pprev[j] + 1;
        size_t ins = prev[j-1] + 1;
        size_t sub = pprev[j-1] + cost;
        prev[j] = del < ins ? del : ins;
        if (sub < prev[j]) prev[j] = sub;
    }

    for (size_t i = 2; i <= alen; i++) {
        curr[0] = i;
        for (size_t j = 1; j <= blen; j++) {
            size_t cost = (a[i-1] == b[j-1]) ? 0 : 1;
            size_t del = prev[j] + 1;
            size_t ins = curr[j-1] + 1;
            size_t sub = prev[j-1] + cost;
            curr[j] = del < ins ? del : ins;
            if (sub < curr[j]) curr[j] = sub;

            /* Transposition: swap of adjacent characters */
            if (i > 1 && j > 1 &&
                a[i-1] == b[j-2] && a[i-2] == b[j-1]) {
                size_t trans = pprev[j-2] + cost;
                if (trans < curr[j]) curr[j] = trans;
            }
        }
        size_t *tmp = pprev;
        pprev = prev;
        prev = curr;
        curr = tmp;
    }

    size_t result = prev[blen];
    free(pprev);
    free(prev);
    free(curr);
    return result;
}

/* Count how many chars from target appear in candidate (order-independent) */
static size_t char_overlap(const char *target, const char *candidate) {
    size_t count = 0;
    size_t tlen = strlen(target);
    size_t clen = strlen(candidate);
    bool used[128] = {false};
    for (size_t i = 0; i < tlen; i++) {
        for (size_t j = 0; j < clen && j < 128; j++) {
            if (!used[j] && target[i] == candidate[j]) {
                count++;
                used[j] = true;
                break;
            }
        }
    }
    return count;
}

const char *vex_closest_match(const char *target, const char **candidates,
                               size_t count, size_t max_distance) {
    const char *best = NULL;
    size_t best_dist = max_distance + 1;
    size_t best_overlap = 0;

    for (size_t i = 0; i < count; i++) {
        size_t d = vex_levenshtein(target, candidates[i]);
        if (d < best_dist) {
            best_dist = d;
            best = candidates[i];
            best_overlap = char_overlap(target, candidates[i]);
        } else if (d == best_dist) {
            /* Tiebreaker: prefer candidate with more character overlap */
            size_t overlap = char_overlap(target, candidates[i]);
            if (overlap > best_overlap) {
                best = candidates[i];
                best_overlap = overlap;
            }
        }
    }

    return best;
}
