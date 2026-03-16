#ifndef VEX_ERROR_H
#define VEX_ERROR_H

typedef struct {
    char *message;
    char *source_line;
    uint32_t line;
    uint16_t col;
    uint16_t span_len;
    char *help;
    char *did_you_mean;
} VexError;

VexError *vex_error_new(const char *msg);
VexError *vex_error_at(const char *msg, const char *source, uint32_t line,
                       uint16_t col, uint16_t span);
void      vex_error_set_help(VexError *e, const char *help);
void      vex_error_set_suggestion(VexError *e, const char *suggestion);
void      vex_error_print(const VexError *e, FILE *out);
void      vex_error_free(VexError *e);

void      vex_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

size_t    vex_levenshtein(const char *a, const char *b);

const char *vex_closest_match(const char *target, const char **candidates,
                               size_t count, size_t max_distance);

#endif
