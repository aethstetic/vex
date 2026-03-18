#ifndef VEX_HELP_PARSE_H
#define VEX_HELP_PARSE_H

#include <stddef.h>

typedef struct {
    char *flag;
    char *description;
} HelpFlag;

typedef struct {
    HelpFlag *flags;
    size_t count;
    size_t cap;
} HelpParseResult;

HelpParseResult *help_parse_flags(const char *help_text);
void help_parse_free(HelpParseResult *result);

#endif
