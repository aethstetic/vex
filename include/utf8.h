#ifndef VEX_UTF8_H
#define VEX_UTF8_H

int32_t utf8_decode(const char **s);

int utf8_encode(char *buf, int32_t cp);

size_t utf8_strlen(const char *s, size_t byte_len);

size_t utf8_offset(const char *s, size_t byte_len, size_t n);

int utf8_charwidth(int32_t cp);

size_t utf8_strwidth(const char *s, size_t byte_len);

static inline bool utf8_is_cont(char c) {
    return (c & 0xC0) == 0x80;
}

#endif
