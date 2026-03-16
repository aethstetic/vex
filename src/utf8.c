#include "vex.h"

int32_t utf8_decode(const char **s) {
    const uint8_t *p = (const uint8_t *)*s;
    int32_t cp;
    int len;

    if (*p < 0x80) {
        cp = *p;
        len = 1;
    } else if ((*p & 0xE0) == 0xC0) {
        cp = *p & 0x1F;
        len = 2;
    } else if ((*p & 0xF0) == 0xE0) {
        cp = *p & 0x0F;
        len = 3;
    } else if ((*p & 0xF8) == 0xF0) {
        cp = *p & 0x07;
        len = 4;
    } else {
        (*s)++;
        return -1;
    }

    for (int i = 1; i < len; i++) {
        if ((p[i] & 0xC0) != 0x80) {
            (*s)++;
            return -1;
        }
        cp = (cp << 6) | (p[i] & 0x3F);
    }

    *s += len;
    return cp;
}

int utf8_encode(char *buf, int32_t cp) {
    if (cp < 0x80) {
        buf[0] = (char)cp;
        return 1;
    } else if (cp < 0x800) {
        buf[0] = (char)(0xC0 | (cp >> 6));
        buf[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp < 0x10000) {
        buf[0] = (char)(0xE0 | (cp >> 12));
        buf[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        buf[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    } else if (cp < 0x110000) {
        buf[0] = (char)(0xF0 | (cp >> 18));
        buf[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        buf[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        buf[3] = (char)(0x80 | (cp & 0x3F));
        return 4;
    }
    return 0;
}

size_t utf8_strlen(const char *s, size_t byte_len) {
    size_t count = 0;
    const char *end = s + byte_len;
    while (s < end) {
        if (!utf8_is_cont(*s)) count++;
        s++;
    }
    return count;
}

size_t utf8_offset(const char *s, size_t byte_len, size_t n) {
    const char *start = s;
    const char *end = s + byte_len;
    size_t count = 0;
    while (s < end && count < n) {
        s++;
        while (s < end && utf8_is_cont(*s)) s++;
        count++;
    }
    return (size_t)(s - start);
}

int utf8_charwidth(int32_t cp) {
    if (cp == 0) return 0;

    if ((cp >= 0x0300 && cp <= 0x036F) ||
        (cp >= 0x1AB0 && cp <= 0x1AFF) ||
        (cp >= 0x1DC0 && cp <= 0x1DFF) ||
        (cp >= 0x20D0 && cp <= 0x20FF) ||
        (cp >= 0xFE00 && cp <= 0xFE0F) ||
        (cp >= 0xFE20 && cp <= 0xFE2F))
        return 0;

    if ((cp >= 0x1100 && cp <= 0x115F) ||
        (cp >= 0x2E80 && cp <= 0x303E) ||
        (cp >= 0x3040 && cp <= 0x33BF) ||
        (cp >= 0x3400 && cp <= 0x4DBF) ||
        (cp >= 0x4E00 && cp <= 0xA4CF) ||
        (cp >= 0xAC00 && cp <= 0xD7AF) ||
        (cp >= 0xF900 && cp <= 0xFAFF) ||
        (cp >= 0xFE30 && cp <= 0xFE6F) ||
        (cp >= 0xFF01 && cp <= 0xFF60) ||
        (cp >= 0xFFE0 && cp <= 0xFFE6) ||
        (cp >= 0x20000 && cp <= 0x2FFFD) ||
        (cp >= 0x30000 && cp <= 0x3FFFD))
        return 2;

    return 1;
}

size_t utf8_strwidth(const char *s, size_t byte_len) {
    const char *end = s + byte_len;
    size_t width = 0;
    while (s < end) {
        int32_t cp = utf8_decode(&s);
        if (cp >= 0) width += (size_t)utf8_charwidth(cp);
    }
    return width;
}
