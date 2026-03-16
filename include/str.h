#ifndef VEX_STR_H
#define VEX_STR_H

#define VEX_STR_SSO_CAP 22

struct VexStr {
    union {
        struct {
            char *data;
            size_t len;
            size_t cap;
        } heap;
        struct {
            char data[VEX_STR_SSO_CAP + 1];
            uint8_t len;
        } sso;
    };
    bool on_heap;
};

VexStr  vstr_new(const char *s);
VexStr  vstr_newn(const char *s, size_t n);
VexStr  vstr_empty(void);
VexStr  vstr_clone(const VexStr *s);
void    vstr_free(VexStr *s);

const char *vstr_data(const VexStr *s);
size_t      vstr_len(const VexStr *s);

void    vstr_append(VexStr *s, const char *data, size_t n);
void    vstr_append_str(VexStr *s, const VexStr *other);
void    vstr_append_char(VexStr *s, char c);
void    vstr_append_cstr(VexStr *s, const char *cstr);

bool    vstr_eq(const VexStr *a, const VexStr *b);
bool    vstr_eq_cstr(const VexStr *s, const char *cstr);
int     vstr_cmp(const VexStr *a, const VexStr *b);

VexStr  vstr_substr(const VexStr *s, size_t start, size_t len);
VexStr  vstr_fmt(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif
