#include "vex.h"
#include <stdarg.h>

static void vstr_promote(VexStr *s) {
    if (s->on_heap) return;
    size_t len = s->sso.len;
    size_t cap = len < 32 ? 32 : len * 2;
    char *data = malloc(cap + 1);
    memcpy(data, s->sso.data, len);
    data[len] = '\0';
    s->heap.data = data;
    s->heap.len = len;
    s->heap.cap = cap;
    s->on_heap = true;
}

VexStr vstr_new(const char *s) {
    if (!s) return vstr_empty();
    return vstr_newn(s, strlen(s));
}

VexStr vstr_newn(const char *s, size_t n) {
    VexStr v;
    if (n <= VEX_STR_SSO_CAP) {
        v.on_heap = false;
        memcpy(v.sso.data, s, n);
        v.sso.data[n] = '\0';
        v.sso.len = (uint8_t)n;
    } else {
        v.on_heap = true;
        v.heap.cap = n < 32 ? 32 : n;
        v.heap.data = malloc(v.heap.cap + 1);
        memcpy(v.heap.data, s, n);
        v.heap.data[n] = '\0';
        v.heap.len = n;
    }
    return v;
}

VexStr vstr_empty(void) {
    VexStr v;
    v.on_heap = false;
    v.sso.data[0] = '\0';
    v.sso.len = 0;
    return v;
}

VexStr vstr_clone(const VexStr *s) {
    return vstr_newn(vstr_data(s), vstr_len(s));
}

void vstr_free(VexStr *s) {
    if (s->on_heap) {
        free(s->heap.data);
    }
    s->on_heap = false;
    s->sso.len = 0;
    s->sso.data[0] = '\0';
}

const char *vstr_data(const VexStr *s) {
    return s->on_heap ? s->heap.data : s->sso.data;
}

size_t vstr_len(const VexStr *s) {
    return s->on_heap ? s->heap.len : s->sso.len;
}

void vstr_append(VexStr *s, const char *data, size_t n) {
    if (n == 0) return;
    size_t cur_len = vstr_len(s);
    size_t new_len = cur_len + n;

    if (!s->on_heap && new_len <= VEX_STR_SSO_CAP) {
        memcpy(s->sso.data + cur_len, data, n);
        s->sso.data[new_len] = '\0';
        s->sso.len = (uint8_t)new_len;
        return;
    }

    if (!s->on_heap) {
        vstr_promote(s);
    }

    if (new_len > s->heap.cap) {
        s->heap.cap = new_len * 2;
        s->heap.data = realloc(s->heap.data, s->heap.cap + 1);
    }
    memcpy(s->heap.data + s->heap.len, data, n);
    s->heap.len = new_len;
    s->heap.data[new_len] = '\0';
}

void vstr_append_str(VexStr *s, const VexStr *other) {
    vstr_append(s, vstr_data(other), vstr_len(other));
}

void vstr_append_char(VexStr *s, char c) {
    vstr_append(s, &c, 1);
}

void vstr_append_cstr(VexStr *s, const char *cstr) {
    vstr_append(s, cstr, strlen(cstr));
}

bool vstr_eq(const VexStr *a, const VexStr *b) {
    size_t la = vstr_len(a), lb = vstr_len(b);
    if (la != lb) return false;
    return memcmp(vstr_data(a), vstr_data(b), la) == 0;
}

bool vstr_eq_cstr(const VexStr *s, const char *cstr) {
    size_t sl = vstr_len(s);
    size_t cl = strlen(cstr);
    if (sl != cl) return false;
    return memcmp(vstr_data(s), cstr, sl) == 0;
}

int vstr_cmp(const VexStr *a, const VexStr *b) {
    size_t la = vstr_len(a), lb = vstr_len(b);
    size_t min = la < lb ? la : lb;
    int r = memcmp(vstr_data(a), vstr_data(b), min);
    if (r != 0) return r;
    return la < lb ? -1 : (la > lb ? 1 : 0);
}

VexStr vstr_substr(const VexStr *s, size_t start, size_t len) {
    size_t sl = vstr_len(s);
    if (start >= sl) return vstr_empty();
    if (start + len > sl) len = sl - start;
    return vstr_newn(vstr_data(s) + start, len);
}

VexStr vstr_fmt(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    va_list args2;
    va_copy(args2, args);
    int needed = vsnprintf(NULL, 0, fmt, args);
    va_end(args);

    if (needed < 0) {
        va_end(args2);
        return vstr_empty();
    }

    char *buf = malloc((size_t)needed + 1);
    vsnprintf(buf, (size_t)needed + 1, fmt, args2);
    va_end(args2);

    VexStr s = vstr_newn(buf, (size_t)needed);
    free(buf);
    return s;
}
