#include "vex.h"
#include <math.h>
#include <ctype.h>

typedef struct {
    const char *src;
    size_t pos;
    size_t len;
    bool had_error;
} JsonParser;

static void json_skip_ws(JsonParser *p) {
    while (p->pos < p->len) {
        char c = p->src[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            p->pos++;
        else
            break;
    }
}

static char json_peek(JsonParser *p) {
    json_skip_ws(p);
    return p->pos < p->len ? p->src[p->pos] : '\0';
}

static bool json_match(JsonParser *p, char expected) {
    json_skip_ws(p);
    if (p->pos < p->len && p->src[p->pos] == expected) {
        p->pos++;
        return true;
    }
    return false;
}

static bool json_match_str(JsonParser *p, const char *s) {
    json_skip_ws(p);
    size_t slen = strlen(s);
    if (p->pos + slen <= p->len && strncmp(p->src + p->pos, s, slen) == 0) {
        p->pos += slen;
        return true;
    }
    return false;
}

static VexValue *json_parse_value(JsonParser *p);

static VexValue *json_parse_string(JsonParser *p) {
    if (!json_match(p, '"')) { p->had_error = true; return vval_null(); }

    /* Fast path: scan for end quote without escapes */
    size_t start = p->pos;
    bool has_escape = false;
    while (p->pos < p->len && p->src[p->pos] != '"') {
        if (p->src[p->pos] == '\\') { has_escape = true; break; }
        p->pos++;
    }

    if (!has_escape) {
        VexValue *result = vval_string(vstr_newn(p->src + start, p->pos - start));
        p->pos++; /* skip closing quote */
        return result;
    }

    /* Slow path: string has escapes */
    p->pos = start;
    VexStr out = vstr_empty();
    while (p->pos < p->len && p->src[p->pos] != '"') {
        if (p->src[p->pos] == '\\') {
            p->pos++;
            if (p->pos >= p->len) break;
            switch (p->src[p->pos]) {
            case '"':  vstr_append_char(&out, '"'); break;
            case '\\': vstr_append_char(&out, '\\'); break;
            case '/':  vstr_append_char(&out, '/'); break;
            case 'b':  vstr_append_char(&out, '\b'); break;
            case 'f':  vstr_append_char(&out, '\f'); break;
            case 'n':  vstr_append_char(&out, '\n'); break;
            case 'r':  vstr_append_char(&out, '\r'); break;
            case 't':  vstr_append_char(&out, '\t'); break;
            case 'u': {
                p->pos++;
                if (p->pos + 4 > p->len) { p->had_error = true; break; }
                char hex[5] = {0};
                memcpy(hex, p->src + p->pos, 4);
                unsigned long cp = strtoul(hex, NULL, 16);
                p->pos += 3;
                char utf8[4];
                if (cp < 0x80) {
                    utf8[0] = (char)cp;
                    vstr_append(&out, utf8, 1);
                } else if (cp < 0x800) {
                    utf8[0] = (char)(0xC0 | (cp >> 6));
                    utf8[1] = (char)(0x80 | (cp & 0x3F));
                    vstr_append(&out, utf8, 2);
                } else {
                    utf8[0] = (char)(0xE0 | (cp >> 12));
                    utf8[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
                    utf8[2] = (char)(0x80 | (cp & 0x3F));
                    vstr_append(&out, utf8, 3);
                }
                break;
            }
            default:
                vstr_append_char(&out, p->src[p->pos]);
            }
            p->pos++;
        } else {
            /* Bulk copy plain characters */
            size_t chunk = p->pos;
            while (p->pos < p->len && p->src[p->pos] != '"' && p->src[p->pos] != '\\')
                p->pos++;
            vstr_append(&out, p->src + chunk, p->pos - chunk);
        }
    }
    if (!json_match(p, '"')) p->had_error = true;
    return vval_string(out);
}

static char *json_parse_key(JsonParser *p) {
    json_skip_ws(p);
    if (p->pos >= p->len || p->src[p->pos] != '"') {
        p->had_error = true;
        return strdup("");
    }
    p->pos++;
    /* Fast path: no escapes in key */
    size_t start = p->pos;
    while (p->pos < p->len && p->src[p->pos] != '"' && p->src[p->pos] != '\\')
        p->pos++;
    if (p->pos < p->len && p->src[p->pos] == '"') {
        char *result = strndup(p->src + start, p->pos - start);
        p->pos++;
        return result;
    }
    /* Slow path: fall back to full string parse */
    p->pos = start - 1;
    VexValue *v = json_parse_string(p);
    VexStr s = vval_to_str(v);
    char *result = strdup(vstr_data(&s));
    vstr_free(&s);
    vval_release(v);
    return result;
}

static VexValue *json_parse_number(JsonParser *p) {
    json_skip_ws(p);
    const char *start = p->src + p->pos;
    char *end;
    bool is_float = false;

    /* Scan to determine int vs float */
    if (p->pos < p->len && p->src[p->pos] == '-') p->pos++;
    while (p->pos < p->len && p->src[p->pos] >= '0' && p->src[p->pos] <= '9') p->pos++;
    if (p->pos < p->len && p->src[p->pos] == '.') {
        is_float = true;
        p->pos++;
        while (p->pos < p->len && p->src[p->pos] >= '0' && p->src[p->pos] <= '9') p->pos++;
    }
    if (p->pos < p->len && (p->src[p->pos] == 'e' || p->src[p->pos] == 'E')) {
        is_float = true;
        p->pos++;
        if (p->pos < p->len && (p->src[p->pos] == '+' || p->src[p->pos] == '-')) p->pos++;
        while (p->pos < p->len && p->src[p->pos] >= '0' && p->src[p->pos] <= '9') p->pos++;
    }

    if (is_float) return vval_float(strtod(start, &end));
    return vval_int(strtoll(start, &end, 10));
}

static VexValue *json_parse_array(JsonParser *p) {
    json_match(p, '[');
    VexValue *list = vval_list();
    if (json_peek(p) == ']') { p->pos++; return list; }

    for (;;) {
        VexValue *item = json_parse_value(p);
        vval_list_push(list, item);
        vval_release(item);
        if (p->had_error) break;
        if (!json_match(p, ',')) break;
    }
    if (!json_match(p, ']')) p->had_error = true;
    return list;
}

static VexValue *json_parse_object(JsonParser *p) {
    json_match(p, '{');
    VexValue *rec = vval_record();
    if (json_peek(p) == '}') { p->pos++; return rec; }

    for (;;) {
        char *key = json_parse_key(p);
        if (!json_match(p, ':')) { free(key); p->had_error = true; break; }
        VexValue *val = json_parse_value(p);
        vval_record_set(rec, key, val);
        vval_release(val);
        free(key);
        if (p->had_error) break;
        if (!json_match(p, ',')) break;
    }
    if (!json_match(p, '}')) p->had_error = true;
    return rec;
}

static VexValue *json_parse_value(JsonParser *p) {
    char c = json_peek(p);
    if (c == '"') return json_parse_string(p);
    if (c == '{') return json_parse_object(p);
    if (c == '[') return json_parse_array(p);
    if (c == '-' || (c >= '0' && c <= '9')) return json_parse_number(p);
    if (json_match_str(p, "true"))  return vval_bool(true);
    if (json_match_str(p, "false")) return vval_bool(false);
    if (json_match_str(p, "null"))  return vval_null();
    p->had_error = true;
    return vval_null();
}

VexValue *format_from_json(const char *src, size_t len) {
    JsonParser p = { .src = src, .pos = 0, .len = len, .had_error = false };
    VexValue *result = json_parse_value(&p);
    if (p.had_error) {
        vval_release(result);
        return vval_error("invalid JSON");
    }
    return result;
}

static void json_serialize(VexStr *out, VexValue *v, int indent, int depth);

static void json_indent(VexStr *out, int indent, int depth) {
    if (indent <= 0) return;
    vstr_append_char(out, '\n');
    for (int i = 0; i < indent * depth; i++)
        vstr_append_char(out, ' ');
}

static void json_serialize_string(VexStr *out, const char *s, size_t len) {
    vstr_append_char(out, '"');
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  vstr_append(out, "\\\"", 2); break;
        case '\\': vstr_append(out, "\\\\", 2); break;
        case '\b': vstr_append(out, "\\b", 2); break;
        case '\f': vstr_append(out, "\\f", 2); break;
        case '\n': vstr_append(out, "\\n", 2); break;
        case '\r': vstr_append(out, "\\r", 2); break;
        case '\t': vstr_append(out, "\\t", 2); break;
        default:
            if (c < 0x20) {
                char esc[7];
                snprintf(esc, sizeof(esc), "\\u%04x", c);
                vstr_append_cstr(out, esc);
            } else {
                vstr_append_char(out, (char)c);
            }
        }
    }
    vstr_append_char(out, '"');
}

static void json_serialize(VexStr *out, VexValue *v, int indent, int depth) {
    if (!v) { vstr_append_cstr(out, "null"); return; }

    switch (v->type) {
    case VEX_VAL_NULL:
        vstr_append_cstr(out, "null"); break;
    case VEX_VAL_BOOL:
        vstr_append_cstr(out, v->boolean ? "true" : "false"); break;
    case VEX_VAL_INT: {
        char buf[32];
        snprintf(buf, sizeof(buf), "%lld", (long long)v->integer);
        vstr_append_cstr(out, buf);
        break;
    }
    case VEX_VAL_FLOAT: {
        char buf[64];
        snprintf(buf, sizeof(buf), "%g", v->floating);
        vstr_append_cstr(out, buf);
        break;
    }
    case VEX_VAL_STRING:
        json_serialize_string(out, vstr_data(&v->string), vstr_len(&v->string));
        break;
    case VEX_VAL_LIST: {
        vstr_append_char(out, '[');
        for (size_t i = 0; i < v->list.len; i++) {
            if (i > 0) vstr_append_char(out, ',');
            if (indent > 0) json_indent(out, indent, depth + 1);
            json_serialize(out, v->list.data[i], indent, depth + 1);
        }
        if (v->list.len > 0 && indent > 0) json_indent(out, indent, depth);
        vstr_append_char(out, ']');
        break;
    }
    case VEX_VAL_RECORD: {
        vstr_append_char(out, '{');
        VexMapIter it = vmap_iter(&v->record);
        const char *key;
        void *val;
        bool first = true;
        while (vmap_next(&it, &key, &val)) {
            if (!first) vstr_append_char(out, ',');
            if (indent > 0) json_indent(out, indent, depth + 1);
            json_serialize_string(out, key, strlen(key));
            vstr_append_char(out, ':');
            if (indent > 0) vstr_append_char(out, ' ');
            json_serialize(out, val, indent, depth + 1);
            first = false;
        }
        if (!first && indent > 0) json_indent(out, indent, depth);
        vstr_append_char(out, '}');
        break;
    }
    default: {
        VexStr s = vval_to_str(v);
        json_serialize_string(out, vstr_data(&s), vstr_len(&s));
        vstr_free(&s);
    }
    }
}

VexStr format_to_json(VexValue *v, bool pretty) {
    VexStr out = vstr_empty();
    json_serialize(&out, v, pretty ? 2 : 0, 0);
    return out;
}

static const char *csv_parse_field(const char *s, VexStr *out) {
    *out = vstr_empty();
    if (*s == '"') {

        s++;
        while (*s) {
            if (*s == '"') {
                if (s[1] == '"') {
                    vstr_append_char(out, '"');
                    s += 2;
                } else {
                    s++;
                    break;
                }
            } else {
                vstr_append_char(out, *s);
                s++;
            }
        }
    } else {

        while (*s && *s != ',' && *s != '\n' && *s != '\r') {
            vstr_append_char(out, *s);
            s++;
        }
    }
    return s;
}

static VexValue *csv_parse_line(const char **cursor) {
    VexValue *fields = vval_list();
    const char *s = *cursor;

    while (*s && *s != '\n' && *s != '\r') {
        VexStr field;
        s = csv_parse_field(s, &field);
        VexValue *v = vval_string(field);
        vval_list_push(fields, v);
        vval_release(v);
        if (*s == ',') s++;
        else break;
    }

    if (*s == '\r') s++;
    if (*s == '\n') s++;
    *cursor = s;
    return fields;
}

VexValue *format_from_csv(const char *src, size_t len) {
    (void)len;
    const char *cursor = src;

    VexValue *headers = csv_parse_line(&cursor);
    if (headers->list.len == 0) {
        vval_release(headers);
        return vval_error("CSV: empty header row");
    }

    size_t ncols = headers->list.len;
    char **hnames = malloc(ncols * sizeof(char *));
    for (size_t i = 0; i < ncols; i++) {
        VexValue *h = headers->list.data[i];
        hnames[i] = strdup(vstr_data(&h->string));
    }
    vval_release(headers);

    VexValue *result = vval_list();
    while (*cursor) {

        if (*cursor == '\n' || *cursor == '\r') {
            if (*cursor == '\r') cursor++;
            if (*cursor == '\n') cursor++;
            continue;
        }
        VexValue *fields = csv_parse_line(&cursor);
        VexValue *rec = vval_record();
        for (size_t i = 0; i < fields->list.len && i < ncols; i++) {
            vval_record_set(rec, hnames[i], fields->list.data[i]);
        }
        vval_list_push(result, rec);
        vval_release(rec);
        vval_release(fields);
    }

    for (size_t i = 0; i < ncols; i++) free(hnames[i]);
    free(hnames);
    return result;
}

static void csv_write_field(VexStr *out, const char *s) {
    bool needs_quote = false;
    for (const char *p = s; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') {
            needs_quote = true;
            break;
        }
    }
    if (needs_quote) {
        vstr_append_char(out, '"');
        for (const char *p = s; *p; p++) {
            if (*p == '"') vstr_append(out, "\"\"", 2);
            else vstr_append_char(out, *p);
        }
        vstr_append_char(out, '"');
    } else {
        vstr_append_cstr(out, s);
    }
}

VexStr format_to_csv(VexValue *v) {
    VexStr out = vstr_empty();
    if (!v || v->type != VEX_VAL_LIST || v->list.len == 0)
        return out;

    VexValue *first = v->list.data[0];
    if (first->type != VEX_VAL_RECORD) return out;

    size_t ncols = 0;
    char *cols[128];
    VexMapIter it = vmap_iter(&first->record);
    const char *key;
    void *val;
    while (vmap_next(&it, &key, &val) && ncols < 128) {
        cols[ncols++] = (char *)key;
    }

    for (size_t i = 0; i < ncols; i++) {
        if (i > 0) vstr_append_char(&out, ',');
        csv_write_field(&out, cols[i]);
    }
    vstr_append_char(&out, '\n');

    for (size_t r = 0; r < v->list.len; r++) {
        VexValue *row = v->list.data[r];
        if (row->type != VEX_VAL_RECORD) continue;
        for (size_t c = 0; c < ncols; c++) {
            if (c > 0) vstr_append_char(&out, ',');
            VexValue *fv = vval_record_get(row, cols[c]);
            if (fv) {
                VexStr s = vval_to_str(fv);
                csv_write_field(&out, vstr_data(&s));
                vstr_free(&s);
            }
        }
        vstr_append_char(&out, '\n');
    }
    return out;
}

typedef struct {
    const char *src;
    size_t pos;
    size_t len;
    bool had_error;
} TomlParser;

static void toml_skip_ws(TomlParser *p) {
    while (p->pos < p->len) {
        char c = p->src[p->pos];
        if (c == ' ' || c == '\t') p->pos++;
        else break;
    }
}

static void toml_skip_line(TomlParser *p) {
    while (p->pos < p->len && p->src[p->pos] != '\n') p->pos++;
    if (p->pos < p->len) p->pos++;
}

static void toml_skip_ws_and_newlines(TomlParser *p) {
    while (p->pos < p->len) {
        char c = p->src[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            p->pos++;
        } else if (c == '#') {
            toml_skip_line(p);
        } else {
            break;
        }
    }
}

static char toml_peek(TomlParser *p) {
    return p->pos < p->len ? p->src[p->pos] : '\0';
}

static VexValue *toml_parse_value(TomlParser *p);

static char *toml_parse_key(TomlParser *p) {
    toml_skip_ws(p);
    if (toml_peek(p) == '"') {

        p->pos++;
        VexStr s = vstr_empty();
        while (p->pos < p->len && p->src[p->pos] != '"') {
            if (p->src[p->pos] == '\\') {
                p->pos++;
                switch (p->src[p->pos]) {
                case '"': vstr_append_char(&s, '"'); break;
                case '\\': vstr_append_char(&s, '\\'); break;
                case 'n': vstr_append_char(&s, '\n'); break;
                case 't': vstr_append_char(&s, '\t'); break;
                default: vstr_append_char(&s, p->src[p->pos]);
                }
            } else {
                vstr_append_char(&s, p->src[p->pos]);
            }
            p->pos++;
        }
        if (p->pos < p->len) p->pos++;
        char *result = strdup(vstr_data(&s));
        vstr_free(&s);
        return result;
    }

    size_t start = p->pos;
    while (p->pos < p->len) {
        char c = p->src[p->pos];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-') {
            p->pos++;
        } else {
            break;
        }
    }
    if (p->pos == start) { p->had_error = true; return strdup(""); }
    return strndup(p->src + start, p->pos - start);
}

static VexValue *toml_parse_string(TomlParser *p) {
    char quote = p->src[p->pos];
    bool is_multiline = false;

    if (p->pos + 2 < p->len && p->src[p->pos+1] == quote && p->src[p->pos+2] == quote) {
        is_multiline = true;
        p->pos += 3;

        if (p->pos < p->len && p->src[p->pos] == '\n') p->pos++;
        else if (p->pos + 1 < p->len && p->src[p->pos] == '\r' && p->src[p->pos+1] == '\n') p->pos += 2;
    } else {
        p->pos++;
    }

    bool is_literal = (quote == '\'');
    VexStr s = vstr_empty();

    if (is_multiline) {
        while (p->pos < p->len) {
            if (p->src[p->pos] == quote && p->pos + 2 < p->len &&
                p->src[p->pos+1] == quote && p->src[p->pos+2] == quote) {
                p->pos += 3;
                return vval_string(s);
            }
            if (!is_literal && p->src[p->pos] == '\\') {
                p->pos++;
                if (p->pos >= p->len) break;
                switch (p->src[p->pos]) {
                case 'n': vstr_append_char(&s, '\n'); break;
                case 't': vstr_append_char(&s, '\t'); break;
                case 'r': vstr_append_char(&s, '\r'); break;
                case '\\': vstr_append_char(&s, '\\'); break;
                case '"': vstr_append_char(&s, '"'); break;
                case '\n':

                    p->pos++;
                    while (p->pos < p->len && (p->src[p->pos] == ' ' || p->src[p->pos] == '\t' || p->src[p->pos] == '\n' || p->src[p->pos] == '\r'))
                        p->pos++;
                    continue;
                default: vstr_append_char(&s, p->src[p->pos]);
                }
                p->pos++;
            } else {
                vstr_append_char(&s, p->src[p->pos]);
                p->pos++;
            }
        }
    } else {

        while (p->pos < p->len && p->src[p->pos] != quote && p->src[p->pos] != '\n') {
            if (!is_literal && p->src[p->pos] == '\\') {
                p->pos++;
                if (p->pos >= p->len) break;
                switch (p->src[p->pos]) {
                case 'n': vstr_append_char(&s, '\n'); break;
                case 't': vstr_append_char(&s, '\t'); break;
                case 'r': vstr_append_char(&s, '\r'); break;
                case '\\': vstr_append_char(&s, '\\'); break;
                case '"': vstr_append_char(&s, '"'); break;
                default: vstr_append_char(&s, p->src[p->pos]);
                }
                p->pos++;
            } else {
                vstr_append_char(&s, p->src[p->pos]);
                p->pos++;
            }
        }
        if (p->pos < p->len && p->src[p->pos] == quote) p->pos++;
    }
    return vval_string(s);
}

static VexValue *toml_parse_number(TomlParser *p) {
    const char *start = p->src + p->pos;
    bool is_float = false;

    if (p->src[p->pos] == '+' || p->src[p->pos] == '-') p->pos++;
    while (p->pos < p->len && ((p->src[p->pos] >= '0' && p->src[p->pos] <= '9') || p->src[p->pos] == '_'))
        p->pos++;
    if (p->pos < p->len && p->src[p->pos] == '.') {
        is_float = true;
        p->pos++;
        while (p->pos < p->len && ((p->src[p->pos] >= '0' && p->src[p->pos] <= '9') || p->src[p->pos] == '_'))
            p->pos++;
    }
    if (p->pos < p->len && (p->src[p->pos] == 'e' || p->src[p->pos] == 'E')) {
        is_float = true;
        p->pos++;
        if (p->pos < p->len && (p->src[p->pos] == '+' || p->src[p->pos] == '-')) p->pos++;
        while (p->pos < p->len && p->src[p->pos] >= '0' && p->src[p->pos] <= '9') p->pos++;
    }

    char buf[64];
    size_t bi = 0;
    for (const char *c = start; c < p->src + p->pos && bi < 62; c++) {
        if (*c != '_') buf[bi++] = *c;
    }
    buf[bi] = '\0';

    if (is_float) return vval_float(strtod(buf, NULL));
    return vval_int(strtoll(buf, NULL, 10));
}

static VexValue *toml_parse_array(TomlParser *p) {
    p->pos++;
    VexValue *list = vval_list();
    toml_skip_ws_and_newlines(p);

    while (p->pos < p->len && toml_peek(p) != ']') {
        VexValue *item = toml_parse_value(p);
        vval_list_push(list, item);
        vval_release(item);
        toml_skip_ws_and_newlines(p);
        if (toml_peek(p) == ',') { p->pos++; toml_skip_ws_and_newlines(p); }
    }
    if (p->pos < p->len) p->pos++;
    return list;
}

static VexValue *toml_parse_inline_table(TomlParser *p) {
    p->pos++;
    VexValue *rec = vval_record();
    toml_skip_ws(p);

    while (p->pos < p->len && toml_peek(p) != '}') {
        char *key = toml_parse_key(p);
        toml_skip_ws(p);
        if (p->pos < p->len && p->src[p->pos] == '=') p->pos++;
        toml_skip_ws(p);
        VexValue *val = toml_parse_value(p);
        vval_record_set(rec, key, val);
        vval_release(val);
        free(key);
        toml_skip_ws(p);
        if (toml_peek(p) == ',') { p->pos++; toml_skip_ws(p); }
    }
    if (p->pos < p->len) p->pos++;
    return rec;
}

static VexValue *toml_parse_value(TomlParser *p) {
    toml_skip_ws(p);
    char c = toml_peek(p);

    if (c == '"' || c == '\'') return toml_parse_string(p);
    if (c == '[') return toml_parse_array(p);
    if (c == '{') return toml_parse_inline_table(p);

    if (p->pos + 4 <= p->len && strncmp(p->src + p->pos, "true", 4) == 0) {
        p->pos += 4;
        return vval_bool(true);
    }
    if (p->pos + 5 <= p->len && strncmp(p->src + p->pos, "false", 5) == 0) {
        p->pos += 5;
        return vval_bool(false);
    }

    if (c == '+' || c == '-' || (c >= '0' && c <= '9')) {
        return toml_parse_number(p);
    }

    p->had_error = true;
    return vval_null();
}

static void toml_set_nested(VexValue *root, char **keys, size_t nkeys, VexValue *val) {
    VexValue *current = root;
    for (size_t i = 0; i < nkeys - 1; i++) {
        VexValue *child = vval_record_get(current, keys[i]);
        if (!child || child->type != VEX_VAL_RECORD) {
            child = vval_record();
            vval_record_set(current, keys[i], child);
            vval_release(child);
            child = vval_record_get(current, keys[i]);
        }
        current = child;
    }
    vval_record_set(current, keys[nkeys - 1], val);
}

static VexValue *toml_get_table(VexValue *root, char **keys, size_t nkeys) {
    VexValue *current = root;
    for (size_t i = 0; i < nkeys; i++) {
        VexValue *child = vval_record_get(current, keys[i]);
        if (!child || child->type != VEX_VAL_RECORD) {
            child = vval_record();
            vval_record_set(current, keys[i], child);
            vval_release(child);
            child = vval_record_get(current, keys[i]);
        }
        current = child;
    }
    return current;
}

VexValue *format_from_toml(const char *src, size_t len) {
    TomlParser p = { .src = src, .pos = 0, .len = len, .had_error = false };
    VexValue *root = vval_record();
    VexValue *current_table = root;

    while (p.pos < p.len) {
        toml_skip_ws_and_newlines(&p);
        if (p.pos >= p.len) break;
        char c = toml_peek(&p);

        if (c == '[') {

            p.pos++;
            bool is_array = false;
            if (p.pos < p.len && p.src[p.pos] == '[') {
                is_array = true;
                p.pos++;
            }

            char *keys[32];
            size_t nkeys = 0;
            for (;;) {
                if (nkeys >= 32) break;
                toml_skip_ws(&p);
                keys[nkeys++] = toml_parse_key(&p);
                toml_skip_ws(&p);
                if (toml_peek(&p) == '.') { p.pos++; continue; }
                break;
            }

            if (is_array) {
                if (p.pos < p.len && p.src[p.pos] == ']') p.pos++;
                if (p.pos < p.len && p.src[p.pos] == ']') p.pos++;

                VexValue *parent = nkeys > 1 ? toml_get_table(root, keys, nkeys - 1) : root;
                VexValue *arr = vval_record_get(parent, keys[nkeys - 1]);
                if (!arr || arr->type != VEX_VAL_LIST) {
                    arr = vval_list();
                    vval_record_set(parent, keys[nkeys - 1], arr);
                    vval_release(arr);
                    arr = vval_record_get(parent, keys[nkeys - 1]);
                }
                VexValue *new_table = vval_record();
                vval_list_push(arr, new_table);
                vval_release(new_table);
                current_table = arr->list.data[arr->list.len - 1];
            } else {
                if (p.pos < p.len && p.src[p.pos] == ']') p.pos++;
                current_table = toml_get_table(root, keys, nkeys);
            }

            for (size_t i = 0; i < nkeys; i++) free(keys[i]);
            toml_skip_line(&p);
            continue;
        }

        if (c == '\n' || c == '\r' || c == '#') {
            toml_skip_line(&p);
            continue;
        }

        char *keys[32];
        size_t nkeys = 0;
        for (;;) {
            if (nkeys >= 32) break;
            keys[nkeys++] = toml_parse_key(&p);
            toml_skip_ws(&p);
            if (toml_peek(&p) == '.') { p.pos++; continue; }
            break;
        }

        toml_skip_ws(&p);
        if (p.pos < p.len && p.src[p.pos] == '=') p.pos++;
        toml_skip_ws(&p);

        VexValue *val = toml_parse_value(&p);

        if (nkeys == 1) {
            vval_record_set(current_table, keys[0], val);
        } else {
            toml_set_nested(current_table, keys, nkeys, val);
        }
        vval_release(val);

        for (size_t i = 0; i < nkeys; i++) free(keys[i]);
        toml_skip_line(&p);
    }

    if (p.had_error) {
        vval_release(root);
        return vval_error("invalid TOML");
    }
    return root;
}

static void toml_serialize_value(VexStr *out, VexValue *v);

static void toml_serialize_value(VexStr *out, VexValue *v) {
    if (!v) { vstr_append_cstr(out, "\"\""); return; }
    switch (v->type) {
    case VEX_VAL_NULL:   vstr_append_cstr(out, "\"\""); break;
    case VEX_VAL_BOOL:   vstr_append_cstr(out, v->boolean ? "true" : "false"); break;
    case VEX_VAL_INT: {
        char buf[32];
        snprintf(buf, sizeof(buf), "%lld", (long long)v->integer);
        vstr_append_cstr(out, buf);
        break;
    }
    case VEX_VAL_FLOAT: {
        char buf[64];
        snprintf(buf, sizeof(buf), "%g", v->floating);
        vstr_append_cstr(out, buf);
        break;
    }
    case VEX_VAL_STRING:
        json_serialize_string(out, vstr_data(&v->string), vstr_len(&v->string));
        break;
    case VEX_VAL_LIST: {
        vstr_append_cstr(out, "[");
        for (size_t i = 0; i < v->list.len; i++) {
            if (i > 0) vstr_append_cstr(out, ", ");
            toml_serialize_value(out, v->list.data[i]);
        }
        vstr_append_char(out, ']');
        break;
    }
    default: {
        VexStr s = vval_to_str(v);
        json_serialize_string(out, vstr_data(&s), vstr_len(&s));
        vstr_free(&s);
    }
    }
}

static void toml_serialize_table(VexStr *out, VexValue *rec, const char *prefix);

static void toml_serialize_table(VexStr *out, VexValue *rec, const char *prefix) {
    if (rec->type != VEX_VAL_RECORD) return;

    VexMapIter it = vmap_iter(&rec->record);
    const char *key;
    void *val;
    while (vmap_next(&it, &key, &val)) {
        VexValue *v = val;
        if (v->type == VEX_VAL_RECORD || (v->type == VEX_VAL_LIST && v->list.len > 0 &&
            ((VexValue *)v->list.data[0])->type == VEX_VAL_RECORD))
            continue;
        vstr_append_cstr(out, key);
        vstr_append_cstr(out, " = ");
        toml_serialize_value(out, v);
        vstr_append_char(out, '\n');
    }

    it = vmap_iter(&rec->record);
    while (vmap_next(&it, &key, &val)) {
        VexValue *v = val;
        if (v->type == VEX_VAL_RECORD) {
            char path[512];
            if (prefix[0])
                snprintf(path, sizeof(path), "%s.%s", prefix, key);
            else
                snprintf(path, sizeof(path), "%s", key);
            vstr_append_char(out, '\n');
            vstr_append_char(out, '[');
            vstr_append_cstr(out, path);
            vstr_append_cstr(out, "]\n");
            toml_serialize_table(out, v, path);
        } else if (v->type == VEX_VAL_LIST && v->list.len > 0 &&
                   ((VexValue *)v->list.data[0])->type == VEX_VAL_RECORD) {
            char path[512];
            if (prefix[0])
                snprintf(path, sizeof(path), "%s.%s", prefix, key);
            else
                snprintf(path, sizeof(path), "%s", key);
            for (size_t i = 0; i < v->list.len; i++) {
                vstr_append_char(out, '\n');
                vstr_append_cstr(out, "[[");
                vstr_append_cstr(out, path);
                vstr_append_cstr(out, "]]\n");
                toml_serialize_table(out, v->list.data[i], path);
            }
        }
    }
}

VexStr format_to_toml(VexValue *v) {
    VexStr out = vstr_empty();
    if (v && v->type == VEX_VAL_RECORD) {
        toml_serialize_table(&out, v, "");
    }
    return out;
}
