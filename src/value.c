#include "vex.h"

static VexValue *vval_alloc(VexType type) {
    VexValue *v = calloc(1, sizeof(VexValue));
    v->type = type;
    v->refcount = 1;
    return v;
}

VexValue *vval_null(void) {
    return vval_alloc(VEX_VAL_NULL);
}

VexValue *vval_bool(bool b) {
    VexValue *v = vval_alloc(VEX_VAL_BOOL);
    v->boolean = b;
    return v;
}

VexValue *vval_int(int64_t n) {
    VexValue *v = vval_alloc(VEX_VAL_INT);
    v->integer = n;
    return v;
}

VexValue *vval_float(double f) {
    VexValue *v = vval_alloc(VEX_VAL_FLOAT);
    v->floating = f;
    return v;
}

VexValue *vval_string(VexStr s) {
    VexValue *v = vval_alloc(VEX_VAL_STRING);
    v->string = s;
    return v;
}

VexValue *vval_string_cstr(const char *s) {
    return vval_string(vstr_new(s));
}

VexValue *vval_list(void) {
    VexValue *v = vval_alloc(VEX_VAL_LIST);
    vexvec_init(&v->list);
    return v;
}

VexValue *vval_record(void) {
    VexValue *v = vval_alloc(VEX_VAL_RECORD);
    v->record = vmap_new();
    return v;
}

VexValue *vval_error(const char *msg) {
    VexValue *v = vval_alloc(VEX_VAL_ERROR);
    v->error = vex_error_new(msg);
    return v;
}

VexValue *vval_range(int64_t start, int64_t end, bool exclusive) {
    VexValue *v = vval_alloc(VEX_VAL_RANGE);
    v->range.start = start;
    v->range.end = end;
    v->range.exclusive = exclusive;
    return v;
}

VexValue *vval_retain(VexValue *v) {
    if (v) v->refcount++;
    return v;
}

void vval_release(VexValue *v) {
    if (!v) return;
    if (--v->refcount > 0) return;

    switch (v->type) {
    case VEX_VAL_STRING:
        vstr_free(&v->string);
        break;
    case VEX_VAL_LIST:
        for (size_t i = 0; i < v->list.len; i++) {
            vval_release(v->list.data[i]);
        }
        vexvec_free(&v->list);
        break;
    case VEX_VAL_RECORD: {
        VexMapIter it = vmap_iter(&v->record);
        const char *key;
        void *val;
        while (vmap_next(&it, &key, &val)) {
            vval_release(val);
        }
        vmap_free(&v->record);
        break;
    }
    case VEX_VAL_BYTES:
        free(v->bytes.data);
        break;
    case VEX_VAL_ERROR:
        vex_error_free(v->error);
        break;
    case VEX_VAL_CLOSURE:

        break;
    default:
        break;
    }
    free(v);
}

void vval_list_push(VexValue *list, VexValue *item) {
    vexvec_push(&list->list, vval_retain(item));
}

VexValue *vval_list_get(VexValue *list, size_t i) {
    return vexvec_get(&list->list, i);
}

size_t vval_list_len(VexValue *list) {
    return list->list.len;
}

void vval_record_set(VexValue *rec, const char *key, VexValue *val) {
    VexValue *old = vmap_get(&rec->record, key);
    if (old) vval_release(old);
    vmap_set(&rec->record, key, vval_retain(val));
}

VexValue *vval_record_get(VexValue *rec, const char *key) {
    return vmap_get(&rec->record, key);
}

bool vval_record_has(VexValue *rec, const char *key) {
    return vmap_has(&rec->record, key);
}

const char *vval_type_name(VexType t) {
    switch (t) {
    case VEX_VAL_NULL:    return "null";
    case VEX_VAL_BOOL:    return "bool";
    case VEX_VAL_INT:     return "int";
    case VEX_VAL_FLOAT:   return "float";
    case VEX_VAL_STRING:  return "string";
    case VEX_VAL_LIST:    return "list";
    case VEX_VAL_RECORD:  return "record";
    case VEX_VAL_CLOSURE: return "closure";
    case VEX_VAL_STREAM:  return "stream";
    case VEX_VAL_BYTES:   return "bytes";
    case VEX_VAL_ERROR:   return "error";
    case VEX_VAL_RANGE:   return "range";
    }
    return "unknown";
}

static void print_value_inner(VexValue *v, FILE *out, int depth) {
    if (!v) { fprintf(out, "null"); return; }
    if (depth > 10) { fprintf(out, "..."); return; }

    switch (v->type) {
    case VEX_VAL_NULL:
        fprintf(out, "null");
        break;
    case VEX_VAL_BOOL:
        fprintf(out, "%s", v->boolean ? "true" : "false");
        break;
    case VEX_VAL_INT:
        fprintf(out, "%ld", v->integer);
        break;
    case VEX_VAL_FLOAT:
        fprintf(out, "%g", v->floating);
        break;
    case VEX_VAL_STRING:
        if (depth == 0)
            fprintf(out, "%s", vstr_data(&v->string));
        else
            fprintf(out, "\"%s\"", vstr_data(&v->string));
        break;
    case VEX_VAL_LIST:
        fprintf(out, "[");
        for (size_t i = 0; i < v->list.len; i++) {
            if (i > 0) fprintf(out, ", ");
            print_value_inner(v->list.data[i], out, depth + 1);
        }
        fprintf(out, "]");
        break;
    case VEX_VAL_RECORD: {
        fprintf(out, "{");
        VexMapIter it = vmap_iter(&v->record);
        const char *key;
        void *val;
        bool first = true;
        while (vmap_next(&it, &key, &val)) {
            if (!first) fprintf(out, ", ");
            fprintf(out, "%s: ", key);
            print_value_inner(val, out, depth + 1);
            first = false;
        }
        fprintf(out, "}");
        break;
    }
    case VEX_VAL_CLOSURE:
        fprintf(out, "<closure>");
        break;
    case VEX_VAL_STREAM:
        fprintf(out, "<stream>");
        break;
    case VEX_VAL_BYTES:
        fprintf(out, "<bytes %zu>", v->bytes.len);
        break;
    case VEX_VAL_ERROR:
        fprintf(out, "<error: %s>", v->error->message);
        break;
    case VEX_VAL_RANGE:
        fprintf(out, "%ld%s%ld", v->range.start,
                v->range.exclusive ? "..<" : "..", v->range.end);
        break;
    }
}

void vval_print(VexValue *v, FILE *out) {
    print_value_inner(v, out, 0);
}

VexStr vval_to_str(VexValue *v) {
    if (!v) return vstr_new("null");

    switch (v->type) {
    case VEX_VAL_NULL:    return vstr_new("null");
    case VEX_VAL_BOOL:    return vstr_new(v->boolean ? "true" : "false");
    case VEX_VAL_INT:     return vstr_fmt("%ld", v->integer);
    case VEX_VAL_FLOAT:   return vstr_fmt("%g", v->floating);
    case VEX_VAL_STRING:  return vstr_clone(&v->string);
    case VEX_VAL_ERROR:   return vstr_fmt("<error: %s>", v->error->message);
    case VEX_VAL_RANGE:   return vstr_fmt("%ld%s%ld", v->range.start,
                              v->range.exclusive ? "..<" : "..", v->range.end);
    default:              return vstr_new("<value>");
    }
}

bool vval_truthy(VexValue *v) {
    if (!v) return false;
    switch (v->type) {
    case VEX_VAL_NULL:   return false;
    case VEX_VAL_BOOL:   return v->boolean;
    case VEX_VAL_INT:    return v->integer != 0;
    case VEX_VAL_FLOAT:  return v->floating != 0.0;
    case VEX_VAL_STRING: return vstr_len(&v->string) > 0;
    case VEX_VAL_LIST:   return v->list.len > 0;
    case VEX_VAL_ERROR:  return false;
    default:             return true;
    }
}

/* Deep structural equality for any two VexValues. */
bool vval_equal(VexValue *a, VexValue *b) {
    if (a == b) return true;
    if (!a || !b) return false;
    if (a->type != b->type) {
        if ((a->type == VEX_VAL_INT && b->type == VEX_VAL_FLOAT) ||
            (a->type == VEX_VAL_FLOAT && b->type == VEX_VAL_INT)) {
            double da = a->type == VEX_VAL_FLOAT ? a->floating : (double)a->integer;
            double db = b->type == VEX_VAL_FLOAT ? b->floating : (double)b->integer;
            return da == db;
        }
        return false;
    }
    switch (a->type) {
    case VEX_VAL_NULL:   return true;
    case VEX_VAL_BOOL:   return a->boolean == b->boolean;
    case VEX_VAL_INT:    return a->integer == b->integer;
    case VEX_VAL_FLOAT:  return a->floating == b->floating;
    case VEX_VAL_STRING: return vstr_eq(&a->string, &b->string);
    case VEX_VAL_LIST: {
        size_t len = vval_list_len(a);
        if (len != vval_list_len(b)) return false;
        for (size_t i = 0; i < len; i++) {
            VexValue *ai = vval_list_get(a, i);
            VexValue *bi = vval_list_get(b, i);
            if (!vval_equal(ai, bi)) return false;
        }
        return true;
    }
    case VEX_VAL_RECORD: {
        if (a->record.len != b->record.len) return false;
        VexMapIter it = vmap_iter(&a->record);
        const char *key;
        void *val;
        while (vmap_next(&it, &key, &val)) {
            VexValue *bv = vmap_get(&b->record, key);
            if (!bv || !vval_equal((VexValue *)val, bv)) return false;
        }
        return true;
    }
    case VEX_VAL_ERROR:
        return strcmp(a->error->message, b->error->message) == 0;
    case VEX_VAL_BYTES:
        return a->bytes.len == b->bytes.len &&
               memcmp(a->bytes.data, b->bytes.data, a->bytes.len) == 0;
    case VEX_VAL_RANGE:
        return a->range.start == b->range.start &&
               a->range.end == b->range.end &&
               a->range.exclusive == b->range.exclusive;
    default:
        return false;
    }
}
