#include "vex.h"

Scope *scope_new(Scope *parent) {
    Scope *s = calloc(1, sizeof(Scope));
    s->bindings = vmap_new();
    s->parent = parent;
    s->is_function_scope = false;
    return s;
}

void scope_free(Scope *s) {
    if (!s) return;

    VexMapIter it = vmap_iter(&s->bindings);
    const char *key;
    void *val;
    while (vmap_next(&it, &key, &val)) {
        vval_release(val);
    }
    vmap_free(&s->bindings);
    free(s);
}

void scope_set(Scope *s, const char *name, VexValue *val) {
    VexValue *old = vmap_get(&s->bindings, name);
    if (old) vval_release(old);
    vmap_set(&s->bindings, name, vval_retain(val));
}

VexValue *scope_get(Scope *s, const char *name) {
    while (s) {
        VexValue *v = vmap_get(&s->bindings, name);
        if (v) return v;
        s = s->parent;
    }
    return NULL;
}

bool scope_has(Scope *s, const char *name) {
    return scope_get(s, name) != NULL;
}

bool scope_update(Scope *s, const char *name, VexValue *val) {
    while (s) {
        if (vmap_has(&s->bindings, name)) {
            VexValue *old = vmap_get(&s->bindings, name);
            if (old) vval_release(old);
            vmap_set(&s->bindings, name, vval_retain(val));
            return true;
        }
        s = s->parent;
    }
    return false;
}

bool scope_del(Scope *s, const char *name) {
    while (s) {
        if (vmap_has(&s->bindings, name)) {
            VexValue *old = vmap_remove(&s->bindings, name);
            if (old) vval_release(old);
            return true;
        }
        s = s->parent;
    }
    return false;
}
