#ifndef VEX_ENV_H
#define VEX_ENV_H

struct Scope {
    VexMap bindings;
    Scope *parent;
    bool is_function_scope;
};

Scope   *scope_new(Scope *parent);
void     scope_free(Scope *s);
void     scope_set(Scope *s, const char *name, VexValue *val);
VexValue *scope_get(Scope *s, const char *name);
bool     scope_has(Scope *s, const char *name);

bool     scope_update(Scope *s, const char *name, VexValue *val);

bool     scope_del(Scope *s, const char *name);

#endif
