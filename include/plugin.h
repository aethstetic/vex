#ifndef VEX_PLUGIN_H
#define VEX_PLUGIN_H

#define VEX_PLUGIN_API_VERSION 3

typedef VexValue *(*VexPluginCommandFn)(void *api, VexValue *input,
                                        VexValue **args, size_t argc);

/* Vtable passed to plugins so they can create values and register commands. */
typedef struct VexPluginAPI {
    uint32_t api_version;

    VexValue *(*new_null)(void);
    VexValue *(*new_bool)(bool b);
    VexValue *(*new_int)(int64_t n);
    VexValue *(*new_float)(double f);
    VexValue *(*new_string)(const char *s, size_t len);
    VexValue *(*new_list)(void);
    VexValue *(*new_record)(void);
    VexValue *(*new_error)(const char *msg);

    int       (*get_type)(VexValue *v);
    bool      (*get_bool)(VexValue *v);
    int64_t   (*get_int)(VexValue *v);
    double    (*get_float)(VexValue *v);
    const char *(*get_string)(VexValue *v, size_t *len_out);
    size_t    (*list_len)(VexValue *v);
    VexValue *(*list_get)(VexValue *v, size_t i);
    VexValue *(*record_get)(VexValue *v, const char *key);
    bool      (*record_has)(VexValue *v, const char *key);

    void      (*list_push)(VexValue *list, VexValue *item);
    void      (*record_set)(VexValue *rec, const char *key, VexValue *val);

    VexValue *(*retain)(VexValue *v);
    void      (*release)(VexValue *v);

    void (*register_command)(const char *name, VexPluginCommandFn fn,
                             const char *usage, const char *description);

    void (*log)(const char *fmt, ...);

    /* API v2 additions */
    void (*register_completion)(const char *cmd, const char *const *words);
    void (*eval_string)(void *ctx, const char *code);

    /* API v3 additions */
    void (*register_prompt)(VexPluginCommandFn fn);
    void (*register_rprompt)(VexPluginCommandFn fn);
    VexValue *(*get_shell_state)(void);
} VexPluginAPI;

typedef void (*VexPluginInitFn)(VexPluginAPI *api);

bool plugin_load(const char *path);

void plugin_api_init(void);

bool plugin_cmd_exists(const char *name);

VexValue *plugin_cmd_exec(const char *name, VexValue *input,
                           VexValue **args, size_t argc);

size_t plugin_cmd_count(void);
const char *plugin_cmd_name(size_t i);

void plugin_cleanup(void);

/* Plugin prompt support */
char *plugin_prompt_eval(void);
char *plugin_rprompt_eval(void);

/* Shell state provider (set by main.c) */
typedef VexValue *(*VexShellStateProviderFn)(void);
void plugin_set_state_provider(VexShellStateProviderFn fn);

#endif
