#include "vex.h"
#include <dlfcn.h>
#include <stdarg.h>
#include <unistd.h>

#define MAX_PLUGINS 64
static void *loaded_plugins[MAX_PLUGINS];
static size_t n_plugins = 0;

#define MAX_PLUGIN_CMDS 256
typedef struct {
    char *name;
    VexPluginCommandFn fn;
    char *usage;
    char *description;
} PluginCmd;

static PluginCmd plugin_cmds[MAX_PLUGIN_CMDS];
static size_t n_plugin_cmds = 0;

static VexPluginAPI api;

static VexPluginCommandFn plugin_prompt_fn = NULL;
static VexPluginCommandFn plugin_rprompt_fn = NULL;

static VexShellStateProviderFn shell_state_provider = NULL;

static VexValue *api_new_null(void) { return vval_null(); }
static VexValue *api_new_bool(bool b) { return vval_bool(b); }
static VexValue *api_new_int(int64_t n) { return vval_int(n); }
static VexValue *api_new_float(double f) { return vval_float(f); }

static VexValue *api_new_string(const char *s, size_t len) {
    return vval_string(vstr_newn(s, len));
}

static VexValue *api_new_list(void) { return vval_list(); }
static VexValue *api_new_record(void) { return vval_record(); }
static VexValue *api_new_error(const char *msg) { return vval_error(msg); }

static int api_get_type(VexValue *v) {
    return v ? (int)v->type : (int)VEX_VAL_NULL;
}

static bool api_get_bool(VexValue *v) {
    return v && v->type == VEX_VAL_BOOL ? v->boolean : false;
}

static int64_t api_get_int(VexValue *v) {
    return v && v->type == VEX_VAL_INT ? v->integer : 0;
}

static double api_get_float(VexValue *v) {
    return v && v->type == VEX_VAL_FLOAT ? v->floating : 0.0;
}

static const char *api_get_string(VexValue *v, size_t *len_out) {
    if (!v || v->type != VEX_VAL_STRING) {
        if (len_out) *len_out = 0;
        return "";
    }
    if (len_out) *len_out = vstr_len(&v->string);
    return vstr_data(&v->string);
}

static size_t api_list_len(VexValue *v) {
    return (v && v->type == VEX_VAL_LIST) ? v->list.len : 0;
}

static VexValue *api_list_get(VexValue *v, size_t i) {
    return vval_list_get(v, i);
}

static VexValue *api_record_get(VexValue *v, const char *key) {
    return (v && v->type == VEX_VAL_RECORD) ? vval_record_get(v, key) : NULL;
}

static bool api_record_has(VexValue *v, const char *key) {
    return (v && v->type == VEX_VAL_RECORD) ? vval_record_has(v, key) : false;
}

static void api_list_push(VexValue *list, VexValue *item) {
    vval_list_push(list, item);
}

static void api_record_set(VexValue *rec, const char *key, VexValue *val) {
    vval_record_set(rec, key, val);
}

static VexValue *api_retain(VexValue *v) { return vval_retain(v); }
static void api_release(VexValue *v) { vval_release(v); }

static void api_register_command(const char *name, VexPluginCommandFn fn,
                                  const char *usage, const char *description) {
    if (n_plugin_cmds >= MAX_PLUGIN_CMDS) {
        fprintf(stderr, "vex: too many plugin commands\n");
        return;
    }
    plugin_cmds[n_plugin_cmds++] = (PluginCmd){
        .name = strdup(name),
        .fn = fn,
        .usage = strdup(usage ? usage : name),
        .description = strdup(description ? description : ""),
    };
}

static void api_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[plugin] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static void api_register_completion(const char *cmd, const char *const *words) {
    plugin_register_completion(cmd, words);
}

static void api_register_prompt(VexPluginCommandFn fn) {
    plugin_prompt_fn = fn;
}

static void api_register_rprompt(VexPluginCommandFn fn) {
    plugin_rprompt_fn = fn;
}

static VexValue *api_get_shell_state(void) {
    if (shell_state_provider) return shell_state_provider();
    return vval_record();
}

static void api_eval_string(void *ctx, const char *code) {
    EvalCtx *ectx = ctx;
    VexArena *saved_arena = ectx->arena;
    VexArena *tmp = arena_create();
    ectx->arena = tmp;
    Parser p = parser_init(code, tmp);
    for (;;) {
        ASTNode *stmt = parser_parse_line(&p);
        if (!stmt) break;
        if (p.had_error) break;
        VexValue *result = eval(ectx, stmt);
        vval_release(result);
    }
    ectx->arena = saved_arena;
    arena_destroy(tmp);
}

/* API v4 additions */
static VexValue *api_new_string_cstr(const char *s) {
    return vval_string_cstr(s);
}

static VexValue *api_record_keys(VexValue *rec) {
    if (!rec || rec->type != VEX_VAL_RECORD) return vval_list();
    VexValue *list = vval_list();
    VexMapIter it = vmap_iter(&rec->record);
    const char *key;
    void *val;
    while (vmap_next(&it, &key, &val)) {
        VexValue *k = vval_string_cstr(key);
        vval_list_push(list, k);
        vval_release(k);
    }
    return list;
}

static bool api_list_remove(VexValue *list, size_t i) {
    if (!list || list->type != VEX_VAL_LIST) return false;
    size_t len = vval_list_len(list);
    if (i >= len) return false;
    VexValue *item = vval_list_get(list, i);
    if (item) vval_release(item);
    for (size_t j = i; j + 1 < len; j++)
        list->list.data[j] = list->list.data[j + 1];
    list->list.len--;
    return true;
}

static bool api_record_remove(VexValue *rec, const char *key) {
    if (!rec || rec->type != VEX_VAL_RECORD) return false;
    return vmap_remove(&rec->record, key);
}

static const char *api_get_env(const char *name) {
    return getenv(name);
}

static void api_set_env(const char *name, const char *value) {
    if (value)
        setenv(name, value, 1);
    else
        unsetenv(name);
}

#define MAX_PLUGIN_HOOKS 32
static struct {
    char *event;
    VexPluginCommandFn fn;
} plugin_hooks[MAX_PLUGIN_HOOKS];
static size_t plugin_hook_count = 0;

static void api_register_hook(const char *event, VexPluginCommandFn fn) {
    if (plugin_hook_count < MAX_PLUGIN_HOOKS) {
        plugin_hooks[plugin_hook_count].event = strdup(event);
        plugin_hooks[plugin_hook_count].fn = fn;
        plugin_hook_count++;
    }
}

static VexValue *api_run_command(void *ctx, const char *cmd) {
    EvalCtx *ectx = ctx;
    VexArena *saved = ectx->arena;
    VexArena *tmp = arena_create();
    ectx->arena = tmp;
    Parser p = parser_init(cmd, tmp);
    VexValue *result = NULL;
    for (;;) {
        ASTNode *stmt = parser_parse_line(&p);
        if (!stmt || p.had_error) break;
        if (result) vval_release(result);
        result = eval(ectx, stmt);
    }
    ectx->arena = saved;
    arena_destroy(tmp);
    if (!result) return vval_null();
    return result;
}

static const char *api_get_cwd(void) {
    static char cwd[4096];
    if (getcwd(cwd, sizeof(cwd))) return cwd;
    return NULL;
}

static bool api_set_cwd(const char *path) {
    return chdir(path) == 0;
}

static size_t api_record_len(VexValue *rec) {
    if (!rec || rec->type != VEX_VAL_RECORD) return 0;
    size_t count = 0;
    VexMapIter it = vmap_iter(&rec->record);
    const char *key;
    void *val;
    while (vmap_next(&it, &key, &val)) count++;
    return count;
}

static VexValue *api_to_string(VexValue *v) {
    if (!v) return vval_string_cstr("null");
    VexStr s = vval_to_str(v);
    VexValue *result = vval_string(s);
    return result;
}

static void api_register_alias(const char *name, const char *expansion) {
    alias_register(name, expansion);
}

void plugin_api_init(void) {
    api = (VexPluginAPI){
        .api_version = VEX_PLUGIN_API_VERSION,

        .new_null    = api_new_null,
        .new_bool    = api_new_bool,
        .new_int     = api_new_int,
        .new_float   = api_new_float,
        .new_string  = api_new_string,
        .new_list    = api_new_list,
        .new_record  = api_new_record,
        .new_error   = api_new_error,

        .get_type    = api_get_type,
        .get_bool    = api_get_bool,
        .get_int     = api_get_int,
        .get_float   = api_get_float,
        .get_string  = api_get_string,
        .list_len    = api_list_len,
        .list_get    = api_list_get,
        .record_get  = api_record_get,
        .record_has  = api_record_has,

        .list_push   = api_list_push,
        .record_set  = api_record_set,

        .retain      = api_retain,
        .release     = api_release,

        .register_command = api_register_command,
        .log         = api_log,

        .register_completion = api_register_completion,
        .eval_string = api_eval_string,

        .register_prompt  = api_register_prompt,
        .register_rprompt = api_register_rprompt,
        .get_shell_state  = api_get_shell_state,

        .new_string_cstr = api_new_string_cstr,
        .record_keys     = api_record_keys,
        .list_remove     = api_list_remove,
        .record_remove   = api_record_remove,
        .get_env         = api_get_env,
        .set_env         = api_set_env,
        .register_hook   = api_register_hook,

        .run_command     = api_run_command,
        .get_cwd         = api_get_cwd,
        .set_cwd         = api_set_cwd,
        .record_len      = api_record_len,
        .to_string       = api_to_string,
        .register_alias  = api_register_alias,
    };
}

bool plugin_load(const char *path) {

    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);

    if (!handle) {

        const char *home = getenv("HOME");
        if (home) {
            char fullpath[4096];
            snprintf(fullpath, sizeof(fullpath),
                     "%s/.local/share/vex/plugins/%s", home, path);
            handle = dlopen(fullpath, RTLD_NOW | RTLD_LOCAL);

            if (!handle) {

                snprintf(fullpath, sizeof(fullpath),
                         "%s/.local/share/vex/plugins/%s.so", home, path);
                handle = dlopen(fullpath, RTLD_NOW | RTLD_LOCAL);
            }
            if (!handle) {

                snprintf(fullpath, sizeof(fullpath),
                         "%s/.local/share/vex/plugins/lib%s.so", home, path);
                handle = dlopen(fullpath, RTLD_NOW | RTLD_LOCAL);
            }
        }
    }

    if (!handle) {
        vex_err("plugin: cannot load '%s': %s", path, dlerror());
        return false;
    }

    uint32_t *plugin_ver = (uint32_t *)dlsym(handle, "vex_plugin_api_version");
    if (!plugin_ver) {
        vex_err("plugin: '%s' missing vex_plugin_api_version symbol "
                "(expected %u)", path, (unsigned)VEX_PLUGIN_API_VERSION);
        dlclose(handle);
        return false;
    }
    if (*plugin_ver != VEX_PLUGIN_API_VERSION) {
        vex_err("plugin: '%s' api version mismatch: plugin=%u vex=%u",
                path, (unsigned)*plugin_ver,
                (unsigned)VEX_PLUGIN_API_VERSION);
        dlclose(handle);
        return false;
    }

    VexPluginInitFn init_fn;
    *(void **)&init_fn = dlsym(handle, "vex_plugin_init");
    if (!init_fn) {
        vex_err("plugin: '%s' has no vex_plugin_init symbol", path);
        dlclose(handle);
        return false;
    }

    if (n_plugins >= MAX_PLUGINS) {
        vex_err("plugin: '%s' rejected: plugin table full (max %d)",
                path, MAX_PLUGINS);
        dlclose(handle);
        return false;
    }
    loaded_plugins[n_plugins++] = handle;

    init_fn(&api);

    return true;
}

bool plugin_cmd_exists(const char *name) {
    for (size_t i = 0; i < n_plugin_cmds; i++) {
        if (strcmp(plugin_cmds[i].name, name) == 0)
            return true;
    }
    return false;
}

VexValue *plugin_cmd_exec(const char *name, VexValue *input,
                           VexValue **args, size_t argc) {
    for (size_t i = 0; i < n_plugin_cmds; i++) {
        if (strcmp(plugin_cmds[i].name, name) == 0) {
            return plugin_cmds[i].fn(&api, input, args, argc);
        }
    }
    return vval_error("plugin command not found");
}

size_t plugin_cmd_count(void) {
    return n_plugin_cmds;
}

const char *plugin_cmd_name(size_t i) {
    return i < n_plugin_cmds ? plugin_cmds[i].name : NULL;
}

void plugin_cleanup(void) {
    for (size_t i = 0; i < n_plugins; i++) {
        dlclose(loaded_plugins[i]);
    }
    n_plugins = 0;

    for (size_t i = 0; i < n_plugin_cmds; i++) {
        free(plugin_cmds[i].name);
        free(plugin_cmds[i].usage);
        free(plugin_cmds[i].description);
    }
    n_plugin_cmds = 0;
    plugin_prompt_fn = NULL;
    plugin_rprompt_fn = NULL;
}

char *plugin_prompt_eval(void) {
    if (!plugin_prompt_fn) return NULL;
    VexValue *result = plugin_prompt_fn(&api, NULL, NULL, 0);
    if (!result || result->type != VEX_VAL_STRING) {
        vval_release(result);
        return NULL;
    }
    char *str = strdup(vstr_data(&result->string));
    vval_release(result);
    return str;
}

char *plugin_rprompt_eval(void) {
    if (!plugin_rprompt_fn) return NULL;
    VexValue *result = plugin_rprompt_fn(&api, NULL, NULL, 0);
    if (!result || result->type != VEX_VAL_STRING) {
        vval_release(result);
        return NULL;
    }
    char *str = strdup(vstr_data(&result->string));
    vval_release(result);
    return str;
}

void plugin_set_state_provider(VexShellStateProviderFn fn) {
    shell_state_provider = fn;
}
