#include "vex.h"
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <signal.h>
#include <limits.h>

#ifndef __APPLE__
extern char *realpath(const char *path, char *resolved_path);
#endif
#include <time.h>
#include <math.h>
#include <ctype.h>
#include <fnmatch.h>
#include <strings.h>
#include <sys/time.h>
#include <termios.h>
#include <libgen.h>
#include <limits.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/wait.h>

static BuiltinCmd builtins_table[512];
static size_t builtins_count = 0;

#define BUILTIN_HT_SIZE 1024
static struct {
    const char *key;
    size_t idx;
} builtin_ht[BUILTIN_HT_SIZE];
static bool builtin_ht_ready = false;

/* FNV-1a */
static uint32_t fnv1a(const char *s) {
    uint32_t h = 2166136261u;
    for (; *s; s++)
        h = (h ^ (unsigned char)*s) * 16777619u;
    return h;
}

static void builtin_ht_build(void) {
    memset(builtin_ht, 0, sizeof(builtin_ht));
    for (size_t i = 0; i < builtins_count; i++) {
        uint32_t slot = fnv1a(builtins_table[i].name) & (BUILTIN_HT_SIZE - 1);
        while (builtin_ht[slot].key)
            slot = (slot + 1) & (BUILTIN_HT_SIZE - 1);
        builtin_ht[slot].key = builtins_table[i].name;
        builtin_ht[slot].idx = i;
    }
    builtin_ht_ready = true;
}

static VexValue *fallback_external(EvalCtx *ctx, const char *cmd, VexValue **args, size_t argc);
static bool has_flag_args(VexValue **args, size_t argc);

static bool is_sh_file(const char *path);
static bool has_sh_shebang(const char *path);
VexValue *source_sh_file(EvalCtx *ctx, const char *path);

#define MAX_SCRIPT_CMDS 256
typedef struct {
    char *name;
    char *usage;
    char *description;
    VexValue *closure;
} ScriptCmd;

static ScriptCmd script_cmds[MAX_SCRIPT_CMDS];
static size_t n_script_cmds = 0;

#define MAX_HOOKS 32
typedef struct {
    VexValue *hooks[MAX_HOOKS];
    size_t count;
} HookList;

static HookList hook_preexec = {.count = 0};
static HookList hook_precmd  = {.count = 0};
static HookList hook_chpwd   = {.count = 0};

static VexValue *prompt_closure = NULL;
static VexValue *rprompt_closure = NULL;

static bool hook_add(HookList *h, VexValue *closure) {
    if (h->count >= MAX_HOOKS) return false;
    h->hooks[h->count++] = vval_retain(closure);
    return true;
}

static void hook_remove(HookList *h, size_t index) {
    if (index >= h->count) return;
    vval_release(h->hooks[index]);
    for (size_t i = index; i + 1 < h->count; i++)
        h->hooks[i] = h->hooks[i + 1];
    h->count--;
}

void hooks_run_preexec(EvalCtx *ctx, const char *cmd) {
    for (size_t i = 0; i < hook_preexec.count; i++) {
        VexValue *arg = vval_string_cstr(cmd);
        VexValue *result = eval_call_closure(ctx, hook_preexec.hooks[i], &arg, 1);
        vval_release(result);
        vval_release(arg);
    }
}

void hooks_run_precmd(EvalCtx *ctx) {
    for (size_t i = 0; i < hook_precmd.count; i++) {
        VexValue *result = eval_call_closure(ctx, hook_precmd.hooks[i], NULL, 0);
        vval_release(result);
    }
}

void hooks_run_chpwd(EvalCtx *ctx) {
    for (size_t i = 0; i < hook_chpwd.count; i++) {
        VexValue *result = eval_call_closure(ctx, hook_chpwd.hooks[i], NULL, 0);
        vval_release(result);
    }
}

VexValue *builtin_prompt_fn(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_CLOSURE)
        return vval_error("prompt-fn requires a closure argument");
    if (prompt_closure) vval_release(prompt_closure);
    prompt_closure = vval_retain(args[0]);
    return vval_null();
}

VexValue *builtin_rprompt_fn(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_CLOSURE)
        return vval_error("rprompt-fn requires a closure argument");
    if (rprompt_closure) vval_release(rprompt_closure);
    rprompt_closure = vval_retain(args[0]);
    return vval_null();
}

char *prompt_fn_eval(EvalCtx *ctx) {
    if (!prompt_closure) return NULL;
    VexValue *result = eval_call_closure(ctx, prompt_closure, NULL, 0);
    if (!result || result->type != VEX_VAL_STRING) {
        vval_release(result);
        return NULL;
    }
    char *str = strdup(vstr_data(&result->string));
    vval_release(result);
    return str;
}

char *rprompt_fn_eval(EvalCtx *ctx) {
    if (!rprompt_closure) return NULL;
    VexValue *result = eval_call_closure(ctx, rprompt_closure, NULL, 0);
    if (!result || result->type != VEX_VAL_STRING) {
        vval_release(result);
        return NULL;
    }
    char *str = strdup(vstr_data(&result->string));
    vval_release(result);
    return str;
}

VexValue *builtin_hook_add(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 2) return vval_error("hook-add requires event name and closure");
    if (args[0]->type != VEX_VAL_STRING) return vval_error("event must be a string");
    if (args[1]->type != VEX_VAL_CLOSURE) return vval_error("handler must be a closure");

    const char *event = vstr_data(&args[0]->string);
    bool ok = false;
    if (strcmp(event, "preexec") == 0)
        ok = hook_add(&hook_preexec, args[1]);
    else if (strcmp(event, "precmd") == 0)
        ok = hook_add(&hook_precmd, args[1]);
    else if (strcmp(event, "chpwd") == 0)
        ok = hook_add(&hook_chpwd, args[1]);
    else
        return vval_error("unknown hook event");

    if (!ok) return vval_error("hook-add: too many hooks (max 32)");
    return vval_null();
}

VexValue *builtin_hook_remove(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1) return vval_error("hook-remove requires event name");
    if (args[0]->type != VEX_VAL_STRING) return vval_error("event must be a string");

    const char *event = vstr_data(&args[0]->string);
    HookList *h = NULL;
    if (strcmp(event, "preexec") == 0)
        h = &hook_preexec;
    else if (strcmp(event, "precmd") == 0)
        h = &hook_precmd;
    else if (strcmp(event, "chpwd") == 0)
        h = &hook_chpwd;
    else
        return vval_error("unknown hook event");

    if (argc >= 2) {
        if (args[1]->type != VEX_VAL_INT)
            return vval_error("index must be an integer");
        int64_t idx = args[1]->integer;
        if (idx < 0 || (size_t)idx >= h->count)
            return vval_error("hook index out of range");
        hook_remove(h, (size_t)idx);
    } else {
        while (h->count > 0)
            hook_remove(h, h->count - 1);
    }

    return vval_null();
}

VexValue *builtin_hook_list(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    VexValue *result = vval_list();

    for (size_t i = 0; i < hook_preexec.count; i++) {
        VexValue *rec = vval_record();
        VexValue *tmp = vval_string_cstr("preexec");
        vval_record_set(rec, "event", tmp);
        vval_release(tmp);
        tmp = vval_int((int64_t)i);
        vval_record_set(rec, "index", tmp);
        vval_release(tmp);
        vval_list_push(result, rec);
        vval_release(rec);
    }
    for (size_t i = 0; i < hook_precmd.count; i++) {
        VexValue *rec = vval_record();
        VexValue *tmp = vval_string_cstr("precmd");
        vval_record_set(rec, "event", tmp);
        vval_release(tmp);
        tmp = vval_int((int64_t)i);
        vval_record_set(rec, "index", tmp);
        vval_release(tmp);
        vval_list_push(result, rec);
        vval_release(rec);
    }
    for (size_t i = 0; i < hook_chpwd.count; i++) {
        VexValue *rec = vval_record();
        VexValue *tmp = vval_string_cstr("chpwd");
        vval_record_set(rec, "event", tmp);
        vval_release(tmp);
        tmp = vval_int((int64_t)i);
        vval_record_set(rec, "index", tmp);
        vval_release(tmp);
        vval_list_push(result, rec);
        vval_release(rec);
    }

    return result;
}

VexValue *builtin_def_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 2) return vval_error("def-cmd: expected name and closure");
    if (args[0]->type != VEX_VAL_STRING) return vval_error("def-cmd: name must be a string");

    const char *name = vstr_data(&args[0]->string);
    VexValue *closure = NULL;
    const char *usage = name;
    const char *desc = "";

    if (argc == 2) {
        if (args[1]->type != VEX_VAL_CLOSURE) return vval_error("def-cmd: second arg must be a closure");
        closure = args[1];
    } else if (argc == 3) {
        if (args[1]->type != VEX_VAL_STRING) return vval_error("def-cmd: usage must be a string");
        if (args[2]->type != VEX_VAL_CLOSURE) return vval_error("def-cmd: third arg must be a closure");
        usage = vstr_data(&args[1]->string);
        closure = args[2];
    } else {
        if (args[1]->type != VEX_VAL_STRING) return vval_error("def-cmd: usage must be a string");
        if (args[2]->type != VEX_VAL_STRING) return vval_error("def-cmd: description must be a string");
        if (args[3]->type != VEX_VAL_CLOSURE) return vval_error("def-cmd: fourth arg must be a closure");
        usage = vstr_data(&args[1]->string);
        desc = vstr_data(&args[2]->string);
        closure = args[3];
    }

    for (size_t i = 0; i < n_script_cmds; i++) {
        if (strcmp(script_cmds[i].name, name) == 0) {
            vval_release(script_cmds[i].closure);
            script_cmds[i].closure = vval_retain(closure);
            free(script_cmds[i].usage);
            free(script_cmds[i].description);
            script_cmds[i].usage = strdup(usage);
            script_cmds[i].description = strdup(desc);
            return vval_null();
        }
    }

    if (n_script_cmds >= MAX_SCRIPT_CMDS) return vval_error("def-cmd: too many script commands");

    script_cmds[n_script_cmds++] = (ScriptCmd){
        .name = strdup(name),
        .usage = strdup(usage),
        .description = strdup(desc),
        .closure = vval_retain(closure),
    };
    return vval_null();
}

bool script_cmd_exists(const char *name) {
    for (size_t i = 0; i < n_script_cmds; i++) {
        if (strcmp(script_cmds[i].name, name) == 0)
            return true;
    }
    return false;
}

VexValue *script_cmd_get_closure(const char *name) {
    for (size_t i = 0; i < n_script_cmds; i++) {
        if (strcmp(script_cmds[i].name, name) == 0)
            return script_cmds[i].closure;
    }
    return NULL;
}

size_t script_cmd_count(void) { return n_script_cmds; }

const char *script_cmd_name(size_t i) {
    return i < n_script_cmds ? script_cmds[i].name : NULL;
}

const char *script_cmd_description(size_t i) {
    return i < n_script_cmds ? script_cmds[i].description : NULL;
}

#define DIR_STACK_MAX 64
static char *dir_stack[DIR_STACK_MAX];
static size_t dir_stack_count = 0;

static void register_builtin(const char *name, BuiltinFn fn,
                              const char *usage, const char *desc) {
    builtins_table[builtins_count++] = (BuiltinCmd){name, fn, usage, desc};
}

VexValue *builtin_echo(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (has_flag_args(args, argc))
        return fallback_external(ctx, "echo", args, argc);

    VexStr out = vstr_empty();
    for (size_t i = 0; i < argc; i++) {
        if (i > 0) vstr_append_char(&out, ' ');
        VexStr s = vval_to_str(args[i]);
        vstr_append_str(&out, &s);
        vstr_free(&s);
    }
    if (!ctx->in_pipeline) {
        printf("%s\n", vstr_data(&out));
    }
    return vval_string(out);
}

VexValue *builtin_cd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    const char *dir;
    if (argc == 0) {
        dir = getenv("HOME");
        if (!dir) {
            vex_err("cd: HOME not set");
            return vval_error("HOME not set");
        }
    } else {
        if (args[0]->type != VEX_VAL_STRING) {
            vex_err("cd: expected string argument");
            return vval_error("expected string");
        }
        dir = vstr_data(&args[0]->string);
    }

    char expanded[4096];
    if (dir[0] == '~') {
        const char *home = getenv("HOME");
        if (home) {
            if (dir[1] == '\0') {
                dir = home;
            } else if (dir[1] == '/') {
                snprintf(expanded, sizeof(expanded), "%s%s", home, dir + 1);
                dir = expanded;
            }
        }
    }

    if (chdir(dir) != 0) {

        const char *cdpath = getenv("CDPATH");
        bool found = false;
        if (cdpath && dir[0] != '/' && dir[0] != '.') {
            char *paths = strdup(cdpath);
            char *entry = strtok(paths, ":");
            while (entry) {
                char full[4096];
                snprintf(full, sizeof(full), "%s/%s", entry, dir);
                if (chdir(full) == 0) {
                    char cwd[4096];
                    if (getcwd(cwd, sizeof(cwd))) {
                        printf("%s\n", cwd);
                        frecency_add(cwd);
                    }
                    found = true;
                    break;
                }
                entry = strtok(NULL, ":");
            }
            free(paths);
        }
        if (!found) {
            /* Frecency fallback */
            char *fpath = frecency_find(dir);
            if (fpath && chdir(fpath) == 0) {
                frecency_add(fpath);
                free(fpath);
                hooks_run_chpwd(ctx);
                return vval_null();
            }
            free(fpath);
            vex_err("cd: %s: No such file or directory", dir);
            ctx->had_error = true;
            return vval_error("No such file or directory");
        }
    } else {

        char cwd[4096];
        if (getcwd(cwd, sizeof(cwd))) frecency_add(cwd);
    }
    hooks_run_chpwd(ctx);
    return vval_null();
}

static VexValue *dirs_print(EvalCtx *ctx) {
    char cwd[4096];
    if (!getcwd(cwd, sizeof(cwd))) {
        return vval_error("getcwd failed");
    }
    VexValue *list = vval_list();
    VexValue *tv = vval_string(vstr_new(cwd));
    vval_list_push(list, tv);
    vval_release(tv);
    for (size_t i = dir_stack_count; i > 0; i--) {
        tv = vval_string(vstr_new(dir_stack[i - 1]));
        vval_list_push(list, tv);
        vval_release(tv);
    }
    if (!ctx->in_pipeline) {
        printf("%s", cwd);
        for (size_t i = dir_stack_count; i > 0; i--) {
            printf(" %s", dir_stack[i - 1]);
        }
        printf("\n");
    }
    return list;
}

VexValue *builtin_pushd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    char cwd[4096];
    if (!getcwd(cwd, sizeof(cwd))) {
        vex_err("pushd: getcwd failed");
        return vval_error("getcwd failed");
    }

    if (argc == 0) {

        if (dir_stack_count == 0) {
            vex_err("pushd: no other directory");
            ctx->had_error = true;
            return vval_error("no other directory");
        }
        char *top = dir_stack[dir_stack_count - 1];
        if (chdir(top) != 0) {
            vex_err("pushd: %s: %s", top, strerror(errno));
            ctx->had_error = true;
            return vval_error(strerror(errno));
        }
        free(dir_stack[dir_stack_count - 1]);
        dir_stack[dir_stack_count - 1] = strdup(cwd);
    } else {

        if (args[0]->type != VEX_VAL_STRING) {
            vex_err("pushd: expected string argument");
            return vval_error("expected string");
        }
        const char *dir = vstr_data(&args[0]->string);
        if (dir_stack_count >= DIR_STACK_MAX) {
            vex_err("pushd: directory stack full");
            ctx->had_error = true;
            return vval_error("directory stack full");
        }
        if (chdir(dir) != 0) {
            vex_err("pushd: %s: %s", dir, strerror(errno));
            ctx->had_error = true;
            return vval_error(strerror(errno));
        }
        dir_stack[dir_stack_count++] = strdup(cwd);
    }

    char newcwd[4096];
    if (getcwd(newcwd, sizeof(newcwd))) frecency_add(newcwd);
    hooks_run_chpwd(ctx);
    return dirs_print(ctx);
}

VexValue *builtin_popd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input; (void)args; (void)argc;
    if (dir_stack_count == 0) {
        vex_err("popd: directory stack empty");
        ctx->had_error = true;
        return vval_error("directory stack empty");
    }
    char *top = dir_stack[--dir_stack_count];
    if (chdir(top) != 0) {
        vex_err("popd: %s: %s", top, strerror(errno));
        ctx->had_error = true;

        dir_stack[dir_stack_count++] = top;
        return vval_error(strerror(errno));
    }
    free(top);

    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd))) frecency_add(cwd);
    hooks_run_chpwd(ctx);
    return dirs_print(ctx);
}

VexValue *builtin_dirs(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input; (void)args; (void)argc;
    return dirs_print(ctx);
}

static volatile bool vex_exit_requested = false;
static int vex_exit_code = 0;

bool vex_should_exit(void) { return vex_exit_requested; }
int vex_get_exit_code(void) { return vex_exit_code; }

VexValue *builtin_exit(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    vex_exit_code = 0;
    if (argc > 0 && args[0]->type == VEX_VAL_INT) {
        vex_exit_code = (int)args[0]->integer;
    }
    vex_exit_requested = true;
    return vval_null();
}

VexValue *builtin_pwd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    char buf[4096];
    if (getcwd(buf, sizeof(buf))) {
        VexValue *v = vval_string_cstr(buf);
        vval_print(v, stdout);
        printf("\n");
        return v;
    }
    return vval_error("pwd failed");
}

VexValue *builtin_env(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    extern char **environ;
    VexValue *rec = vval_record();
    for (int i = 0; environ[i]; i++) {
        char *eq = strchr(environ[i], '=');
        if (eq) {
            char key[256];
            size_t klen = (size_t)(eq - environ[i]);
            if (klen >= sizeof(key)) klen = sizeof(key) - 1;
            memcpy(key, environ[i], klen);
            key[klen] = '\0';
            VexValue *val = vval_string_cstr(eq + 1);
            vval_record_set(rec, key, val);
            vval_release(val);
        }
    }
    vval_print(rec, stdout);
    printf("\n");
    return rec;
}

static const char *file_type_str(mode_t mode) {
    if (S_ISDIR(mode)) return "dir";
    if (S_ISLNK(mode)) return "symlink";
    if (S_ISREG(mode)) return "file";
    return "other";
}

static const char *format_size(off_t size, char *buf, size_t buflen) {
    if (size >= 1073741824)
        snprintf(buf, buflen, "%.1f GB", (double)size / 1073741824.0);
    else if (size >= 1048576)
        snprintf(buf, buflen, "%.1f MB", (double)size / 1048576.0);
    else if (size >= 1024)
        snprintf(buf, buflen, "%.1f KB", (double)size / 1024.0);
    else
        snprintf(buf, buflen, "%ld B", (long)size);
    return buf;
}

static VexValue *fallback_external(EvalCtx *ctx, const char *cmd, VexValue **args, size_t argc) {
    char **argv = malloc((argc + 2) * sizeof(char *));
    if (!argv) return vval_error("out of memory");
    VexStr *strs = malloc(argc * sizeof(VexStr));
    if (!strs) { free(argv); return vval_error("out of memory"); }
    argv[0] = (char *)cmd;
    for (size_t i = 0; i < argc; i++) {
        strs[i] = vval_to_str(args[i]);
        argv[i + 1] = (char *)vstr_data(&strs[i]);
    }
    argv[argc + 1] = NULL;

    int status = exec_external(cmd, argv, -1, -1);
    ctx->last_exit_code = status;
    for (size_t i = 0; i < argc; i++)
        vstr_free(&strs[i]);
    free(strs);
    free(argv);
    return vval_null();
}

static bool has_flag_args(VexValue **args, size_t argc) {
    for (size_t i = 0; i < argc; i++) {
        if (args[i]->type == VEX_VAL_STRING) {
            const char *s = vstr_data(&args[i]->string);
            size_t len = vstr_len(&args[i]->string);
            if (len >= 2 && s[0] == '-') {
                /* Short flags: -l, -la */
                if (len <= 3) {
                    bool all_alpha = true;
                    for (size_t j = 1; j < len; j++) {
                        if (!((s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z'))) {
                            all_alpha = false;
                            break;
                        }
                    }
                    if (all_alpha) return true;
                }
                /* Long flags: --help, --version, --color=always */
                if (len >= 3 && s[1] == '-') return true;
            }
        }
    }
    return false;
}

VexValue *builtin_ls(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;

    if (has_flag_args(args, argc))
        return fallback_external(ctx, "ls", args, argc);
    const char *path = ".";
    if (argc > 0 && args[0]->type == VEX_VAL_STRING) {
        path = vstr_data(&args[0]->string);
    }

    DIR *d = opendir(path);
    if (!d) {
        vex_err("ls: %s: %s", path, strerror(errno));
        return vval_error(strerror(errno));
    }

    VexValue *list = vval_list();
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char fullpath[4096];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", path, ent->d_name);

        struct stat st;
        if (stat(fullpath, &st) != 0) continue;

        VexValue *rec = vval_record();
        VexValue *name = vval_string_cstr(ent->d_name);
        VexValue *type = vval_string_cstr(file_type_str(st.st_mode));
        VexValue *size = vval_int(st.st_size);

        char timebuf[64];
        struct tm *tm = localtime(&st.st_mtime);
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M", tm);
        VexValue *modified = vval_string_cstr(timebuf);

        vval_record_set(rec, "name", name);
        vval_record_set(rec, "type", type);
        vval_record_set(rec, "size", size);
        vval_record_set(rec, "modified", modified);

        vval_release(name);
        vval_release(type);
        vval_release(size);
        vval_release(modified);

        vval_list_push(list, rec);
        vval_release(rec);
    }
    closedir(d);

    for (size_t i = 0; i < list->list.len; i++) {
        for (size_t k = i + 1; k < list->list.len; k++) {
            VexValue *a = list->list.data[i];
            VexValue *b = list->list.data[k];
            VexValue *sa = vval_record_get(a, "size");
            VexValue *sb = vval_record_get(b, "size");
            if (sa && sb && sb->integer > sa->integer) {
                list->list.data[i] = b;
                list->list.data[k] = a;
            }
        }
    }

    if (!ctx->in_pipeline) {
        size_t name_w = 4;
        size_t size_w = 4;
        char **size_strs = malloc(list->list.len * sizeof(char *));
        for (size_t i = 0; i < list->list.len; i++) {
            VexValue *rec = list->list.data[i];
            VexValue *n = vval_record_get(rec, "name");
            VexValue *sv = vval_record_get(rec, "size");
            if (n) {
                size_t w = strlen(vstr_data(&n->string));
                if (w > name_w) name_w = w;
            }
            size_strs[i] = malloc(32);
            format_size(sv ? sv->integer : 0, size_strs[i], 32);
            size_t sw = strlen(size_strs[i]);
            if (sw > size_w) size_w = sw;
        }
        name_w += 2;

        printf("\033[1m%-*s %-6s %*s  %-16s\033[0m\n",
               (int)name_w, "name", "type", (int)size_w, "size", "modified");
        for (size_t i = 0; i < list->list.len; i++) {
            VexValue *rec = list->list.data[i];
            VexValue *name = vval_record_get(rec, "name");
            VexValue *type = vval_record_get(rec, "type");
            VexValue *mod = vval_record_get(rec, "modified");

            const char *type_str = vstr_data(&type->string);
            bool is_dir = strcmp(type_str, "dir") == 0;

            if (is_dir)
                printf("\033[1;34m%-*s\033[0m ", (int)name_w, vstr_data(&name->string));
            else
                printf("%-*s ", (int)name_w, vstr_data(&name->string));

            printf("%-6s %*s  %-16s\n",
                   type_str,
                   (int)size_w, size_strs[i],
                   vstr_data(&mod->string));
            free(size_strs[i]);
        }
        free(size_strs);
    }

    return ctx->in_pipeline ? list : vval_null();
}

VexValue *builtin_which(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc == 0) {
        vex_err("which: missing argument");
        return vval_error("missing argument");
    }
    const char *name = vstr_data(&args[0]->string);

    if (builtin_exists(name)) {
        VexStr s = vstr_fmt("builtin: %s", name);
        VexValue *v = vval_string(s);
        vval_print(v, stdout);
        printf("\n");
        return v;
    }

    char *path = find_in_path(name);
    if (path) {
        VexValue *v = vval_string_cstr(path);
        vval_print(v, stdout);
        printf("\n");
        free(path);
        return v;
    }

    vex_err("which: %s not found", name);
    return vval_error("not found");
}

VexValue *builtin_type_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    VexValue *v = NULL;
    if (argc > 0)
        v = args[0];
    else if (input)
        v = input;
    else
        return vval_error("missing argument");
    printf("%s\n", vval_type_name(v->type));
    return vval_string_cstr(vval_type_name(v->type));
}

VexValue *builtin_where(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST) {
        vex_err("where: expected list input from pipeline");
        return vval_null();
    }

    VexValue *result = vval_list();

    if (argc == 1 && args[0]->type == VEX_VAL_CLOSURE) {
        for (size_t i = 0; i < input->list.len; i++) {
            VexValue *row = input->list.data[i];
            VexValue *call_args[1] = { row };
            VexValue *pred = eval_call_closure(ctx, args[0], call_args, 1);
            if (vval_truthy(pred)) {
                vval_list_push(result, row);
            }
            vval_release(pred);
        }
        return result;
    }

    if (argc == 2 && args[0]->type == VEX_VAL_STRING) {
        const char *field = vstr_data(&args[0]->string);
        for (size_t i = 0; i < input->list.len; i++) {
            VexValue *row = input->list.data[i];
            if (row->type != VEX_VAL_RECORD) continue;
            VexValue *fv = vval_record_get(row, field);
            if (!fv) continue;

            bool match = false;
            if (fv->type == args[1]->type) {
                if (fv->type == VEX_VAL_STRING)
                    match = vstr_eq(&fv->string, &args[1]->string);
                else if (fv->type == VEX_VAL_INT)
                    match = fv->integer == args[1]->integer;
                else if (fv->type == VEX_VAL_BOOL)
                    match = fv->boolean == args[1]->boolean;
            }
            if (match) vval_list_push(result, row);
        }
        return result;
    }

    if (argc == 1 && args[0]->type == VEX_VAL_BOOL) {
        if (args[0]->boolean) {
            vval_release(result);
            return vval_retain(input);
        }
        return result;
    }

    vex_err("where: use closure form: where { |row| row.field == value }");
    vval_release(result);
    return vval_retain(input);
}

VexValue *builtin_first(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("first: expected list input");
    if (input->list.len == 0) return vval_null();

    size_t n = 1;
    if (argc > 0 && args[0]->type == VEX_VAL_INT)
        n = (size_t)args[0]->integer;

    if (n == 1) return vval_retain(input->list.data[0]);

    VexValue *list = vval_list();
    for (size_t i = 0; i < n && i < input->list.len; i++) {
        vval_list_push(list, input->list.data[i]);
    }
    return list;
}

VexValue *builtin_last(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("last: expected list input");
    if (input->list.len == 0) return vval_null();

    size_t n = 1;
    if (argc > 0 && args[0]->type == VEX_VAL_INT)
        n = (size_t)args[0]->integer;

    if (n == 1) return vval_retain(input->list.data[input->list.len - 1]);

    VexValue *list = vval_list();
    size_t start = input->list.len > n ? input->list.len - n : 0;
    for (size_t i = start; i < input->list.len; i++) {
        vval_list_push(list, input->list.data[i]);
    }
    return list;
}

VexValue *builtin_get(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (argc == 0 || !input) return vval_null();

    if (args[0]->type == VEX_VAL_INT) {
        if (input->type == VEX_VAL_LIST) {
            int64_t idx = args[0]->integer;
            size_t len = vval_list_len(input);
            if (idx < 0) idx += (int64_t)len;
            if (idx < 0 || (size_t)idx >= len) return vval_null();
            return vval_retain(vval_list_get(input, (size_t)idx));
        }
        return vval_null();
    }

    const char *field = vstr_data(&args[0]->string);

    if (input->type == VEX_VAL_RECORD) {
        VexValue *v = vval_record_get(input, field);
        return v ? vval_retain(v) : vval_null();
    }

    if (input->type == VEX_VAL_LIST) {
        VexValue *result = vval_list();
        for (size_t i = 0; i < vval_list_len(input); i++) {
            VexValue *item = vval_list_get(input, i);
            if (item->type == VEX_VAL_RECORD) {
                VexValue *v = vval_record_get(item, field);
                if (v) vval_list_push(result, v);
            }
        }
        return result;
    }

    return vval_null();
}

static const char *sort_field_name;
static int sort_compare(const void *a, const void *b) {
    VexValue *ra = *(VexValue **)a;
    VexValue *rb = *(VexValue **)b;
    if (ra->type != VEX_VAL_RECORD || rb->type != VEX_VAL_RECORD) return 0;

    VexValue *va = vval_record_get(ra, sort_field_name);
    VexValue *vb = vval_record_get(rb, sort_field_name);
    if (!va || !vb) return 0;

    if (va->type == VEX_VAL_INT && vb->type == VEX_VAL_INT) {
        return (va->integer > vb->integer) - (va->integer < vb->integer);
    }
    if (va->type == VEX_VAL_STRING && vb->type == VEX_VAL_STRING) {
        return vstr_cmp(&va->string, &vb->string);
    }
    return 0;
}

VexValue *builtin_sort_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("sort-by: expected list input");
    if (argc == 0 || args[0]->type != VEX_VAL_STRING) {
        vex_err("sort-by: expected field name");
        return vval_retain(input);
    }

    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        vval_list_push(result, input->list.data[i]);
    }

    sort_field_name = vstr_data(&args[0]->string);
    qsort(result->list.data, result->list.len, sizeof(void *), sort_compare);
    return result;
}

VexValue *builtin_each(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("each: expected list input");
    if (argc == 0 || args[0]->type != VEX_VAL_CLOSURE) {
        vex_err("each: expected closure argument");
        return vval_retain(input);
    }

    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        VexValue *call_args[1] = { item };
        VexValue *mapped = eval_call_closure(ctx, args[0], call_args, 1);
        vval_list_push(result, mapped);
        vval_release(mapped);
    }
    return result;
}

VexValue *builtin_select(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("select: expected list input");

    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *row = input->list.data[i];
        if (row->type != VEX_VAL_RECORD) continue;

        VexValue *new_rec = vval_record();
        for (size_t j = 0; j < argc; j++) {
            if (args[j]->type != VEX_VAL_STRING) continue;
            const char *field = vstr_data(&args[j]->string);
            VexValue *val = vval_record_get(row, field);
            if (val) vval_record_set(new_rec, field, val);
        }
        vval_list_push(result, new_rec);
        vval_release(new_rec);
    }
    return result;
}

VexValue *builtin_reject(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("reject: expected list input");

    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *row = input->list.data[i];
        if (row->type != VEX_VAL_RECORD) continue;

        VexValue *new_rec = vval_record();
        VexMapIter it = vmap_iter(&row->record);
        const char *key;
        void *val;
        while (vmap_next(&it, &key, &val)) {
            bool rejected = false;
            for (size_t j = 0; j < argc; j++) {
                if (args[j]->type == VEX_VAL_STRING &&
                    strcmp(vstr_data(&args[j]->string), key) == 0) {
                    rejected = true;
                    break;
                }
            }
            if (!rejected) vval_record_set(new_rec, key, val);
        }
        vval_list_push(result, new_rec);
        vval_release(new_rec);
    }
    return result;
}

VexValue *builtin_length(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_int(0);
    if (input->type == VEX_VAL_LIST) return vval_int((int64_t)input->list.len);
    if (input->type == VEX_VAL_STRING)
        return vval_int((int64_t)vstr_len(&input->string));
    return vval_int(0);
}

VexValue *builtin_reverse(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("reverse: expected list input");
    VexValue *result = vval_list();
    for (size_t i = input->list.len; i > 0; i--) {
        vval_list_push(result, input->list.data[i - 1]);
    }
    return result;
}

VexValue *builtin_flatten(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("flatten: expected list input");
    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        if (item->type == VEX_VAL_LIST) {
            for (size_t j = 0; j < item->list.len; j++) {
                vval_list_push(result, item->list.data[j]);
            }
        } else {
            vval_list_push(result, item);
        }
    }
    return result;
}

VexValue *builtin_uniq(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("uniq: expected list input");
    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        if (i == 0) {
            vval_list_push(result, item);
            continue;
        }

        VexValue *prev = input->list.data[i - 1];
        VexStr a = vval_to_str(item);
        VexStr b = vval_to_str(prev);
        if (!vstr_eq(&a, &b)) {
            vval_list_push(result, item);
        }
        vstr_free(&a);
        vstr_free(&b);
    }
    return result;
}

VexValue *builtin_enumerate(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("enumerate: expected list input");
    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *rec = vval_record();
        VexValue *idx = vval_int((int64_t)i);
        vval_record_set(rec, "index", idx);
        vval_record_set(rec, "item", input->list.data[i]);
        vval_release(idx);
        vval_list_push(result, rec);
        vval_release(rec);
    }
    return result;
}

VexValue *builtin_skip(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("skip: expected list input");
    size_t n = 1;
    if (argc > 0 && args[0]->type == VEX_VAL_INT)
        n = (size_t)args[0]->integer;

    VexValue *result = vval_list();
    for (size_t i = n; i < input->list.len; i++) {
        vval_list_push(result, input->list.data[i]);
    }
    return result;
}

VexValue *builtin_reduce(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("reduce: expected list input");
    if (argc < 2 || args[1]->type != VEX_VAL_CLOSURE) {
        vex_err("reduce: expected initial value and closure");
        return vval_null();
    }

    VexValue *acc = vval_retain(args[0]);
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *call_args[2] = { acc, input->list.data[i] };
        VexValue *new_acc = eval_call_closure(ctx, args[1], call_args, 2);
        vval_release(acc);
        acc = new_acc;
    }
    return acc;
}

VexValue *builtin_to_text(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_string_cstr("");
    if (input->type == VEX_VAL_STRING) return vval_retain(input);

    if (input->type == VEX_VAL_LIST) {
        VexStr out = vstr_empty();
        for (size_t i = 0; i < input->list.len; i++) {
            if (i > 0) vstr_append_char(&out, '\n');
            VexStr s = vval_to_str(input->list.data[i]);
            vstr_append_str(&out, &s);
            vstr_free(&s);
        }
        return vval_string(out);
    }

    VexStr s = vval_to_str(input);
    return vval_string(s);
}

VexValue *builtin_str_join(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("str-join: expected list input");
    const char *sep = " ";
    if (argc > 0 && args[0]->type == VEX_VAL_STRING)
        sep = vstr_data(&args[0]->string);

    VexStr out = vstr_empty();
    for (size_t i = 0; i < input->list.len; i++) {
        if (i > 0) vstr_append_cstr(&out, sep);
        VexStr s = vval_to_str(input->list.data[i]);
        vstr_append_str(&out, &s);
        vstr_free(&s);
    }
    return vval_string(out);
}

VexValue *builtin_str_split(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *sep = " ";
    if (argc > 0 && args[0]->type == VEX_VAL_STRING)
        sep = vstr_data(&args[0]->string);

    VexValue *result = vval_list();
    const char *s = vstr_data(&input->string);
    size_t sep_len = strlen(sep);

    if (sep_len == 0) {
        /* Empty sep: split into UTF-8 codepoints */
        while (*s) {
            size_t clen = 1;
            unsigned char c = (unsigned char)*s;
            if (c >= 0xC0 && c < 0xE0) clen = 2;
            else if (c >= 0xE0 && c < 0xF0) clen = 3;
            else if (c >= 0xF0) clen = 4;
            VexValue *v = vval_string(vstr_newn(s, clen));
            vval_list_push(result, v);
            vval_release(v);
            s += clen;
        }
        return result;
    }

    while (*s) {
        const char *found = strstr(s, sep);
        if (!found) {
            VexValue *v = vval_string(vstr_new(s));
            vval_list_push(result, v);
            vval_release(v);
            break;
        }
        VexValue *v = vval_string(vstr_newn(s, (size_t)(found - s)));
        vval_list_push(result, v);
        vval_release(v);
        s = found + sep_len;
    }
    return result;
}

VexValue *builtin_str_trim(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    size_t start = 0, end = len;
    while (start < len && (s[start] == ' ' || s[start] == '\t' ||
           s[start] == '\n' || s[start] == '\r')) start++;
    while (end > start && (s[end-1] == ' ' || s[end-1] == '\t' ||
           s[end-1] == '\n' || s[end-1] == '\r')) end--;
    return vval_string(vstr_newn(s + start, end - start));
}

VexValue *builtin_str_replace(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 2) return vval_null();
    if (args[0]->type != VEX_VAL_STRING || args[1]->type != VEX_VAL_STRING)
        return vval_retain(input);

    const char *s = vstr_data(&input->string);
    const char *find = vstr_data(&args[0]->string);
    const char *repl = vstr_data(&args[1]->string);
    size_t find_len = vstr_len(&args[0]->string);
    size_t repl_len = vstr_len(&args[1]->string);

    if (find_len == 0) return vval_retain(input);
    VexStr out = vstr_empty();
    while (*s) {
        const char *found = strstr(s, find);
        if (!found) {
            vstr_append_cstr(&out, s);
            break;
        }
        vstr_append(&out, s, (size_t)(found - s));
        vstr_append(&out, repl, repl_len);
        s = found + find_len;
    }
    return vval_string(out);
}

VexValue *builtin_lines(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();

    VexValue *list = vval_list();
    const char *s = vstr_data(&input->string);
    const char *start = s;

    while (*s) {
        if (*s == '\n') {
            VexValue *line = vval_string(vstr_newn(start, (size_t)(s - start)));
            vval_list_push(list, line);
            vval_release(line);
            start = s + 1;
        }
        s++;
    }
    if (s > start) {
        VexValue *line = vval_string(vstr_newn(start, (size_t)(s - start)));
        vval_list_push(list, line);
        vval_release(line);
    }
    return list;
}

VexValue *builtin_help(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    printf("\n\033[1mVex Shell\033[0m — a structured-data shell\n\n");
    printf("Built-in commands:\n");
    for (size_t i = 0; i < builtins_count; i++) {
        printf("  \033[1;32m%-12s\033[0m %s\n",
               builtins_table[i].name, builtins_table[i].description);
    }
    if (n_script_cmds > 0) {
        printf("\nScript commands:\n");
        for (size_t i = 0; i < n_script_cmds; i++) {
            printf("  \033[1;36m%-12s\033[0m %s\n",
                   script_cmds[i].name, script_cmds[i].description);
        }
    }
    printf("\nUse ^ prefix for external commands: ^grep, ^git, etc.\n");
    printf("Pipelines: command | command | command\n");
    printf("\n");
    return vval_null();
}

VexValue *builtin_from_json(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    const char *src = NULL;
    size_t slen = 0;
    if (input && input->type == VEX_VAL_STRING) {
        src = vstr_data(&input->string);
        slen = vstr_len(&input->string);
    } else if (argc > 0 && args[0]->type == VEX_VAL_STRING) {
        src = vstr_data(&args[0]->string);
        slen = vstr_len(&args[0]->string);
    }
    if (!src) return vval_error("from-json: expected string input");
    return format_from_json(src, slen);
}

VexValue *builtin_to_json(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    VexValue *v = input ? input : (argc > 0 ? args[0] : vval_null());
    VexStr s = format_to_json(v, true);
    return vval_string(s);
}

VexValue *builtin_from_csv(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    const char *src = NULL;
    size_t slen = 0;
    if (input && input->type == VEX_VAL_STRING) {
        src = vstr_data(&input->string);
        slen = vstr_len(&input->string);
    } else if (argc > 0 && args[0]->type == VEX_VAL_STRING) {
        src = vstr_data(&args[0]->string);
        slen = vstr_len(&args[0]->string);
    }
    if (!src) return vval_error("from-csv: expected string input");
    return format_from_csv(src, slen);
}

VexValue *builtin_to_csv(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    VexValue *v = input ? input : (argc > 0 ? args[0] : vval_null());
    VexStr s = format_to_csv(v);
    return vval_string(s);
}

VexValue *builtin_from_toml(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    const char *src = NULL;
    size_t slen = 0;
    if (input && input->type == VEX_VAL_STRING) {
        src = vstr_data(&input->string);
        slen = vstr_len(&input->string);
    } else if (argc > 0 && args[0]->type == VEX_VAL_STRING) {
        src = vstr_data(&args[0]->string);
        slen = vstr_len(&args[0]->string);
    }
    if (!src) return vval_error("from-toml: expected string input");
    return format_from_toml(src, slen);
}

VexValue *builtin_to_toml(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    VexValue *v = input ? input : (argc > 0 ? args[0] : vval_null());
    VexStr s = format_to_toml(v);
    return vval_string(s);
}

static VexValue *read_file_contents(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return vval_error(strerror(errno));

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc((size_t)size + 1);
    size_t nread = fread(buf, 1, (size_t)size, f);
    buf[nread] = '\0';
    fclose(f);

    VexValue *result = vval_string(vstr_newn(buf, nread));
    free(buf);
    return result;
}

VexValue *builtin_open(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc == 0 || args[0]->type != VEX_VAL_STRING) {
        vex_err("open: expected file path");
        ctx->had_error = true;
        return vval_error("expected file path");
    }
    const char *path = vstr_data(&args[0]->string);

    VexValue *content = read_file_contents(path);
    if (content->type == VEX_VAL_ERROR) {
        vex_err("open: %s: %s", path, content->error->message);
        ctx->had_error = true;
        return content;
    }

    const char *ext = strrchr(path, '.');
    if (ext) {
        const char *src = vstr_data(&content->string);
        size_t slen = vstr_len(&content->string);
        VexValue *parsed = NULL;

        if (strcmp(ext, ".json") == 0) {
            parsed = format_from_json(src, slen);
        } else if (strcmp(ext, ".csv") == 0) {
            parsed = format_from_csv(src, slen);
        } else if (strcmp(ext, ".toml") == 0) {
            parsed = format_from_toml(src, slen);
        }

        if (parsed) {
            vval_release(content);
            return parsed;
        }
    }

    return content;
}

VexValue *builtin_save(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (argc == 0 || args[0]->type != VEX_VAL_STRING) {
        vex_err("save: expected file path");
        ctx->had_error = true;
        return vval_error("expected file path");
    }
    const char *path = vstr_data(&args[0]->string);
    VexValue *data = input;
    if (!data) {
        vex_err("save: no input data");
        ctx->had_error = true;
        return vval_error("no input data");
    }

    VexStr output = vstr_empty();

    const char *ext = strrchr(path, '.');
    if (ext) {
        if (strcmp(ext, ".json") == 0) {
            output = format_to_json(data, true);
        } else if (strcmp(ext, ".csv") == 0) {
            output = format_to_csv(data);
        } else if (strcmp(ext, ".toml") == 0) {
            output = format_to_toml(data);
        } else {
            output = vval_to_str(data);
        }
    } else {
        output = vval_to_str(data);
    }

    FILE *f = fopen(path, "w");
    if (!f) {
        vex_err("save: %s: %s", path, strerror(errno));
        vstr_free(&output);
        ctx->had_error = true;
        return vval_error(strerror(errno));
    }
    fwrite(vstr_data(&output), 1, vstr_len(&output), f);
    fclose(f);
    vstr_free(&output);

    return vval_null();
}

static void glob_recurse(const char *dir, const char *pattern, VexValue *list, bool recursive) {
    DIR *d = opendir(dir);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' && ent->d_name[1] == '\0') continue;
        if (ent->d_name[0] == '.' && ent->d_name[1] == '.' && ent->d_name[2] == '\0') continue;

        char fullpath[4096];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, ent->d_name);

        struct stat st;
        if (stat(fullpath, &st) != 0) continue;

        if (fnmatch(pattern, ent->d_name, 0) == 0) {
            VexValue *v = vval_string_cstr(fullpath);
            vval_list_push(list, v);
            vval_release(v);
        }

        if (recursive && S_ISDIR(st.st_mode)) {
            glob_recurse(fullpath, pattern, list, recursive);
        }
    }
    closedir(d);
}

VexValue *builtin_glob(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc == 0 || args[0]->type != VEX_VAL_STRING) {
        vex_err("glob: expected pattern");
        return vval_error("expected pattern");
    }

    const char *pattern = vstr_data(&args[0]->string);
    VexValue *list = vval_list();

    bool recursive = (strstr(pattern, "**") != NULL);

    char dir[4096] = ".";
    const char *file_pattern = pattern;

    const char *last_slash = strrchr(pattern, '/');
    if (last_slash) {
        size_t dir_len = (size_t)(last_slash - pattern);
        if (dir_len > 0 && dir_len < sizeof(dir)) {
            memcpy(dir, pattern, dir_len);
            dir[dir_len] = '\0';
        }
        file_pattern = last_slash + 1;

        char *dp = strstr(dir, "/**");
        if (dp) *dp = '\0';
        if (dir[0] == '\0') strcpy(dir, ".");
    }

    glob_recurse(dir, file_pattern, list, recursive);
    return list;
}

VexValue *builtin_str_contains(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc == 0 || args[0]->type != VEX_VAL_STRING)
        return vval_bool(false);
    return vval_bool(strstr(vstr_data(&input->string), vstr_data(&args[0]->string)) != NULL);
}

VexValue *builtin_str_length(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_int(0);

    const char *s = vstr_data(&input->string);
    size_t count = 0;
    while (*s) {
        if ((*s & 0xC0) != 0x80) count++;
        s++;
    }
    return vval_int((int64_t)count);
}

static size_t case_utf8_encode(char *buf, uint32_t cp) {
    if (cp < 0x80) { buf[0] = (char)cp; return 1; }
    if (cp < 0x800) {
        buf[0] = (char)(0xC0 | (cp >> 6));
        buf[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        buf[0] = (char)(0xE0 | (cp >> 12));
        buf[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        buf[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    buf[0] = (char)(0xF0 | (cp >> 18));
    buf[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    buf[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    buf[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

static uint32_t case_utf8_decode(const char *s, size_t *pos) {
    unsigned char c = (unsigned char)s[*pos];
    uint32_t cp;
    size_t len;
    if (c < 0x80) { cp = c; len = 1; }
    else if (c < 0xE0) { cp = c & 0x1F; len = 2; }
    else if (c < 0xF0) { cp = c & 0x0F; len = 3; }
    else { cp = c & 0x07; len = 4; }
    for (size_t i = 1; i < len; i++)
        cp = (cp << 6) | ((unsigned char)s[*pos + i] & 0x3F);
    *pos += len;
    return cp;
}

static uint32_t unicode_tolower(uint32_t cp) {
    if (cp < 0x80) return (uint32_t)tolower((int)cp);

    if (cp >= 0xC0 && cp <= 0xD6) return cp + 0x20;

    if (cp >= 0xD8 && cp <= 0xDE) return cp + 0x20;
    return cp;
}

static uint32_t unicode_toupper(uint32_t cp) {
    if (cp < 0x80) return (uint32_t)toupper((int)cp);

    if (cp >= 0xE0 && cp <= 0xF6) return cp - 0x20;

    if (cp >= 0xF8 && cp <= 0xFE) return cp - 0x20;
    return cp;
}

VexValue *builtin_str_downcase(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    char *buf = malloc(len * 4 + 1);
    size_t si = 0, di = 0;
    while (si < len) {
        uint32_t cp = case_utf8_decode(s, &si);
        cp = unicode_tolower(cp);
        di += case_utf8_encode(buf + di, cp);
    }
    buf[di] = '\0';
    VexValue *result = vval_string(vstr_newn(buf, di));
    free(buf);
    return result;
}

VexValue *builtin_str_upcase(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);

    char *buf = malloc(len * 4 + 1);
    size_t si = 0, di = 0;
    while (si < len) {
        uint32_t cp = case_utf8_decode(s, &si);
        cp = unicode_toupper(cp);
        di += case_utf8_encode(buf + di, cp);
    }
    buf[di] = '\0';
    VexValue *result = vval_string(vstr_newn(buf, di));
    free(buf);
    return result;
}

VexValue *builtin_str_starts_with(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc == 0 || args[0]->type != VEX_VAL_STRING)
        return vval_bool(false);
    const char *s = vstr_data(&input->string);
    const char *prefix = vstr_data(&args[0]->string);
    return vval_bool(strncmp(s, prefix, vstr_len(&args[0]->string)) == 0);
}

VexValue *builtin_str_ends_with(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc == 0 || args[0]->type != VEX_VAL_STRING)
        return vval_bool(false);
    size_t slen = vstr_len(&input->string);
    size_t plen = vstr_len(&args[0]->string);
    if (plen > slen) return vval_bool(false);
    return vval_bool(strcmp(vstr_data(&input->string) + slen - plen, vstr_data(&args[0]->string)) == 0);
}

VexValue *builtin_math_sum(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("math-sum: expected list input");
    bool has_float = false;
    double fsum = 0;
    int64_t isum = 0;
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *v = input->list.data[i];
        if (v->type == VEX_VAL_FLOAT) { has_float = true; fsum += v->floating; }
        else if (v->type == VEX_VAL_INT) { isum += v->integer; fsum += (double)v->integer; }
    }
    return has_float ? vval_float(fsum) : vval_int(isum);
}

VexValue *builtin_math_avg(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("math-avg: expected list input");
    if (input->list.len == 0) return vval_float(0.0);
    double sum = 0;
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *v = input->list.data[i];
        if (v->type == VEX_VAL_FLOAT) sum += v->floating;
        else if (v->type == VEX_VAL_INT) sum += (double)v->integer;
    }
    return vval_float(sum / (double)input->list.len);
}

VexValue *builtin_math_min(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("math-min: expected list input");
    if (input->list.len == 0) return vval_null();
    double min_val = 1e308;
    bool has_float = false;
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *v = input->list.data[i];
        double d;
        if (v->type == VEX_VAL_FLOAT) { d = v->floating; has_float = true; }
        else if (v->type == VEX_VAL_INT) { d = (double)v->integer; }
        else continue;
        if (d < min_val) min_val = d;
    }
    if (has_float) return vval_float(min_val);
    return vval_int((int64_t)min_val);
}

VexValue *builtin_math_max(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("math-max: expected list input");
    if (input->list.len == 0) return vval_null();
    double max_val = -1e308;
    bool has_float = false;
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *v = input->list.data[i];
        double d;
        if (v->type == VEX_VAL_FLOAT) { d = v->floating; has_float = true; }
        else if (v->type == VEX_VAL_INT) { d = (double)v->integer; }
        else continue;
        if (d > max_val) max_val = d;
    }
    if (has_float) return vval_float(max_val);
    return vval_int((int64_t)max_val);
}

VexValue *builtin_math_abs(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    VexValue *v = input ? input : (argc > 0 ? args[0] : NULL);
    if (!v) return vval_int(0);
    if (v->type == VEX_VAL_INT) return vval_int(v->integer < 0 ? -v->integer : v->integer);
    if (v->type == VEX_VAL_FLOAT) return vval_float(fabs(v->floating));
    return vval_int(0);
}

VexValue *builtin_math_round(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    VexValue *v = input ? input : (argc > 0 ? args[0] : NULL);
    if (!v) return vval_int(0);
    if (v->type == VEX_VAL_INT) return vval_retain(v);
    if (v->type == VEX_VAL_FLOAT) return vval_int((int64_t)round(v->floating));
    return vval_int(0);
}

VexValue *builtin_j(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc == 0) {
        vex_err("j: expected search terms");
        return vval_error("expected search terms");
    }

    VexStr query = vstr_empty();
    for (size_t i = 0; i < argc; i++) {
        if (i > 0) vstr_append_char(&query, ' ');
        VexStr s = vval_to_str(args[i]);
        vstr_append_str(&query, &s);
        vstr_free(&s);
    }

    char *path = frecency_find(vstr_data(&query));
    vstr_free(&query);

    if (!path) {
        vex_err("j: no matching directory");
        return vval_error("no matching directory");
    }

    if (chdir(path) != 0) {
        vex_err("j: %s: %s", path, strerror(errno));
        ctx->had_error = true;
        VexValue *e = vval_error(strerror(errno));
        free(path);
        return e;
    }

    frecency_add(path);
    hooks_run_chpwd(ctx);
    VexValue *result = vval_string_cstr(path);
    free(path);
    return result;
}

VexValue *builtin_ji(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input; (void)args; (void)argc;

    size_t count;
    char **entries = frecency_list(&count);
    if (!entries || count == 0) {
        vex_err("ji: no frecency entries");
        return vval_error("no frecency entries");
    }

    char *selected = filter_select(entries, count);

    for (size_t i = 0; i < count; i++) free(entries[i]);
    free(entries);

    if (!selected) return vval_null();

    if (chdir(selected) != 0) {
        vex_err("ji: %s: %s", selected, strerror(errno));
        ctx->had_error = true;
        VexValue *e = vval_error(strerror(errno));
        free(selected);
        return e;
    }

    frecency_add(selected);
    hooks_run_chpwd(ctx);
    printf("%s\n", selected);
    VexValue *result = vval_string_cstr(selected);
    free(selected);
    return result;
}

VexValue *builtin_filter(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("filter: expected list input");
    if (input->list.len == 0) return vval_list();

    size_t count = input->list.len;
    char **items = malloc(count * sizeof(char *));
    for (size_t i = 0; i < count; i++) {
        VexStr s = vval_to_str(input->list.data[i]);
        items[i] = strdup(vstr_data(&s));
        vstr_free(&s);
    }

    bool multi = false;
    for (size_t i = 0; i < argc; i++) {
        if (args[i]->type == VEX_VAL_STRING &&
            strcmp(vstr_data(&args[i]->string), "--multi") == 0) {
            multi = true;
        }
    }

    VexValue *result;
    if (multi) {
        bool *selected = calloc(count, sizeof(bool));
        filter_run(items, count, true, selected);
        result = vval_list();
        for (size_t i = 0; i < count; i++) {
            if (selected[i]) {
                vval_list_push(result, input->list.data[i]);
            }
        }
        free(selected);
    } else {
        int idx = filter_run(items, count, false, NULL);
        if (idx >= 0 && (size_t)idx < count) {
            result = vval_retain(input->list.data[idx]);
        } else {
            result = vval_null();
        }
    }

    for (size_t i = 0; i < count; i++) free(items[i]);
    free(items);
    return result;
}

VexValue *builtin_jobs(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    job_print_all(stdout);
    return vval_null();
}

VexValue *builtin_fg(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    int id;
    if (argc > 0 && args[0]->type == VEX_VAL_INT) {
        id = (int)args[0]->integer;
    } else {
        id = job_last_id();
        if (id < 0) {
            vex_err("fg: no current job");
            return vval_error("no current job");
        }
    }
    int code = job_foreground(id);
    ctx->last_exit_code = code;
    return vval_int(code);
}

VexValue *builtin_bg(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    int id;
    if (argc > 0 && args[0]->type == VEX_VAL_INT) {
        id = (int)args[0]->integer;
    } else {
        id = job_last_id();
        if (id < 0) {
            vex_err("bg: no current job");
            return vval_error("no current job");
        }
    }
    job_background(id);
    return vval_null();
}

VexValue *builtin_kill(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;

    if (has_flag_args(args, argc))
        return fallback_external(ctx, "kill", args, argc);
    if (argc < 1) {
        vex_err("kill: usage: kill <job-id> [signal]");
        return vval_error("missing argument");
    }
    int id = (args[0]->type == VEX_VAL_INT) ? (int)args[0]->integer : 0;
    int sig = SIGTERM;
    if (argc > 1 && args[1]->type == VEX_VAL_INT) {
        sig = (int)args[1]->integer;
    } else if (argc > 1 && args[1]->type == VEX_VAL_STRING) {
        const char *name = vstr_data(&args[1]->string);
        if (strcmp(name, "SIGKILL") == 0 || strcmp(name, "KILL") == 0) sig = SIGKILL;
        else if (strcmp(name, "SIGINT") == 0 || strcmp(name, "INT") == 0) sig = SIGINT;
        else if (strcmp(name, "SIGTERM") == 0 || strcmp(name, "TERM") == 0) sig = SIGTERM;
        else if (strcmp(name, "SIGSTOP") == 0 || strcmp(name, "STOP") == 0) sig = SIGSTOP;
        else if (strcmp(name, "SIGCONT") == 0 || strcmp(name, "CONT") == 0) sig = SIGCONT;
        else if (strcmp(name, "SIGHUP") == 0 || strcmp(name, "HUP") == 0) sig = SIGHUP;
    }
    job_kill(id, sig);
    return vval_null();
}

VexValue *builtin_wait_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc > 0 && args[0]->type == VEX_VAL_INT) {
        int id = (int)args[0]->integer;
        int code = job_wait(id);
        ctx->last_exit_code = code;
        return vval_int(code);
    }

    for (;;) {
        int id = job_last_id();
        if (id < 0) break;
        job_wait(id);
    }
    return vval_null();
}

VexValue *builtin_ps(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (argc > 0)
        return fallback_external(ctx, "ps", args, argc);
    (void)ctx; (void)input; (void)args; (void)argc;

    VexValue *list = vval_list();

#ifdef __APPLE__
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    size_t proc_len = 0;
    if (sysctl(mib, 4, NULL, &proc_len, NULL, 0) < 0) return list;
    struct kinfo_proc *procs = malloc(proc_len);
    if (!procs) return list;
    if (sysctl(mib, 4, procs, &proc_len, NULL, 0) < 0) { free(procs); return list; }
    size_t nprocs = proc_len / sizeof(struct kinfo_proc);

    for (size_t pi = 0; pi < nprocs; pi++) {
        struct kinfo_proc *kp = &procs[pi];
        int pid = kp->kp_proc.p_pid;
        char comm[256];
        strncpy(comm, kp->kp_proc.p_comm, sizeof(comm) - 1);
        comm[sizeof(comm) - 1] = '\0';
        char state = '?';
        switch (kp->kp_proc.p_stat) {
        case SRUN: state = 'R'; break;
        case SSLEEP: state = 'S'; break;
        case SSTOP: state = 'T'; break;
        case SZOMB: state = 'Z'; break;
        }
        char cmdline[1024];
        snprintf(cmdline, sizeof(cmdline), "%s", comm);
#else
    DIR *d = opendir("/proc");
    if (!d) return list;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {

        bool is_pid = true;
        for (int i = 0; ent->d_name[i]; i++) {
            if (ent->d_name[i] < '0' || ent->d_name[i] > '9') {
                is_pid = false;
                break;
            }
        }
        if (!is_pid) continue;

        char path[512];
        snprintf(path, sizeof(path), "/proc/%s/stat", ent->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        char stat_line[1024];
        if (!fgets(stat_line, sizeof(stat_line), f)) {
            fclose(f);
            continue;
        }
        fclose(f);

        int pid;
        char comm[256], state;
        char *start = strchr(stat_line, '(');
        char *end2 = strrchr(stat_line, ')');
        if (!start || !end2) continue;

        pid = atoi(stat_line);
        size_t clen = (size_t)(end2 - start - 1);
        if (clen >= sizeof(comm)) clen = sizeof(comm) - 1;
        memcpy(comm, start + 1, clen);
        comm[clen] = '\0';
        state = *(end2 + 2);

        snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
        f = fopen(path, "r");
        char cmdline[1024] = "";
        if (f) {
            size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);

            for (size_t i = 0; i < n; i++)
                if (cmdline[i] == '\0') cmdline[i] = ' ';
            cmdline[n] = '\0';

            while (n > 0 && cmdline[n-1] == ' ') cmdline[--n] = '\0';
            fclose(f);
        }
#endif

        VexValue *rec = vval_record();
        VexValue *vpid = vval_int(pid);
        VexValue *vname = vval_string_cstr(comm);
        char state_str[2] = { state, '\0' };
        VexValue *vstate = vval_string_cstr(state_str);
        VexValue *vcmd = vval_string_cstr(cmdline[0] ? cmdline : comm);

        vval_record_set(rec, "pid", vpid);
        vval_record_set(rec, "name", vname);
        vval_record_set(rec, "status", vstate);
        vval_record_set(rec, "command", vcmd);
        vval_release(vpid);
        vval_release(vname);
        vval_release(vstate);
        vval_release(vcmd);

        vval_list_push(list, rec);
        vval_release(rec);
    }
#ifdef __APPLE__
    free(procs);
#else
    closedir(d);
#endif
    return list;
}

static struct {
    bool errexit;
    bool xtrace;
    bool nounset;
    bool noclobber;
    bool pipefail;
} shell_opts = {0};

bool vex_opt_errexit(void)   { return shell_opts.errexit; }
bool vex_opt_xtrace(void)    { return shell_opts.xtrace; }
bool vex_opt_nounset(void)   { return shell_opts.nounset; }
bool vex_opt_noclobber(void) { return shell_opts.noclobber; }

static bool set_shell_opt(const char *name, bool value) {
    if (strcmp(name, "errexit") == 0 || strcmp(name, "e") == 0)
        shell_opts.errexit = value;
    else if (strcmp(name, "xtrace") == 0 || strcmp(name, "x") == 0)
        shell_opts.xtrace = value;
    else if (strcmp(name, "nounset") == 0 || strcmp(name, "u") == 0)
        shell_opts.nounset = value;
    else if (strcmp(name, "noclobber") == 0 || strcmp(name, "C") == 0)
        shell_opts.noclobber = value;
    else if (strcmp(name, "pipefail") == 0)
        shell_opts.pipefail = value;
    else
        return false;
    return true;
}

VexValue *builtin_set(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1) {

        const char *mode = getenv("VEX_EDIT_MODE");
        printf("edit mode: %s\n", mode ? mode : "emacs");
        printf("errexit  (-e): %s\n", shell_opts.errexit  ? "on" : "off");
        printf("xtrace   (-x): %s\n", shell_opts.xtrace   ? "on" : "off");
        printf("nounset  (-u): %s\n", shell_opts.nounset   ? "on" : "off");
        printf("noclobber(-C): %s\n", shell_opts.noclobber ? "on" : "off");
        printf("pipefail    : %s\n", shell_opts.pipefail  ? "on" : "off");
        return vval_null();
    }

    for (size_t i = 0; i < argc; i++) {
        VexStr arg = vval_to_str(args[i]);
        const char *val = vstr_data(&arg);

        if (strcmp(val, "vi") == 0) {
            setenv("VEX_EDIT_MODE", "vi", 1);
        } else if (strcmp(val, "emacs") == 0) {
            setenv("VEX_EDIT_MODE", "emacs", 1);
        } else if (val[0] == '-' && val[1] == 'o' && val[2] == '\0') {

            vstr_free(&arg);
            i++;
            if (i >= argc) {
                vex_err("set: -o requires option name");
                return vval_error("-o requires option name");
            }
            VexStr oarg = vval_to_str(args[i]);
            if (!set_shell_opt(vstr_data(&oarg), true)) {
                vex_err("set: unknown option '%s'", vstr_data(&oarg));
                vstr_free(&oarg);
                return vval_error("unknown option");
            }
            vstr_free(&oarg);
            continue;
        } else if (val[0] == '+' && val[1] == 'o' && val[2] == '\0') {

            vstr_free(&arg);
            i++;
            if (i >= argc) {
                vex_err("set: +o requires option name");
                return vval_error("+o requires option name");
            }
            VexStr oarg = vval_to_str(args[i]);
            if (!set_shell_opt(vstr_data(&oarg), false)) {
                vex_err("set: unknown option '%s'", vstr_data(&oarg));
                vstr_free(&oarg);
                return vval_error("unknown option");
            }
            vstr_free(&oarg);
            continue;
        } else if (val[0] == '-' && val[1] != '\0') {

            for (const char *c = val + 1; *c; c++) {
                char opt[2] = {*c, '\0'};
                if (!set_shell_opt(opt, true)) {
                    vex_err("set: unknown option '-%c'", *c);
                    vstr_free(&arg);
                    return vval_error("unknown option");
                }
            }
        } else if (val[0] == '+' && val[1] != '\0') {

            for (const char *c = val + 1; *c; c++) {
                char opt[2] = {*c, '\0'};
                if (!set_shell_opt(opt, false)) {
                    vex_err("set: unknown option '+%c'", *c);
                    vstr_free(&arg);
                    return vval_error("unknown option");
                }
            }
        } else {
            vex_err("set: unknown option '%s'", val);
            vstr_free(&arg);
            return vval_error("unknown option");
        }
        vstr_free(&arg);
    }
    return vval_null();
}

VexValue *builtin_export(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1) {

        extern char **environ;
        VexValue *list = vval_list();
        for (char **ep = environ; *ep; ep++) {
            VexValue *s = vval_string_cstr(*ep);
            vval_list_push(list, s);
            vval_release(s);
        }
        return list;
    }
    if (argc < 2) {
        vex_err("export: expected key and value");
        return vval_error("export: expected key and value");
    }
    VexStr key = vval_to_str(args[0]);
    VexStr val = vval_to_str(args[1]);
    setenv(vstr_data(&key), vstr_data(&val), 1);

    scope_set(ctx->current, vstr_data(&key), args[1]);
    vstr_free(&key);
    vstr_free(&val);
    return vval_null();
}

VexValue *builtin_source(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1) {
        vex_err("source: expected file path");
        return vval_error("source: expected file path");
    }
    VexStr path = vval_to_str(args[0]);
    const char *p = vstr_data(&path);

    if (is_sh_file(p) || has_sh_shebang(p)) {
        VexValue *result = source_sh_file(ctx, p);
        vstr_free(&path);
        return result;
    }

    FILE *f = fopen(p, "r");
    if (!f) {
        vex_err("source: cannot open '%s': %s", p, strerror(errno));
        vstr_free(&path);
        return vval_error("source: file not found");
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *source = malloc((size_t)size + 1);
    fread(source, 1, (size_t)size, f);
    source[size] = '\0';
    fclose(f);

    Parser parser = parser_init(source, ctx->arena);
    VexValue *result = vval_null();

    for (;;) {
        ASTNode *stmt = parser_parse_line(&parser);
        if (!stmt || parser.had_error) break;
        vval_release(result);
        result = eval(ctx, stmt);
    }

    free(source);
    vstr_free(&path);
    return result;
}

static struct { char *name; char *expansion; } alias_table[128];
static size_t alias_count = 0;

const char *alias_lookup(const char *name) {
    for (size_t i = 0; i < alias_count; i++) {
        if (strcmp(alias_table[i].name, name) == 0)
            return alias_table[i].expansion;
    }
    return NULL;
}

void alias_register(const char *name, const char *expansion) {
    for (size_t i = 0; i < alias_count; i++) {
        if (strcmp(alias_table[i].name, name) == 0) {
            free(alias_table[i].expansion);
            alias_table[i].expansion = strdup(expansion);
            return;
        }
    }
    if (alias_count < 128) {
        alias_table[alias_count].name = strdup(name);
        alias_table[alias_count].expansion = strdup(expansion);
        alias_count++;
    }
}

VexValue *builtin_alias(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1) {

        VexValue *list = vval_list();
        for (size_t i = 0; i < alias_count; i++) {
            VexValue *rec = vval_record();
            VexValue *n = vval_string_cstr(alias_table[i].name);
            VexValue *v = vval_string_cstr(alias_table[i].expansion);
            vval_record_set(rec, "name", n);
            vval_record_set(rec, "command", v);
            vval_release(n);
            vval_release(v);
            vval_list_push(list, rec);
            vval_release(rec);
        }
        return list;
    }
    if (argc < 2) {
        vex_err("alias: expected name and command");
        return vval_error("alias: expected name and command");
    }
    VexStr name = vval_to_str(args[0]);

    size_t start = 1;
    if (start < argc && args[start]->type == VEX_VAL_STRING &&
        strcmp(vstr_data(&args[start]->string), "=") == 0)
        start++;

    if (start >= argc) {
        vstr_free(&name);
        vex_err("alias: expected command after name");
        return vval_error("alias: expected command");
    }

    VexStr exp = vstr_empty();
    for (size_t i = start; i < argc; i++) {
        if (i > start) vstr_append_char(&exp, ' ');
        VexStr s = vval_to_str(args[i]);
        vstr_append_str(&exp, &s);
        vstr_free(&s);
    }

    for (size_t i = 0; i < alias_count; i++) {
        if (strcmp(alias_table[i].name, vstr_data(&name)) == 0) {
            free(alias_table[i].expansion);
            alias_table[i].expansion = strdup(vstr_data(&exp));
            vstr_free(&name);
            vstr_free(&exp);
            return vval_null();
        }
    }
    if (alias_count < 128) {
        alias_table[alias_count].name = strdup(vstr_data(&name));
        alias_table[alias_count].expansion = strdup(vstr_data(&exp));
        alias_count++;
    }
    vstr_free(&name);
    vstr_free(&exp);
    return vval_null();
}

#define MAX_ABBRS 128
static struct { char *name; char *expansion; } abbr_table[MAX_ABBRS];
static size_t abbr_count = 0;

const char *abbr_lookup(const char *name) {
    for (size_t i = 0; i < abbr_count; i++) {
        if (strcmp(abbr_table[i].name, name) == 0)
            return abbr_table[i].expansion;
    }
    return NULL;
}

VexValue *builtin_abbr(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1) return vval_error("abbr requires a subcommand: add, remove, list");

    VexStr sub_s = vval_to_str(args[0]);
    const char *sub = vstr_data(&sub_s);

    if (strcmp(sub, "add") == 0) {
        if (argc < 3) {
            vstr_free(&sub_s);
            return vval_error("abbr add requires name and expansion");
        }
        VexStr name_s = vval_to_str(args[1]);

        VexStr exp_s = vstr_empty();
        for (size_t i = 2; i < argc; i++) {
            if (i > 2) vstr_append_char(&exp_s, ' ');
            VexStr s = vval_to_str(args[i]);
            vstr_append_str(&exp_s, &s);
            vstr_free(&s);
        }
        const char *name = vstr_data(&name_s);
        const char *expansion = vstr_data(&exp_s);

        for (size_t i = 0; i < abbr_count; i++) {
            if (strcmp(abbr_table[i].name, name) == 0) {
                free(abbr_table[i].expansion);
                abbr_table[i].expansion = strdup(expansion);
                vstr_free(&name_s);
                vstr_free(&exp_s);
                vstr_free(&sub_s);
                return vval_null();
            }
        }
        if (abbr_count >= MAX_ABBRS) {
            vstr_free(&name_s);
            vstr_free(&exp_s);
            vstr_free(&sub_s);
            return vval_error("too many abbreviations");
        }
        abbr_table[abbr_count].name = strdup(name);
        abbr_table[abbr_count].expansion = strdup(expansion);
        abbr_count++;
        vstr_free(&name_s);
        vstr_free(&exp_s);
        vstr_free(&sub_s);
        return vval_null();
    }

    if (strcmp(sub, "remove") == 0) {
        if (argc < 2) {
            vstr_free(&sub_s);
            return vval_error("abbr remove requires name");
        }
        VexStr name_s = vval_to_str(args[1]);
        const char *name = vstr_data(&name_s);
        for (size_t i = 0; i < abbr_count; i++) {
            if (strcmp(abbr_table[i].name, name) == 0) {
                free(abbr_table[i].name);
                free(abbr_table[i].expansion);
                memmove(&abbr_table[i], &abbr_table[i+1],
                        (abbr_count - i - 1) * sizeof(abbr_table[0]));
                abbr_count--;
                vstr_free(&name_s);
                vstr_free(&sub_s);
                return vval_null();
            }
        }
        vstr_free(&name_s);
        vstr_free(&sub_s);
        return vval_error("abbreviation not found");
    }

    if (strcmp(sub, "list") == 0) {
        vstr_free(&sub_s);
        VexValue *list = vval_list();
        for (size_t i = 0; i < abbr_count; i++) {
            VexValue *rec = vval_record();
            VexValue *n = vval_string_cstr(abbr_table[i].name);
            VexValue *v = vval_string_cstr(abbr_table[i].expansion);
            vval_record_set(rec, "name", n);
            vval_record_set(rec, "expansion", v);
            vval_release(n);
            vval_release(v);
            vval_list_push(list, rec);
            vval_release(rec);
        }
        return list;
    }

    vstr_free(&sub_s);
    return vval_error("unknown abbr subcommand");
}

typedef enum {
    COMP_KIND_FILES,
    COMP_KIND_DIRS,
    COMP_KIND_WORDS,
    COMP_KIND_COMMAND,
} CompSpecKind;

typedef struct {
    char *cmd_name;
    CompSpecKind kind;
    char **words;
    size_t word_count;
} CompSpec;

static CompSpec comp_specs[256];
static size_t comp_spec_count = 0;

static void comp_spec_register_words(const char *cmd, const char *const *word_list) {
    if (comp_spec_count >= 256) return;
    size_t n = 0;
    while (word_list[n]) n++;
    char **words = malloc(n * sizeof(char *));
    if (!words) return;
    for (size_t i = 0; i < n; i++)
        words[i] = strdup(word_list[i]);
    comp_specs[comp_spec_count].cmd_name = strdup(cmd);
    comp_specs[comp_spec_count].kind = COMP_KIND_WORDS;
    comp_specs[comp_spec_count].words = words;
    comp_specs[comp_spec_count].word_count = n;
    comp_spec_count++;
}

void plugin_register_completion(const char *cmd, const char *const *words) {
    comp_spec_register_words(cmd, words);
}

static void register_default_completions(void) {

    static const char *const git_cmds[] = {
        "add", "bisect", "branch", "checkout", "cherry-pick", "clean",
        "clone", "commit", "config", "diff", "fetch", "grep", "init",
        "log", "merge", "mv", "pull", "push", "rebase", "remote",
        "reset", "restore", "revert", "rm", "show", "stash", "status",
        "switch", "tag", "worktree", NULL
    };
    comp_spec_register_words("git", git_cmds);

    static const char *const docker_cmds[] = {
        "attach", "build", "commit", "compose", "container", "cp",
        "create", "diff", "events", "exec", "export", "history",
        "image", "images", "import", "info", "inspect", "kill",
        "load", "login", "logout", "logs", "network", "pause",
        "port", "ps", "pull", "push", "rename", "restart", "rm",
        "rmi", "run", "save", "search", "start", "stats", "stop",
        "system", "tag", "top", "unpause", "update", "version",
        "volume", "wait", NULL
    };
    comp_spec_register_words("docker", docker_cmds);

    static const char *const cargo_cmds[] = {
        "add", "bench", "build", "check", "clean", "clippy", "doc",
        "fetch", "fix", "fmt", "generate-lockfile", "init", "install",
        "locate-project", "login", "metadata", "new", "owner",
        "package", "pkgid", "publish", "read-manifest", "remove",
        "report", "run", "rustc", "rustdoc", "search", "test",
        "tree", "uninstall", "update", "vendor", "verify-project",
        "version", "yank", NULL
    };
    comp_spec_register_words("cargo", cargo_cmds);

    static const char *const npm_cmds[] = {
        "access", "adduser", "audit", "bugs", "cache", "ci",
        "completion", "config", "dedupe", "deprecate", "diff",
        "dist-tag", "docs", "doctor", "edit", "exec", "explain",
        "explore", "find-dupes", "fund", "help", "init", "install",
        "link", "ll", "login", "logout", "ls", "org", "outdated",
        "owner", "pack", "ping", "pkg", "prefix", "profile", "prune",
        "publish", "query", "rebuild", "repo", "restart", "root",
        "run", "run-script", "search", "set-script", "shrinkwrap",
        "star", "stars", "start", "stop", "team", "test", "token",
        "uninstall", "unpublish", "unstar", "update", "version",
        "view", "whoami", NULL
    };
    comp_spec_register_words("npm", npm_cmds);

    static const char *const ssh_opts[] = {
        "-1", "-2", "-4", "-6", "-A", "-a", "-C", "-f", "-G", "-g",
        "-K", "-k", "-M", "-N", "-n", "-q", "-s", "-T", "-t", "-V",
        "-v", "-W", "-w", "-X", "-x", "-Y", "-y",
        "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J",
        "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", NULL
    };
    comp_spec_register_words("ssh", ssh_opts);

    static const char *const systemctl_cmds[] = {
        "start", "stop", "restart", "reload", "enable", "disable",
        "status", "is-active", "is-enabled", "mask", "unmask",
        "daemon-reload", "list-units", "list-unit-files", "show",
        "cat", "edit", "isolate", "kill", "reset-failed", NULL
    };
    comp_spec_register_words("systemctl", systemctl_cmds);

    static const char *const make_cmds[] = {
        "all", "clean", "install", "uninstall", "test", "check",
        "dist", "distclean", "debug", NULL
    };
    comp_spec_register_words("make", make_cmds);

    static const char *const kubectl_cmds[] = {
        "apply", "attach", "auth", "autoscale", "certificate", "cluster-info",
        "completion", "config", "cordon", "cp", "create", "debug", "delete",
        "describe", "diff", "drain", "edit", "events", "exec", "explain",
        "expose", "get", "kustomize", "label", "logs", "patch", "plugin",
        "port-forward", "proxy", "replace", "rollout", "run", "scale",
        "set", "taint", "top", "uncordon", "version", "wait", NULL
    };
    comp_spec_register_words("kubectl", kubectl_cmds);

    static const char *const pip_cmds[] = {
        "install", "download", "uninstall", "freeze", "inspect", "list",
        "show", "check", "config", "debug", "wheel", "hash", "cache",
        "index", "search", NULL
    };
    comp_spec_register_words("pip", pip_cmds);
    comp_spec_register_words("pip3", pip_cmds);

    static const char *const grep_opts[] = {
        "-i", "--ignore-case", "-v", "--invert-match", "-c", "--count",
        "-l", "--files-with-matches", "-L", "--files-without-match",
        "-n", "--line-number", "-r", "--recursive", "-R",
        "-w", "--word-regexp", "-x", "--line-regexp",
        "-E", "--extended-regexp", "-F", "--fixed-strings", "-P", "--perl-regexp",
        "-o", "--only-matching", "-q", "--quiet", "--silent",
        "-H", "--with-filename", "-h", "--no-filename",
        "--include", "--exclude", "--exclude-dir",
        "-A", "-B", "-C", "--context", "--color", "--colour", NULL
    };
    comp_spec_register_words("grep", grep_opts);

    static const char *const find_opts[] = {
        "-name", "-iname", "-path", "-ipath", "-regex", "-iregex",
        "-type", "-size", "-mtime", "-atime", "-ctime", "-newer",
        "-user", "-group", "-perm", "-empty", "-maxdepth", "-mindepth",
        "-exec", "-execdir", "-ok", "-print", "-print0", "-delete",
        "-prune", "-not", "-and", "-or", "-ls", "-fls",
        "-follow", "-xdev", "-mount", NULL
    };
    comp_spec_register_words("find", find_opts);

    static const char *const curl_opts[] = {
        "-X", "--request", "-H", "--header", "-d", "--data", "--data-raw",
        "-o", "--output", "-O", "--remote-name", "-L", "--location",
        "-s", "--silent", "-S", "--show-error", "-v", "--verbose",
        "-k", "--insecure", "-u", "--user", "-A", "--user-agent",
        "-b", "--cookie", "-c", "--cookie-jar", "-e", "--referer",
        "-F", "--form", "-I", "--head", "-f", "--fail",
        "--compressed", "--connect-timeout", "--max-time",
        "-w", "--write-out", "--retry", "--retry-delay",
        "-x", "--proxy", "--cacert", "--cert", "--key", NULL
    };
    comp_spec_register_words("curl", curl_opts);

    static const char *const tar_opts[] = {
        "-c", "--create", "-x", "--extract", "-t", "--list",
        "-f", "--file", "-v", "--verbose", "-z", "--gzip",
        "-j", "--bzip2", "-J", "--xz", "--zstd",
        "-C", "--directory", "-k", "--keep-old-files",
        "--exclude", "--strip-components", "-p", "--preserve-permissions",
        "-r", "--append", "-u", "--update", NULL
    };
    comp_spec_register_words("tar", tar_opts);

    static const char *const rsync_opts[] = {
        "-a", "--archive", "-v", "--verbose", "-z", "--compress",
        "-r", "--recursive", "-n", "--dry-run", "--delete",
        "--exclude", "--include", "--progress", "-P",
        "-e", "--rsh", "-u", "--update", "--checksum",
        "--partial", "--bwlimit", "--backup", "--stats",
        "-h", "--human-readable", "-l", "--links", NULL
    };
    comp_spec_register_words("rsync", rsync_opts);

    static const char *const chmod_opts[] = {
        "-R", "--recursive", "-v", "--verbose", "-c", "--changes",
        "-f", "--silent", "--quiet", "--reference",
        "u+x", "u+r", "u+w", "g+x", "g+r", "g+w", "o+x", "o+r", "o+w",
        "a+x", "a+r", "a+w", "+x", "+r", "+w",
        "755", "644", "700", "600", "777", "775", "664", NULL
    };
    comp_spec_register_words("chmod", chmod_opts);

    static const char *const apt_cmds[] = {
        "install", "remove", "purge", "update", "upgrade", "full-upgrade",
        "autoremove", "search", "show", "list", "edit-sources",
        "depends", "rdepends", "policy", "download", "source",
        "build-dep", "satisfy", NULL
    };
    comp_spec_register_words("apt", apt_cmds);
    comp_spec_register_words("apt-get", apt_cmds);

    static const char *const pacman_opts[] = {
        "-S", "-Ss", "-Si", "-Sy", "-Syu", "-Syyu", "-Sc", "-Scc",
        "-R", "-Rs", "-Rns", "-Rn",
        "-Q", "-Qs", "-Qi", "-Ql", "-Qe", "-Qdt", "-Qo",
        "-U", "-F", "-Fy", NULL
    };
    comp_spec_register_words("pacman", pacman_opts);

    static const char *const brew_cmds[] = {
        "install", "uninstall", "reinstall", "upgrade", "update",
        "search", "info", "list", "outdated", "cleanup",
        "doctor", "config", "deps", "uses", "leaves",
        "tap", "untap", "pin", "unpin", "link", "unlink",
        "services", "cask", "--cask", NULL
    };
    comp_spec_register_words("brew", brew_cmds);

    static const char *const tmux_cmds[] = {
        "new-session", "new", "attach-session", "attach", "a",
        "detach-client", "detach", "kill-session", "kill-server",
        "list-sessions", "ls", "list-windows", "lsw",
        "list-panes", "lsp", "new-window", "neww",
        "split-window", "splitw", "select-pane", "selectp",
        "select-window", "selectw", "rename-session", "rename",
        "rename-window", "renamew", "send-keys", "send",
        "resize-pane", "resizep", "source-file", "source",
        "set-option", "set", "show-options", "show", NULL
    };
    comp_spec_register_words("tmux", tmux_cmds);

    static const char *const journalctl_opts[] = {
        "-u", "--unit", "-f", "--follow", "-n", "--lines",
        "-b", "--boot", "-k", "--dmesg", "-p", "--priority",
        "--since", "--until", "-o", "--output",
        "--no-pager", "--disk-usage", "--vacuum-size",
        "--vacuum-time", "--list-boots", "-r", "--reverse",
        "-e", "--pager-end", "-x", "--catalog", NULL
    };
    comp_spec_register_words("journalctl", journalctl_opts);

    static const char *const git_commit_opts[] = {
        "--message", "-m", "--all", "-a", "--amend", "--no-edit",
        "--signoff", "-s", "--verbose", "-v", "--dry-run",
        "--fixup", "--squash", "--reuse-message", "--allow-empty", NULL
    };
    comp_spec_register_words("git-commit", git_commit_opts);

    static const char *const git_checkout_opts[] = {
        "--branch", "-b", "--track", "-t", "--force", "-f",
        "--merge", "--detach", "--orphan", "--ours", "--theirs", NULL
    };
    comp_spec_register_words("git-checkout", git_checkout_opts);
    comp_spec_register_words("git-switch", git_checkout_opts);

    static const char *const git_log_opts[] = {
        "--oneline", "--graph", "--all", "--stat", "--patch", "-p",
        "--author", "--since", "--until", "--grep", "--follow",
        "--pretty", "--format", "--no-merges", "--first-parent",
        "-n", "--reverse", "--abbrev-commit", NULL
    };
    comp_spec_register_words("git-log", git_log_opts);

    static const char *const git_diff_opts[] = {
        "--staged", "--cached", "--stat", "--name-only", "--name-status",
        "--no-index", "--word-diff", "--color-words", "--check", NULL
    };
    comp_spec_register_words("git-diff", git_diff_opts);

    static const char *const git_push_opts[] = {
        "--force", "-f", "--force-with-lease", "--set-upstream", "-u",
        "--tags", "--all", "--dry-run", "--no-verify", "--delete", NULL
    };
    comp_spec_register_words("git-push", git_push_opts);
    comp_spec_register_words("git-pull", git_push_opts);

    static const char *const git_stash_opts[] = {
        "push", "pop", "apply", "drop", "list", "show", "clear",
        "--keep-index", "--include-untracked", "-u", "--message", "-m", NULL
    };
    comp_spec_register_words("git-stash", git_stash_opts);

    static const char *const git_rebase_opts[] = {
        "--interactive", "-i", "--onto", "--continue", "--abort",
        "--skip", "--autosquash", "--no-autosquash", NULL
    };
    comp_spec_register_words("git-rebase", git_rebase_opts);

    static const char *const git_remote_opts[] = {
        "add", "remove", "rename", "show", "get-url", "set-url",
        "prune", "-v", NULL
    };
    comp_spec_register_words("git-remote", git_remote_opts);

    static const char *const gcc_opts[] = {
        "-o", "-c", "-S", "-E", "-g", "-O0", "-O1", "-O2", "-O3", "-Os", "-Og",
        "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-Wno-unused",
        "-std=c99", "-std=c11", "-std=c17", "-std=c23",
        "-std=c++11", "-std=c++14", "-std=c++17", "-std=c++20", "-std=c++23",
        "-I", "-L", "-l", "-D", "-U", "-include", "-isystem",
        "-shared", "-fPIC", "-fPIE", "-pie", "-static",
        "-pthread", "-lm", "-ldl", "-lrt",
        "-fsanitize=address", "-fsanitize=undefined", "-fsanitize=thread",
        "-fno-omit-frame-pointer", "-march=native", "-mtune=native",
        "-MMD", "-MP", "-MF", "-MT", NULL
    };
    comp_spec_register_words("gcc", gcc_opts);
    comp_spec_register_words("g++", gcc_opts);
    comp_spec_register_words("cc", gcc_opts);
    comp_spec_register_words("c++", gcc_opts);

    static const char *const clang_extra[] = {
        "-o", "-c", "-S", "-E", "-g", "-O0", "-O1", "-O2", "-O3", "-Os", "-Oz",
        "-Wall", "-Wextra", "-Werror", "-Weverything",
        "-std=c99", "-std=c11", "-std=c17",
        "-std=c++11", "-std=c++14", "-std=c++17", "-std=c++20",
        "-I", "-L", "-l", "-D", "-fsanitize=address", "-fsanitize=undefined",
        "-fcolor-diagnostics", "-fansi-escape-codes",
        "-stdlib=libc++", "-stdlib=libstdc++", NULL
    };
    comp_spec_register_words("clang", clang_extra);
    comp_spec_register_words("clang++", clang_extra);

    static const char *const cmake_opts[] = {
        "--build", "--install", "--open", "--preset",
        "-S", "-B", "-G", "-D", "-U", "-C",
        "-DCMAKE_BUILD_TYPE=Debug", "-DCMAKE_BUILD_TYPE=Release",
        "-DCMAKE_BUILD_TYPE=RelWithDebInfo", "-DCMAKE_BUILD_TYPE=MinSizeRel",
        "-DCMAKE_INSTALL_PREFIX=", "-DCMAKE_C_COMPILER=",
        "-DCMAKE_CXX_COMPILER=", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        "--target", "--config", "--clean-first", "--parallel", "-j",
        "--verbose", "--", NULL
    };
    comp_spec_register_words("cmake", cmake_opts);

    static const char *const meson_cmds[] = {
        "setup", "configure", "compile", "test", "install", "dist",
        "subprojects", "wrap", "devenv", "rewrite", "init",
        "--buildtype=debug", "--buildtype=release", "--buildtype=plain",
        "--prefix=", "--backend=ninja", "--wipe", "--reconfigure", NULL
    };
    comp_spec_register_words("meson", meson_cmds);

    static const char *const ninja_opts[] = {
        "-j", "-k", "-l", "-n", "-v", "-d", "-t", "-w",
        "-C", "--version", "clean", NULL
    };
    comp_spec_register_words("ninja", ninja_opts);

    static const char *const python_opts[] = {
        "-c", "-m", "-u", "-v", "-V", "--version", "-W", "-x",
        "-i", "-O", "-OO", "-B", "-b", "-d", "-E", "-s", "-S",
        "-h", "--help", "--check-hash-based-pycs",
        "venv", "http.server", "json.tool", "pdb", "timeit",
        "unittest", "compileall", "ensurepip", "zipapp", NULL
    };
    comp_spec_register_words("python", python_opts);
    comp_spec_register_words("python3", python_opts);

    static const char *const pytest_opts[] = {
        "-v", "--verbose", "-q", "--quiet", "-x", "--exitfirst",
        "-s", "--capture=no", "-k", "--keyword", "-m", "--markers",
        "--tb=short", "--tb=long", "--tb=line", "--tb=no",
        "--co", "--collect-only", "--lf", "--last-failed",
        "--ff", "--failed-first", "-n", "--numprocesses",
        "--cov", "--cov-report", "--maxfail", "--durations",
        "-p", "--no-header", "--pdb", NULL
    };
    comp_spec_register_words("pytest", pytest_opts);

    static const char *const uv_cmds[] = {
        "init", "add", "remove", "sync", "lock", "run", "tool",
        "python", "pip", "venv", "build", "publish", "cache",
        "self", "version", "--help", NULL
    };
    comp_spec_register_words("uv", uv_cmds);

    static const char *const node_opts[] = {
        "-e", "--eval", "-p", "--print", "-c", "--check",
        "-v", "--version", "-h", "--help",
        "--inspect", "--inspect-brk", "--inspect-port",
        "--loader", "--experimental-modules", "--experimental-vm-modules",
        "--max-old-space-size", "--stack-size",
        "--enable-source-maps", "--trace-warnings",
        "--es-module-specifier-resolution", NULL
    };
    comp_spec_register_words("node", node_opts);

    static const char *const yarn_cmds[] = {
        "add", "remove", "install", "init", "run", "test", "build",
        "start", "info", "why", "upgrade", "upgrade-interactive",
        "outdated", "list", "link", "unlink", "pack", "publish",
        "cache", "config", "global", "workspace", "workspaces",
        "dlx", "exec", "plugin", "set", "--version", NULL
    };
    comp_spec_register_words("yarn", yarn_cmds);

    static const char *const pnpm_cmds[] = {
        "add", "install", "remove", "update", "link", "unlink",
        "import", "rebuild", "prune", "fetch", "dedupe",
        "run", "test", "start", "exec", "dlx", "create",
        "publish", "pack", "audit", "licenses", "why",
        "list", "outdated", "store", "server", "--filter", NULL
    };
    comp_spec_register_words("pnpm", pnpm_cmds);

    static const char *const npx_opts[] = {
        "--yes", "-y", "--no", "--package", "-p", "--call", "-c",
        "--shell", "--shell-auto-fallback", NULL
    };
    comp_spec_register_words("npx", npx_opts);

    static const char *const bun_cmds[] = {
        "run", "test", "build", "install", "add", "remove", "update",
        "link", "unlink", "init", "create", "upgrade", "repl",
        "pm", "x", "--version", "--help", NULL
    };
    comp_spec_register_words("bun", bun_cmds);

    static const char *const deno_cmds[] = {
        "run", "test", "bench", "compile", "bundle", "cache", "check",
        "completions", "coverage", "doc", "eval", "fmt", "info",
        "init", "install", "lint", "lsp", "repl", "task",
        "types", "uninstall", "upgrade", "vendor", NULL
    };
    comp_spec_register_words("deno", deno_cmds);

    static const char *const rustup_cmds[] = {
        "show", "update", "default", "toolchain", "target",
        "component", "override", "run", "which", "doc",
        "self", "set", "completions", NULL
    };
    comp_spec_register_words("rustup", rustup_cmds);

    static const char *const go_cmds[] = {
        "build", "clean", "doc", "env", "fix", "fmt", "generate",
        "get", "install", "list", "mod", "work", "run", "test",
        "tool", "version", "vet", NULL
    };
    comp_spec_register_words("go", go_cmds);

    static const char *const mvn_cmds[] = {
        "clean", "compile", "test", "package", "verify", "install",
        "deploy", "site", "dependency:tree", "dependency:resolve",
        "versions:display-dependency-updates",
        "-DskipTests", "-pl", "-am", "-amd", "-T", "-U", "-o",
        "-P", "-X", "--debug", NULL
    };
    comp_spec_register_words("mvn", mvn_cmds);

    static const char *const gradle_cmds[] = {
        "build", "clean", "test", "assemble", "check", "run",
        "dependencies", "tasks", "projects", "properties",
        "--info", "--debug", "--stacktrace", "--scan",
        "--parallel", "--daemon", "--no-daemon",
        "--build-cache", "--no-build-cache", "--refresh-dependencies",
        "-x", "--exclude-task", NULL
    };
    comp_spec_register_words("gradle", gradle_cmds);
    comp_spec_register_words("gradlew", gradle_cmds);
    comp_spec_register_words("./gradlew", gradle_cmds);

    static const char *const docker_compose_cmds[] = {
        "up", "down", "build", "start", "stop", "restart",
        "logs", "ps", "exec", "run", "pull", "push",
        "config", "create", "events", "images", "kill",
        "pause", "unpause", "port", "rm", "scale", "top",
        "-f", "--file", "-d", "--detach", "--build",
        "--force-recreate", "--no-deps", "--remove-orphans", NULL
    };
    comp_spec_register_words("docker-compose", docker_compose_cmds);

    static const char *const podman_cmds[] = {
        "attach", "build", "commit", "container", "cp", "create",
        "diff", "events", "exec", "export", "generate", "healthcheck",
        "history", "image", "images", "import", "info", "init",
        "inspect", "kill", "load", "login", "logout", "logs",
        "machine", "manifest", "mount", "network", "pause", "play",
        "pod", "port", "ps", "pull", "push", "rename", "restart",
        "rm", "rmi", "run", "save", "search", "secret", "start",
        "stats", "stop", "system", "tag", "top", "unmount",
        "unpause", "untag", "update", "version", "volume", "wait", NULL
    };
    comp_spec_register_words("podman", podman_cmds);

    static const char *const helm_cmds[] = {
        "completion", "create", "dependency", "env", "get", "history",
        "install", "lint", "list", "package", "plugin", "pull",
        "push", "registry", "repo", "rollback", "search", "show",
        "status", "template", "test", "uninstall", "upgrade",
        "verify", "version", NULL
    };
    comp_spec_register_words("helm", helm_cmds);

    static const char *const terraform_cmds[] = {
        "init", "plan", "apply", "destroy", "validate", "fmt",
        "show", "state", "output", "taint", "untaint", "import",
        "refresh", "graph", "workspace", "providers", "version",
        "-auto-approve", "-var", "-var-file", "-target",
        "-lock=false", "-parallelism", NULL
    };
    comp_spec_register_words("terraform", terraform_cmds);

    static const char *const ansible_cmds[] = {
        "-i", "--inventory", "-m", "--module-name", "-a", "--args",
        "-e", "--extra-vars", "-b", "--become", "-K", "--ask-become-pass",
        "-k", "--ask-pass", "-u", "--user", "-l", "--limit",
        "-t", "--tags", "--skip-tags", "-C", "--check", "-D", "--diff",
        "-v", "-vv", "-vvv", "-vvvv", "--list-hosts", "--list-tasks",
        "--syntax-check", "--forks", "-f", NULL
    };
    comp_spec_register_words("ansible", ansible_cmds);
    comp_spec_register_words("ansible-playbook", ansible_cmds);

    static const char *const vagrant_cmds[] = {
        "box", "cloud", "destroy", "global-status", "halt", "init",
        "login", "package", "plugin", "port", "powershell",
        "provision", "push", "rdp", "reload", "resume",
        "serve", "snapshot", "ssh", "ssh-config", "status",
        "suspend", "up", "upload", "validate", "version",
        "winrm", "winrm-config", NULL
    };
    comp_spec_register_words("vagrant", vagrant_cmds);

    static const char *const sed_opts[] = {
        "-e", "--expression", "-f", "--file", "-i", "--in-place",
        "-n", "--quiet", "--silent", "-r", "-E", "--regexp-extended",
        "-s", "--separate", "-z", "--null-data", "--posix",
        "--follow-symlinks", NULL
    };
    comp_spec_register_words("sed", sed_opts);

    static const char *const awk_opts[] = {
        "-F", "--field-separator", "-v", "--assign",
        "-f", "--file", "-o", "--pretty-print",
        "-O", "--optimize", "--posix", "--traditional",
        "--sandbox", "-b", "--characters-as-bytes", NULL
    };
    comp_spec_register_words("awk", awk_opts);
    comp_spec_register_words("gawk", awk_opts);

    static const char *const sort_opts[] = {
        "-r", "--reverse", "-n", "--numeric-sort", "-k", "--key",
        "-t", "--field-separator", "-u", "--unique",
        "-f", "--ignore-case", "-h", "--human-numeric-sort",
        "-M", "--month-sort", "-V", "--version-sort",
        "-s", "--stable", "-o", "--output",
        "-c", "--check", "-m", "--merge", NULL
    };
    comp_spec_register_words("sort", sort_opts);

    static const char *const uniq_opts[] = {
        "-c", "--count", "-d", "--repeated", "-D",
        "-f", "--skip-fields", "-i", "--ignore-case",
        "-s", "--skip-chars", "-u", "--unique",
        "-z", "--zero-terminated", "-w", "--check-chars", NULL
    };
    comp_spec_register_words("uniq", uniq_opts);

    static const char *const cut_opts[] = {
        "-b", "--bytes", "-c", "--characters", "-d", "--delimiter",
        "-f", "--fields", "-s", "--only-delimited",
        "--complement", "--output-delimiter",
        "-z", "--zero-terminated", NULL
    };
    comp_spec_register_words("cut", cut_opts);

    static const char *const tr_opts[] = {
        "-c", "-C", "--complement", "-d", "--delete",
        "-s", "--squeeze-repeats", "-t", "--truncate-set1",
        "[:upper:]", "[:lower:]", "[:digit:]", "[:alpha:]",
        "[:alnum:]", "[:space:]", "[:punct:]", NULL
    };
    comp_spec_register_words("tr", tr_opts);

    static const char *const xargs_opts[] = {
        "-0", "--null", "-I", "--replace", "-n", "--max-args",
        "-P", "--max-procs", "-d", "--delimiter",
        "-p", "--interactive", "-t", "--verbose",
        "-r", "--no-run-if-empty", "-L", "--max-lines",
        "-s", "--max-chars", NULL
    };
    comp_spec_register_words("xargs", xargs_opts);

    static const char *const diff_opts[] = {
        "-u", "--unified", "-c", "--context", "-y", "--side-by-side",
        "-r", "--recursive", "-q", "--brief", "-s", "--report-identical-files",
        "-i", "--ignore-case", "-w", "--ignore-all-space",
        "-B", "--ignore-blank-lines", "--color", "--no-color",
        "-N", "--new-file", "-a", "--text", "--strip-trailing-cr", NULL
    };
    comp_spec_register_words("diff", diff_opts);

    static const char *const patch_opts[] = {
        "-p0", "-p1", "-p2", "--strip", "-R", "--reverse",
        "--dry-run", "-b", "--backup", "-f", "--force",
        "-i", "--input", "-o", "--output", "-d", "--directory",
        "--verbose", "--quiet", "-N", "--forward", NULL
    };
    comp_spec_register_words("patch", patch_opts);

    static const char *const jq_opts[] = {
        "-r", "--raw-output", "-R", "--raw-input",
        "-c", "--compact-output", "-S", "--sort-keys",
        "-e", "--exit-status", "-s", "--slurp",
        "-n", "--null-input", "--arg", "--argjson",
        "--slurpfile", "--jsonargs", "--indent",
        "--tab", "--join-output", NULL
    };
    comp_spec_register_words("jq", jq_opts);

    static const char *const zip_opts[] = {
        "-r", "--recurse-paths", "-q", "--quiet", "-v", "--verbose",
        "-u", "--update", "-d", "--delete", "-e", "--encrypt",
        "-j", "--junk-paths", "-x", "--exclude",
        "-9", "-0", "-1", NULL
    };
    comp_spec_register_words("zip", zip_opts);

    static const char *const unzip_opts[] = {
        "-l", "-t", "-o", "-n", "-q", "-v", "-d",
        "-x", "-j", "-C", "-L", "-P", NULL
    };
    comp_spec_register_words("unzip", unzip_opts);

    static const char *const seven_z_cmds[] = {
        "a", "d", "e", "l", "rn", "t", "u", "x",
        "-o", "-p", "-r", "-t7z", "-tzip", "-tgzip", "-tbzip2",
        "-y", "-mx=0", "-mx=1", "-mx=5", "-mx=9", NULL
    };
    comp_spec_register_words("7z", seven_z_cmds);

    static const char *const gzip_opts[] = {
        "-d", "--decompress", "-c", "--stdout", "-k", "--keep",
        "-f", "--force", "-l", "--list", "-r", "--recursive",
        "-t", "--test", "-v", "--verbose", "-q", "--quiet",
        "-1", "--fast", "-9", "--best", NULL
    };
    comp_spec_register_words("gzip", gzip_opts);
    comp_spec_register_words("gunzip", gzip_opts);

    static const char *const zstd_opts[] = {
        "-d", "--decompress", "-c", "--stdout", "-k", "--keep",
        "-f", "--force", "-v", "--verbose", "-q", "--quiet",
        "-r", "--recursive", "-t", "--test", "--rm",
        "-1", "-3", "-5", "-9", "-19", "--fast", "--ultra",
        "-T0", "--threads", "--long", NULL
    };
    comp_spec_register_words("zstd", zstd_opts);

    static const char *const xz_opts[] = {
        "-d", "--decompress", "-c", "--stdout", "-k", "--keep",
        "-f", "--force", "-v", "--verbose", "-q", "--quiet",
        "-t", "--test", "-l", "--list", "-T", "--threads",
        "-0", "-1", "-6", "-9", "-e", "--extreme", NULL
    };
    comp_spec_register_words("xz", xz_opts);

    static const char *const wget_opts[] = {
        "-O", "--output-document", "-o", "--output-file",
        "-q", "--quiet", "-v", "--verbose", "-nv", "--no-verbose",
        "-c", "--continue", "-r", "--recursive", "-l", "--level",
        "-N", "--timestamping", "-np", "--no-parent",
        "-k", "--convert-links", "-p", "--page-requisites",
        "-P", "--directory-prefix", "-U", "--user-agent",
        "--no-check-certificate", "--limit-rate",
        "--spider", "--mirror", "-i", "--input-file",
        "--reject", "--accept", "--timeout", "--tries", NULL
    };
    comp_spec_register_words("wget", wget_opts);

    static const char *const ip_cmds[] = {
        "addr", "address", "addrlabel", "link", "maddr", "mroute",
        "neighbor", "neigh", "netns", "route", "rule", "tunnel",
        "tuntap", "xfrm", "monitor",
        "show", "add", "del", "change", "replace", "list",
        "-4", "-6", "-s", "-d", "-h", "-j", "-p", "-br", NULL
    };
    comp_spec_register_words("ip", ip_cmds);

    static const char *const ss_opts[] = {
        "-t", "--tcp", "-u", "--udp", "-l", "--listening",
        "-a", "--all", "-n", "--numeric", "-p", "--processes",
        "-e", "--extended", "-m", "--memory", "-o", "--options",
        "-s", "--summary", "-4", "-6", "-x", "--unix",
        "-i", "--info", "-H", "--no-header", NULL
    };
    comp_spec_register_words("ss", ss_opts);

    static const char *const ping_opts[] = {
        "-c", "--count", "-i", "--interval", "-W", "--timeout",
        "-s", "--size", "-t", "--ttl", "-q", "--quiet",
        "-f", "--flood", "-n", "--numeric", "-4", "-6",
        "-I", "--interface", "-v", "--verbose", NULL
    };
    comp_spec_register_words("ping", ping_opts);

    static const char *const dig_opts[] = {
        "+short", "+trace", "+nocmd", "+noall", "+answer",
        "+stats", "+comments", "+authority", "+additional",
        "+multiline", "+tcp", "+nssearch", "+dnssec",
        "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA",
        "SRV", "PTR", "ANY", "@", NULL
    };
    comp_spec_register_words("dig", dig_opts);

    static const char *const nmap_opts[] = {
        "-sS", "-sT", "-sU", "-sP", "-sn", "-sV", "-sC",
        "-O", "-A", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
        "-p", "-F", "--top-ports", "-oN", "-oX", "-oG", "-oA",
        "-v", "-vv", "-Pn", "--open", "--script",
        "--traceroute", "-iL", "--exclude", NULL
    };
    comp_spec_register_words("nmap", nmap_opts);

    static const char *const lsof_opts[] = {
        "-i", "-p", "-u", "-c", "-d", "-n", "-P",
        "-t", "-s", "-R", "+D", "+d", "-a",
        "-iTCP", "-iUDP", NULL
    };
    comp_spec_register_words("lsof", lsof_opts);

    static const char *const strace_opts[] = {
        "-p", "-f", "-ff", "-o", "-e", "-c", "-C",
        "-t", "-tt", "-ttt", "-T", "-v", "-V",
        "-s", "-x", "-xx", "-y", "-yy",
        "-e trace=", "-e signal=", "-e read=", "-e write=",
        "trace=network", "trace=file", "trace=process",
        "trace=signal", "trace=ipc", "trace=memory", NULL
    };
    comp_spec_register_words("strace", strace_opts);

    static const char *const htop_opts[] = {
        "-d", "--delay", "-u", "--user", "-p", "--pid",
        "-s", "--sort-key", "-C", "--no-color", "-t", "--tree",
        "-H", "--highlight-changes", NULL
    };
    comp_spec_register_words("htop", htop_opts);

    static const char *const kill_opts[] = {
        "-9", "-15", "-1", "-2", "-3", "-6",
        "-SIGKILL", "-SIGTERM", "-SIGHUP", "-SIGINT",
        "-SIGQUIT", "-SIGABRT", "-SIGSTOP", "-SIGCONT",
        "-SIGUSR1", "-SIGUSR2",
        "-s", "--signal", "-l", "--list", NULL
    };
    comp_spec_register_words("kill", kill_opts);

    static const char *const man_opts[] = {
        "-k", "--apropos", "-f", "--whatis", "-a", "--all",
        "-w", "--where", "--path", "-K", "--global-apropos",
        "-l", "--local-file", "-S", "--sections",
        "1", "2", "3", "4", "5", "6", "7", "8", "9", NULL
    };
    comp_spec_register_words("man", man_opts);

    static const char *const mount_opts[] = {
        "-t", "--types", "-o", "--options", "-a", "--all",
        "-r", "--read-only", "-w", "--rw", "-v", "--verbose",
        "-n", "--no-mtab", "-l", "--show-labels",
        "--bind", "--rbind", "--move", "--make-shared",
        "--make-private", "--make-slave", NULL
    };
    comp_spec_register_words("mount", mount_opts);
    comp_spec_register_words("umount", (const char *const[]){
        "-a", "--all", "-f", "--force", "-l", "--lazy",
        "-R", "--recursive", "-v", "--verbose", NULL
    });

    static const char *const lsblk_opts[] = {
        "-a", "--all", "-f", "--fs", "-l", "--list",
        "-o", "--output", "-p", "--paths", "-t", "--topology",
        "-n", "--noheadings", "-J", "--json", "-b", "--bytes",
        "-d", "--nodeps", "-S", "--scsi", NULL
    };
    comp_spec_register_words("lsblk", lsblk_opts);

    static const char *const fdisk_opts[] = {
        "-l", "--list", "-b", "--sector-size", "-o", "--output",
        "-t", "--type", "-u", "--units", "-C", "--cylinders",
        "-H", "--heads", "-S", "--sectors", NULL
    };
    comp_spec_register_words("fdisk", fdisk_opts);

    static const char *const dd_opts[] = {
        "if=", "of=", "bs=", "ibs=", "obs=", "count=", "skip=",
        "seek=", "conv=notrunc", "conv=sync", "conv=noerror",
        "status=progress", "status=none", "oflag=direct",
        "iflag=direct", "oflag=sync", NULL
    };
    comp_spec_register_words("dd", dd_opts);

    static const char *const vim_opts[] = {
        "-R", "-r", "-d", "-o", "-O", "-p", "-c", "-S",
        "-u", "-N", "-n", "-e", "-E", "-s", "-b",
        "+", "--cmd", "--noplugin", "--clean",
        "--startuptime", "--version", NULL
    };
    comp_spec_register_words("vim", vim_opts);
    comp_spec_register_words("nvim", vim_opts);
    comp_spec_register_words("vi", vim_opts);

    static const char *const less_opts[] = {
        "-N", "--LINE-NUMBERS", "-S", "--chop-long-lines",
        "-R", "--RAW-CONTROL-CHARS", "-i", "--ignore-case",
        "-I", "--IGNORE-CASE", "-F", "--quit-if-one-screen",
        "-X", "--no-init", "-g", "--hilite-search",
        "-n", "--line-numbers", "-J", "--status-column",
        "+F", "+G", NULL
    };
    comp_spec_register_words("less", less_opts);

    static const char *const svn_cmds[] = {
        "add", "blame", "cat", "changelist", "checkout", "cleanup",
        "commit", "copy", "delete", "diff", "export", "help",
        "import", "info", "list", "lock", "log", "merge",
        "mergeinfo", "mkdir", "move", "patch", "propdel",
        "propedit", "propget", "proplist", "propset",
        "relocate", "resolve", "resolved", "revert",
        "status", "switch", "unlock", "update", "upgrade", NULL
    };
    comp_spec_register_words("svn", svn_cmds);

    static const char *const gh_cmds[] = {
        "auth", "browse", "codespace", "gist", "issue", "org",
        "pr", "project", "release", "repo", "run", "workflow",
        "alias", "api", "completion", "config", "extension",
        "gpg-key", "label", "ruleset", "search", "secret",
        "ssh-key", "status", "variable", NULL
    };
    comp_spec_register_words("gh", gh_cmds);

    static const char *const ufw_cmds[] = {
        "enable", "disable", "status", "allow", "deny", "reject",
        "limit", "delete", "reset", "reload", "logging",
        "default", "app", "route", "prepend", "insert",
        "verbose", "numbered", NULL
    };
    comp_spec_register_words("ufw", ufw_cmds);

    static const char *const iptables_opts[] = {
        "-A", "--append", "-D", "--delete", "-I", "--insert",
        "-R", "--replace", "-L", "--list", "-F", "--flush",
        "-Z", "--zero", "-N", "--new-chain", "-X", "--delete-chain",
        "-P", "--policy", "-E", "--rename-chain",
        "-p", "--protocol", "-s", "--source", "-d", "--destination",
        "-j", "--jump", "-i", "--in-interface", "-o", "--out-interface",
        "--sport", "--dport", "-m", "--match",
        "ACCEPT", "DROP", "REJECT", "LOG", "MASQUERADE",
        "INPUT", "OUTPUT", "FORWARD", NULL
    };
    comp_spec_register_words("iptables", iptables_opts);

    static const char *const ffmpeg_opts[] = {
        "-i", "-f", "-c", "-c:v", "-c:a", "-b:v", "-b:a",
        "-r", "-s", "-an", "-vn", "-sn", "-y", "-n",
        "-ss", "-t", "-to", "-map", "-filter_complex",
        "-vf", "-af", "-preset", "-crf", "-qp",
        "copy", "libx264", "libx265", "libvpx-vp9", "aac",
        "libopus", "libmp3lame", "h264_nvenc", "hevc_nvenc",
        "-movflags", "+faststart", "-pix_fmt", "yuv420p",
        "-threads", "-loglevel", "quiet", "error", "info", NULL
    };
    comp_spec_register_words("ffmpeg", ffmpeg_opts);

    static const char *const convert_opts[] = {
        "-resize", "-crop", "-quality", "-strip", "-rotate",
        "-flip", "-flop", "-blur", "-sharpen", "-brightness-contrast",
        "-colorspace", "-type", "-depth", "-density", "-units",
        "-gravity", "-annotate", "-font", "-pointsize",
        "-fill", "-stroke", "-composite", "-append", "+append",
        "-thumbnail", "-extent", "-background", "-alpha", NULL
    };
    comp_spec_register_words("convert", convert_opts);
    comp_spec_register_words("magick", convert_opts);

    static const char *const openssl_cmds[] = {
        "enc", "dgst", "genrsa", "genpkey", "req", "x509",
        "verify", "s_client", "s_server", "ca", "pkcs12",
        "rsa", "ec", "ecparam", "rand", "passwd", "version",
        "-in", "-out", "-inform", "-outform",
        "-new", "-newkey", "-keyout", "-days", "-nodes",
        "-text", "-noout", "-pubkey", "-sha256", "-sha512",
        "-aes256", "-connect", "-servername", NULL
    };
    comp_spec_register_words("openssl", openssl_cmds);

    static const char *const ssh_keygen_opts[] = {
        "-t", "-b", "-C", "-f", "-N", "-p", "-l", "-E", "-R",
        "-y", "-e", "-i", "-m",
        "rsa", "ed25519", "ecdsa", "dsa",
        "-o", "-a", "-q", "-v", NULL
    };
    comp_spec_register_words("ssh-keygen", ssh_keygen_opts);

    static const char *const gpg_opts[] = {
        "--gen-key", "--full-gen-key", "--list-keys", "--list-secret-keys",
        "--sign", "--clearsign", "--detach-sign", "--verify",
        "--encrypt", "--decrypt", "--symmetric",
        "--armor", "-a", "--output", "-o", "--recipient", "-r",
        "--keyserver", "--send-keys", "--recv-keys", "--search-keys",
        "--import", "--export", "--export-secret-keys",
        "--delete-key", "--delete-secret-key",
        "--fingerprint", "--edit-key", "--keyid-format", "long", NULL
    };
    comp_spec_register_words("gpg", gpg_opts);
    comp_spec_register_words("gpg2", gpg_opts);

    static const char *const tee_opts[] = {
        "-a", "--append", "-i", "--ignore-interrupts",
        "-p", "--output-error", NULL
    };
    comp_spec_register_words("tee", tee_opts);

    static const char *const wc_opts[] = {
        "-c", "--bytes", "-m", "--chars", "-l", "--lines",
        "-w", "--words", "-L", "--max-line-length", NULL
    };
    comp_spec_register_words("wc", wc_opts);

    static const char *const head_opts[] = {
        "-n", "--lines", "-c", "--bytes", "-q", "--quiet",
        "-v", "--verbose", NULL
    };
    comp_spec_register_words("head", head_opts);
    comp_spec_register_words("tail", (const char *const[]){
        "-n", "--lines", "-c", "--bytes", "-f", "--follow",
        "-F", "-q", "--quiet", "-v", "--verbose",
        "--pid", "-s", "--sleep-interval", "--retry", NULL
    });

    static const char *const watch_opts[] = {
        "-n", "--interval", "-d", "--differences",
        "-t", "--no-title", "-b", "--beep", "-p", "--precise",
        "-e", "--errexit", "-c", "--color", "-x", "--exec", NULL
    };
    comp_spec_register_words("watch", watch_opts);

    static const char *const file_opts[] = {
        "-b", "--brief", "-i", "--mime", "--mime-type",
        "-L", "--dereference", "-z", "--uncompress",
        "-s", "--special-files", "-r", "--raw",
        "-k", "--keep-going", "-p", "--preserve-date", NULL
    };
    comp_spec_register_words("file", file_opts);

    static const char *const stat_opts[] = {
        "-c", "--format", "-f", "--file-system",
        "-L", "--dereference", "-t", "--terse", NULL
    };
    comp_spec_register_words("stat", stat_opts);

    static const char *const ln_opts[] = {
        "-s", "--symbolic", "-f", "--force", "-n", "--no-dereference",
        "-r", "--relative", "-v", "--verbose",
        "-b", "--backup", "-i", "--interactive", "-T", "--no-target-directory", NULL
    };
    comp_spec_register_words("ln", ln_opts);

    static const char *const cp_opts[] = {
        "-r", "-R", "--recursive", "-a", "--archive",
        "-f", "--force", "-i", "--interactive", "-n", "--no-clobber",
        "-u", "--update", "-v", "--verbose", "-l", "--link",
        "-s", "--symbolic-link", "-p", "--preserve",
        "-b", "--backup", "-T", "--no-target-directory", NULL
    };
    comp_spec_register_words("cp", cp_opts);

    static const char *const mv_opts[] = {
        "-f", "--force", "-i", "--interactive", "-n", "--no-clobber",
        "-u", "--update", "-v", "--verbose",
        "-b", "--backup", "-T", "--no-target-directory", NULL
    };
    comp_spec_register_words("mv", mv_opts);

    static const char *const rm_opts[] = {
        "-f", "--force", "-i", "--interactive", "-I",
        "-r", "-R", "--recursive", "-d", "--dir",
        "-v", "--verbose", "--no-preserve-root",
        "--preserve-root", "--one-file-system", NULL
    };
    comp_spec_register_words("rm", rm_opts);

    static const char *const mkdir_opts[] = {
        "-p", "--parents", "-m", "--mode", "-v", "--verbose",
        "-Z", "--context", NULL
    };
    comp_spec_register_words("mkdir", mkdir_opts);

    static const char *const chown_opts[] = {
        "-R", "--recursive", "-v", "--verbose", "-c", "--changes",
        "-f", "--silent", "--quiet", "--reference",
        "-h", "--no-dereference", "--from",
        "--preserve-root", "--no-preserve-root", NULL
    };
    comp_spec_register_words("chown", chown_opts);
    comp_spec_register_words("chgrp", chown_opts);

    static const char *const ls_opts[] = {
        "-l", "-a", "-A", "--all", "-h", "--human-readable",
        "-R", "--recursive", "-S", "--sort=size", "-t", "--sort=time",
        "-r", "--reverse", "-d", "--directory", "-i", "--inode",
        "-1", "--color", "--color=auto", "--color=always",
        "-F", "--classify", "-g", "-o", "--group-directories-first",
        "-n", "--numeric-uid-gid", NULL
    };
    comp_spec_register_words("ls", ls_opts);

    static const char *const du_opts[] = {
        "-h", "--human-readable", "-s", "--summarize",
        "-a", "--all", "-c", "--total", "-d", "--max-depth",
        "-k", "-m", "--si", "-b", "--bytes",
        "--exclude", "-x", "--one-file-system",
        "--apparent-size", "--time", "-L", "--dereference", NULL
    };
    comp_spec_register_words("du", du_opts);

    static const char *const df_opts[] = {
        "-h", "--human-readable", "-H", "--si",
        "-T", "--print-type", "-i", "--inodes",
        "-a", "--all", "-l", "--local",
        "-t", "--type", "-x", "--exclude-type",
        "--total", "--output", NULL
    };
    comp_spec_register_words("df", df_opts);

    static const char *const ps_opts[] = {
        "aux", "-ef", "-e", "--every", "-f", "--full",
        "-l", "--long", "-u", "--user", "-p", "--pid",
        "-C", "--command", "-o", "--format",
        "--forest", "--sort", "--no-headers",
        "-H", "--headers", NULL
    };
    comp_spec_register_words("ps", ps_opts);

    static const char *const free_opts[] = {
        "-h", "--human", "-b", "--bytes", "-k", "--kibi",
        "-m", "--mebi", "-g", "--gibi", "--tera",
        "-s", "--seconds", "-c", "--count",
        "-t", "--total", "-w", "--wide",
        "-l", "--lohi", "--si", NULL
    };
    comp_spec_register_words("free", free_opts);

    static const char *const gdb_opts[] = {
        "-p", "--pid", "-c", "--core", "-x", "--command",
        "-ex", "-iex", "--batch", "-batch-silent",
        "--args", "--tui", "-q", "--quiet", "--silent",
        "-d", "--directory", "-s", "--symbols",
        "--return-child-result", NULL
    };
    comp_spec_register_words("gdb", gdb_opts);

    static const char *const valgrind_opts[] = {
        "--tool=memcheck", "--tool=callgrind", "--tool=cachegrind",
        "--tool=massif", "--tool=helgrind", "--tool=drd",
        "--leak-check=full", "--leak-check=yes", "--leak-check=no",
        "--show-leak-kinds=all", "--track-origins=yes",
        "--gen-suppressions=all", "--suppressions=",
        "--log-file=", "-v", "--verbose", "-q", "--quiet",
        "--trace-children=yes", "--num-callers=",
        "--error-exitcode=", NULL
    };
    comp_spec_register_words("valgrind", valgrind_opts);

    static const char *const perf_cmds[] = {
        "stat", "record", "report", "annotate", "top",
        "bench", "test", "list", "diff", "evlist",
        "inject", "kmem", "kvm", "lock", "mem",
        "sched", "script", "timechart", "trace", NULL
    };
    comp_spec_register_words("perf", perf_cmds);

    static const char *const rg_opts[] = {
        "-i", "--ignore-case", "-S", "--smart-case",
        "-w", "--word-regexp", "-c", "--count",
        "-l", "--files-with-matches", "-L", "--files-without-match",
        "-n", "--line-number", "-N", "--no-line-number",
        "-t", "--type", "-T", "--type-not",
        "-g", "--glob", "--iglob",
        "-F", "--fixed-strings", "-e", "--regexp",
        "-r", "--replace", "-A", "-B", "-C", "--context",
        "-m", "--max-count", "--max-depth",
        "--hidden", "--no-ignore", "-u", "--unrestricted",
        "--json", "-p", "--pretty", "--sort", "--sortr",
        "--stats", "--trim", "--vimgrep", NULL
    };
    comp_spec_register_words("rg", rg_opts);

    static const char *const fd_opts[] = {
        "-H", "--hidden", "-I", "--no-ignore",
        "-u", "--unrestricted", "-s", "--case-sensitive",
        "-i", "--ignore-case", "-g", "--glob",
        "-F", "--fixed-strings", "-a", "--absolute-path",
        "-l", "--list-details", "-L", "--follow",
        "-p", "--full-path", "-t", "--type",
        "-e", "--extension", "-E", "--exclude",
        "-d", "--max-depth", "-x", "--exec",
        "-X", "--exec-batch", "-0", "--print0",
        "-c", "--color", "--changed-within", "--changed-before",
        "-S", "--size", "--strip-cwd-prefix", NULL
    };
    comp_spec_register_words("fd", fd_opts);
    comp_spec_register_words("fdfind", fd_opts);

    static const char *const fzf_opts[] = {
        "-m", "--multi", "-e", "--exact", "-i", "--no-sort",
        "--reverse", "--height", "--min-height",
        "--border", "--margin", "--padding",
        "--preview", "--preview-window", "--bind",
        "--header", "--header-lines", "--prompt",
        "--pointer", "--marker", "--ansi",
        "--delimiter", "-n", "--nth", "--with-nth",
        "--tac", "--no-mouse", "--cycle",
        "--print-query", "--expect", "--read0", "--print0", NULL
    };
    comp_spec_register_words("fzf", fzf_opts);

    static const char *const bat_opts[] = {
        "-l", "--language", "-n", "--number",
        "-p", "--plain", "-P", "--paging",
        "--style", "--theme", "--list-themes", "--list-languages",
        "-A", "--show-all", "-r", "--line-range",
        "-H", "--highlight-line", "--color",
        "--decorations", "--wrap", "--tabs",
        "-d", "--diff", "--diff-context", NULL
    };
    comp_spec_register_words("bat", bat_opts);
    comp_spec_register_words("batcat", bat_opts);

    static const char *const eza_opts[] = {
        "-l", "--long", "-a", "--all", "-A",
        "-1", "--oneline", "-G", "--grid", "-T", "--tree",
        "-R", "--recurse", "-F", "--classify",
        "--icons", "--no-icons", "--color", "--no-color",
        "-s", "--sort", "-r", "--reverse",
        "--group-directories-first", "--git", "--git-ignore",
        "-h", "--header", "-d", "--list-dirs",
        "-D", "--only-dirs", "-f", "--only-files",
        "--level", "--time-style", "--no-permissions",
        "--no-filesize", "--no-user", "--no-time", NULL
    };
    comp_spec_register_words("eza", eza_opts);
    comp_spec_register_words("exa", eza_opts);

    static const char *const psql_opts[] = {
        "-h", "--host", "-p", "--port", "-U", "--username",
        "-d", "--dbname", "-w", "--no-password", "-W", "--password",
        "-c", "--command", "-f", "--file",
        "-l", "--list", "-t", "--tuples-only",
        "-A", "--no-align", "-H", "--html",
        "-x", "--expanded", "-q", "--quiet",
        "-o", "--output", "-v", "--variable",
        "--csv", "-F", "--field-separator", NULL
    };
    comp_spec_register_words("psql", psql_opts);

    static const char *const mysql_opts[] = {
        "-h", "--host", "-P", "--port", "-u", "--user",
        "-p", "--password", "-D", "--database",
        "-e", "--execute", "-B", "--batch",
        "-N", "--skip-column-names", "-t", "--table",
        "-v", "--verbose", "--ssl-mode", "--default-character-set",
        "--connect-timeout", "--quick", NULL
    };
    comp_spec_register_words("mysql", mysql_opts);
    comp_spec_register_words("mariadb", mysql_opts);

    static const char *const redis_cli_opts[] = {
        "-h", "-p", "-a", "-n", "--user", "--pass",
        "--tls", "--cacert", "--cert", "--key",
        "-r", "-i", "-u", "--pipe", "--pipe-timeout",
        "--bigkeys", "--memkeys", "--scan", "--pattern",
        "--latency", "--intrinsic-latency", "--stat",
        "--cluster", "--json", "--resp2", "--resp3", NULL
    };
    comp_spec_register_words("redis-cli", redis_cli_opts);

    static const char *const sqlite3_opts[] = {
        "-bail", "-batch", "-column", "-csv", "-header", "-html",
        "-json", "-line", "-list", "-markdown", "-table",
        "-separator", "-nullvalue", "-cmd", "-init",
        "-echo", "-stats", "-readonly", "-memtrace", NULL
    };
    comp_spec_register_words("sqlite3", sqlite3_opts);

    static const char *const loginctl_cmds[] = {
        "list-sessions", "session-status", "show-session",
        "activate", "lock-session", "unlock-session",
        "terminate-session", "kill-session",
        "list-users", "user-status", "show-user",
        "enable-linger", "disable-linger", "terminate-user",
        "list-seats", "seat-status", "show-seat",
        "attach", "flush-devices", "terminate-seat", NULL
    };
    comp_spec_register_words("loginctl", loginctl_cmds);

    static const char *const timedatectl_cmds[] = {
        "status", "show", "set-time", "set-timezone",
        "list-timezones", "set-ntp", "timesync-status",
        "show-timesync", NULL
    };
    comp_spec_register_words("timedatectl", timedatectl_cmds);

    static const char *const hostnamectl_cmds[] = {
        "status", "hostname", "icon-name", "chassis",
        "deployment", "location", "set-hostname",
        "set-icon-name", "set-chassis", "set-deployment",
        "set-location", NULL
    };
    comp_spec_register_words("hostnamectl", hostnamectl_cmds);

    static const char *const resolvectl_cmds[] = {
        "query", "service", "openpgp", "tlsa",
        "status", "statistics", "reset-statistics",
        "flush-caches", "reset-server-features",
        "dns", "domain", "default-route", "llmnr",
        "mdns", "dnssec", "dnsovertls", "nta",
        "revert", "log-level", NULL
    };
    comp_spec_register_words("resolvectl", resolvectl_cmds);

    static const char *const git_add_opts[] = {
        "-A", "--all", "-p", "--patch", "-u", "--update",
        "-n", "--dry-run", "-v", "--verbose", "-f", "--force",
        "--intent-to-add", "-N", "--refresh",
        "--ignore-errors", "--ignore-missing", NULL
    };
    comp_spec_register_words("git-add", git_add_opts);

    static const char *const git_branch_opts[] = {
        "-a", "--all", "-r", "--remotes", "-d", "--delete",
        "-D", "--force", "-m", "--move", "-M", "-c", "--copy",
        "-v", "--verbose", "--list", "--no-merged", "--merged",
        "--contains", "--sort", "--format",
        "--set-upstream-to", "-u", "--unset-upstream",
        "--track", "--no-track", NULL
    };
    comp_spec_register_words("git-branch", git_branch_opts);

    static const char *const git_merge_opts[] = {
        "--no-ff", "--ff-only", "--squash", "--no-commit",
        "--abort", "--continue", "--quit",
        "--strategy", "-s", "--strategy-option", "-X",
        "--stat", "--no-stat", "--verify-signatures",
        "-m", "--message", NULL
    };
    comp_spec_register_words("git-merge", git_merge_opts);

    static const char *const git_reset_opts[] = {
        "--soft", "--mixed", "--hard", "--merge", "--keep",
        "-p", "--patch", "-q", "--quiet", NULL
    };
    comp_spec_register_words("git-reset", git_reset_opts);

    static const char *const git_tag_opts[] = {
        "-a", "--annotate", "-s", "--sign", "-d", "--delete",
        "-v", "--verify", "-l", "--list", "-n",
        "-f", "--force", "-m", "--message",
        "--sort", "--contains", "--no-contains",
        "--merged", "--no-merged", "--points-at", NULL
    };
    comp_spec_register_words("git-tag", git_tag_opts);

    static const char *const git_clone_opts[] = {
        "--depth", "--shallow-submodules", "--single-branch",
        "--branch", "-b", "--bare", "--mirror",
        "--recurse-submodules", "--shallow-since",
        "--filter", "--sparse", "--no-checkout",
        "-o", "--origin", "-j", "--jobs",
        "--reference", "--dissociate", NULL
    };
    comp_spec_register_words("git-clone", git_clone_opts);

    static const char *const git_config_opts[] = {
        "--global", "--local", "--system", "--worktree",
        "--list", "-l", "--get", "--get-all", "--unset",
        "--unset-all", "--edit", "-e",
        "user.name", "user.email", "core.editor",
        "core.autocrlf", "core.filemode",
        "pull.rebase", "push.default", "init.defaultBranch",
        "merge.tool", "diff.tool", "credential.helper", NULL
    };
    comp_spec_register_words("git-config", git_config_opts);

    static const char *const git_show_opts[] = {
        "--stat", "--name-only", "--name-status",
        "--format", "--pretty", "--oneline",
        "--no-patch", "-p", "--patch", NULL
    };
    comp_spec_register_words("git-show", git_show_opts);

    static const char *const git_clean_opts[] = {
        "-f", "--force", "-d", "-n", "--dry-run",
        "-x", "-X", "-e", "--exclude", "-q", "--quiet", NULL
    };
    comp_spec_register_words("git-clean", git_clean_opts);

    static const char *const git_worktree_opts[] = {
        "add", "list", "lock", "move", "prune",
        "remove", "repair", "unlock",
        "--force", "-b", "--detach", NULL
    };
    comp_spec_register_words("git-worktree", git_worktree_opts);

    static const char *const git_bisect_opts[] = {
        "start", "bad", "good", "new", "old",
        "reset", "skip", "run", "log", "replay",
        "visualize", "view", "terms", NULL
    };
    comp_spec_register_words("git-bisect", git_bisect_opts);

    static const char *const git_cherry_pick_opts[] = {
        "-e", "--edit", "-x", "-n", "--no-commit",
        "-m", "--mainline", "-s", "--signoff",
        "--continue", "--abort", "--quit", "--skip",
        "--strategy", "--strategy-option", NULL
    };
    comp_spec_register_words("git-cherry-pick", git_cherry_pick_opts);

    static const char *const git_fetch_opts[] = {
        "--all", "-p", "--prune", "--prune-tags", "-t", "--tags",
        "--no-tags", "--depth", "--shallow-since", "--shallow-exclude",
        "--unshallow", "-f", "--force", "-j", "--jobs",
        "--dry-run", "--set-upstream", NULL
    };
    comp_spec_register_words("git-fetch", git_fetch_opts);

    static const char *const git_submodule_opts[] = {
        "add", "status", "init", "deinit", "update", "set-branch",
        "set-url", "summary", "foreach", "sync", "absorbgitdirs",
        "--init", "--recursive", "--remote", "--force", NULL
    };
    comp_spec_register_words("git-submodule", git_submodule_opts);
}

static bool comp_defaults_loaded = false;

static void comp_ensure_defaults(void) {
    if (!comp_defaults_loaded) {
        comp_defaults_loaded = true;
        register_default_completions();
    }
}

const CompSpec *comp_spec_lookup(const char *cmd) {
    comp_ensure_defaults();
    for (size_t i = 0; i < comp_spec_count; i++) {
        if (strcmp(comp_specs[i].cmd_name, cmd) == 0)
            return &comp_specs[i];
    }
    return NULL;
}

size_t comp_spec_get_words(const char *cmd, const char ***words_out) {
    const CompSpec *spec = comp_spec_lookup(cmd);
    if (!spec || spec->kind != COMP_KIND_WORDS) return 0;
    *words_out = (const char **)spec->words;
    return spec->word_count;
}

int comp_spec_get_kind(const char *cmd) {
    const CompSpec *spec = comp_spec_lookup(cmd);
    if (!spec) return -1;
    return (int)spec->kind;
}

#define HELP_TRIED_MAX 256
static char *help_tried[HELP_TRIED_MAX];
static size_t help_tried_count = 0;

static bool help_already_tried(const char *cmd) {
    for (size_t i = 0; i < help_tried_count; i++)
        if (strcmp(help_tried[i], cmd) == 0) return true;
    return false;
}

static void help_mark_tried(const char *cmd) {
    if (help_tried_count < HELP_TRIED_MAX)
        help_tried[help_tried_count++] = strdup(cmd);
}

static char *run_help_capture(const char *cmd_path) {
    int pipefd[2];
    if (pipe(pipefd) != 0) return NULL;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }

        alarm(2);

        execlp(cmd_path, cmd_path, "--help", (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);

    size_t cap = 4096, len = 0;
    char *buf = vex_xmalloc(cap);

    for (;;) {
        if (len + 1024 > cap) {
            cap *= 2;
            if (cap > 65536) break;
            buf = vex_xrealloc(buf, cap);
        }
        ssize_t n = read(pipefd[0], buf + len, cap - len - 1);
        if (n <= 0) break;
        len += (size_t)n;
    }
    close(pipefd[0]);
    buf[len] = '\0';

    int status;
    waitpid(pid, &status, 0);

    /* Fallback to -h */
    if (len == 0) {
        free(buf);

        if (pipe(pipefd) != 0) return NULL;
        pid = fork();
        if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return NULL; }

        if (pid == 0) {
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            dup2(pipefd[1], STDERR_FILENO);
            close(pipefd[1]);
            int devnull = open("/dev/null", O_RDONLY);
            if (devnull >= 0) { dup2(devnull, STDIN_FILENO); close(devnull); }
            alarm(2);
            execlp(cmd_path, cmd_path, "-h", (char *)NULL);
            _exit(127);
        }

        close(pipefd[1]);
        cap = 4096; len = 0;
        buf = vex_xmalloc(cap);
        for (;;) {
            if (len + 1024 > cap) {
                cap *= 2;
                if (cap > 65536) break;
                buf = vex_xrealloc(buf, cap);
            }
            ssize_t n = read(pipefd[0], buf + len, cap - len - 1);
            if (n <= 0) break;
            len += (size_t)n;
        }
        close(pipefd[0]);
        buf[len] = '\0';
        waitpid(pid, &status, 0);
    }

    if (len == 0) { free(buf); return NULL; }
    return buf;
}

bool comp_spec_try_help(const char *cmd) {
    if (help_already_tried(cmd)) return false;
    help_mark_tried(cmd);

    if (builtin_exists(cmd)) return false;

    char *path = find_in_path(cmd);
    if (!path) return false;

    char *help_text = run_help_capture(path);
    free(path);
    if (!help_text) return false;

    HelpParseResult *parsed = help_parse_flags(help_text);
    free(help_text);

    if (!parsed || parsed->count == 0) {
        help_parse_free(parsed);
        return false;
    }

    if (comp_spec_count < 256) {
        char **words = malloc((parsed->count + 1) * sizeof(char *));
        for (size_t i = 0; i < parsed->count; i++)
            words[i] = strdup(parsed->flags[i].flag);
        words[parsed->count] = NULL;

        comp_specs[comp_spec_count].cmd_name = strdup(cmd);
        comp_specs[comp_spec_count].kind = COMP_KIND_WORDS;
        comp_specs[comp_spec_count].words = words;
        comp_specs[comp_spec_count].word_count = parsed->count;
        comp_spec_count++;
    }

    help_parse_free(parsed);
    return true;
}

#define MAX_COMP_CALLBACKS 64
static struct {
    char *command;
    VexValue *closure;
} comp_callbacks[MAX_COMP_CALLBACKS];
static size_t comp_callback_count = 0;

static EvalCtx *comp_eval_ctx = NULL;

void builtin_set_comp_ctx(EvalCtx *ctx) {
    comp_eval_ctx = ctx;
}

char **scope_complete_vars(const char *prefix, size_t *count) {
    if (!comp_eval_ctx) { *count = 0; return NULL; }

    size_t cap = 32;
    char **results = malloc(cap * sizeof(char *));
    *count = 0;
    size_t plen = strlen(prefix);

    Scope *s = comp_eval_ctx->current;
    while (s) {
        VexMapIter it = vmap_iter(&s->bindings);
        const char *key;
        VexValue *val;
        while (vmap_next(&it, &key, (void **)&val)) {

            if (strncmp(key, prefix, plen) == 0) {

                bool dup = false;
                for (size_t j = 0; j < *count; j++) {
                    if (strcmp(results[j], key) == 0) { dup = true; break; }
                }
                if (!dup) {
                    if (*count >= cap) {
                        cap *= 2;
                        char **tmp = realloc(results, cap * sizeof(char *));
                        if (!tmp) break;
                        results = tmp;
                    }
                    results[(*count)++] = strdup(key);
                }
            }
        }
        s = s->parent;
    }

    extern char **environ;
    for (char **e = environ; *e; e++) {
        const char *eq = strchr(*e, '=');
        if (!eq) continue;
        size_t nlen = (size_t)(eq - *e);
        if (nlen >= plen && strncmp(*e, prefix, plen) == 0) {
            char *name = malloc(nlen + 1);
            memcpy(name, *e, nlen);
            name[nlen] = '\0';
            bool dup = false;
            for (size_t j = 0; j < *count; j++) {
                if (strcmp(results[j], name) == 0) { dup = true; break; }
            }
            if (!dup) {
                if (*count >= cap) {
                    cap *= 2;
                    char **tmp = realloc(results, cap * sizeof(char *));
                    if (!tmp) break;
                    results = tmp;
                }
                results[(*count)++] = name;
            } else {
                free(name);
            }
        }
    }

    return results;
}

VexValue *builtin_complete_fn(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 2) return vval_error("complete-fn requires command name and closure");
    if (args[0]->type != VEX_VAL_STRING) return vval_error("command must be a string");
    if (args[1]->type != VEX_VAL_CLOSURE) return vval_error("handler must be a closure");

    if (comp_callback_count >= MAX_COMP_CALLBACKS)
        return vval_error("too many completion callbacks");

    const char *cmd = vstr_data(&args[0]->string);

    for (size_t i = 0; i < comp_callback_count; i++) {
        if (strcmp(comp_callbacks[i].command, cmd) == 0) {
            vval_release(comp_callbacks[i].closure);
            comp_callbacks[i].closure = vval_retain(args[1]);
            return vval_null();
        }
    }

    comp_callbacks[comp_callback_count].command = strdup(cmd);
    comp_callbacks[comp_callback_count].closure = vval_retain(args[1]);
    comp_callback_count++;
    return vval_null();
}

VexValue *comp_callback_query(const char *cmd, const char *prefix) {
    if (!comp_eval_ctx) return NULL;
    for (size_t i = 0; i < comp_callback_count; i++) {
        if (strcmp(comp_callbacks[i].command, cmd) == 0) {
            VexValue *arg = vval_string_cstr(prefix);
            VexValue *result = eval_call_closure(comp_eval_ctx, comp_callbacks[i].closure, &arg, 1);
            vval_release(arg);
            return result;
        }
    }
    return NULL;
}

VexValue *builtin_complete(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;

    if (argc == 0) {

        VexValue *list = vval_list();
        for (size_t i = 0; i < comp_spec_count; i++) {
            const char *kind_str = "unknown";
            switch (comp_specs[i].kind) {
            case COMP_KIND_FILES: kind_str = "files"; break;
            case COMP_KIND_DIRS: kind_str = "dirs"; break;
            case COMP_KIND_WORDS: kind_str = "words"; break;
            case COMP_KIND_COMMAND: kind_str = "commands"; break;
            }
            VexValue *rec = vval_record();
            VexValue *n = vval_string_cstr(comp_specs[i].cmd_name);
            VexValue *k = vval_string_cstr(kind_str);
            vval_record_set(rec, "command", n);
            vval_record_set(rec, "type", k);
            vval_release(n);
            vval_release(k);
            if (comp_specs[i].kind == COMP_KIND_WORDS && comp_specs[i].words) {
                VexValue *wl = vval_list();
                for (size_t j = 0; j < comp_specs[i].word_count; j++) {
                    VexValue *w = vval_string_cstr(comp_specs[i].words[j]);
                    vval_list_push(wl, w);
                    vval_release(w);
                }
                vval_record_set(rec, "words", wl);
                vval_release(wl);
            }
            vval_list_push(list, rec);
            vval_release(rec);
        }
        return list;
    }

    if (argc < 2) {
        vex_err("complete: expected kind and command name");
        return vval_error("usage: complete files|dirs|commands|words <words> <command>");
    }

    VexStr flag_str = vval_to_str(args[0]);
    const char *flag = vstr_data(&flag_str);

    CompSpecKind kind;
    char **words = NULL;
    size_t word_count = 0;
    size_t cmd_arg_idx = 1;

    if (strcmp(flag, "files") == 0) {
        kind = COMP_KIND_FILES;
    } else if (strcmp(flag, "dirs") == 0) {
        kind = COMP_KIND_DIRS;
    } else if (strcmp(flag, "commands") == 0) {
        kind = COMP_KIND_COMMAND;
    } else if (strcmp(flag, "words") == 0) {
        kind = COMP_KIND_WORDS;
        if (argc < 3) {
            vstr_free(&flag_str);
            vex_err("complete words: expected word list and command name");
            return vval_error("usage: complete words <words> <command>");
        }

        if (args[1]->type == VEX_VAL_LIST) {
            word_count = args[1]->list.len;
            words = malloc(word_count * sizeof(char *));
            for (size_t i = 0; i < word_count; i++) {
                VexStr ws = vval_to_str(((VexValue **)args[1]->list.data)[i]);
                words[i] = strdup(vstr_data(&ws));
                vstr_free(&ws);
            }
        } else {
            VexStr wstr = vval_to_str(args[1]);

            const char *p = vstr_data(&wstr);
            size_t cap = 16;
            words = malloc(cap * sizeof(char *));
            while (*p) {
                while (*p == ' ') p++;
                if (!*p) break;
                const char *start = p;
                while (*p && *p != ' ') p++;
                if (word_count >= cap) {
                    cap *= 2;
                    char **tmp = realloc(words, cap * sizeof(char *));
                    if (!tmp) break;
                    words = tmp;
                }
                words[word_count++] = strndup(start, (size_t)(p - start));
            }
            vstr_free(&wstr);
        }
        cmd_arg_idx = 2;
    } else {
        vstr_free(&flag_str);
        vex_err("complete: unknown kind '%s' (use files, dirs, commands, words)", flag);
        return vval_error("unknown kind");
    }
    vstr_free(&flag_str);

    if (cmd_arg_idx >= argc) {
        vex_err("complete: missing command name");
        for (size_t i = 0; i < word_count; i++) free(words[i]);
        free(words);
        return vval_error("missing command name");
    }

    VexStr cmd_str = vval_to_str(args[cmd_arg_idx]);
    const char *cmd = vstr_data(&cmd_str);

    CompSpec *existing = NULL;
    for (size_t i = 0; i < comp_spec_count; i++) {
        if (strcmp(comp_specs[i].cmd_name, cmd) == 0) {
            existing = &comp_specs[i];
            break;
        }
    }

    if (existing) {

        for (size_t i = 0; i < existing->word_count; i++) free(existing->words[i]);
        free(existing->words);
        existing->kind = kind;
        existing->words = words;
        existing->word_count = word_count;
    } else if (comp_spec_count < 128) {
        comp_specs[comp_spec_count].cmd_name = strdup(cmd);
        comp_specs[comp_spec_count].kind = kind;
        comp_specs[comp_spec_count].words = words;
        comp_specs[comp_spec_count].word_count = word_count;
        comp_spec_count++;
    } else {

        for (size_t i = 0; i < word_count; i++) free(words[i]);
        free(words);
        vstr_free(&cmd_str);
        vex_err("complete: completion table full (max 128)");
        return vval_error("completion table full");
    }

    vstr_free(&cmd_str);
    return vval_null();
}

#define TRAP_MAX 32

static struct {
    int signum;
    char *command;
} trap_table[TRAP_MAX];
static size_t trap_count = 0;

static volatile sig_atomic_t trap_pending[32];

static void trap_signal_handler(int sig) {
    if (sig >= 0 && sig < 32)
        trap_pending[sig] = 1;
}

static const struct { const char *name; int signum; } signal_names[] = {
    {"EXIT", 0},
    {"HUP",  SIGHUP},
    {"INT",  SIGINT},
    {"QUIT", SIGQUIT},
    {"TERM", SIGTERM},
    {"USR1", SIGUSR1},
    {"USR2", SIGUSR2},
    {NULL, 0}
};

static int signal_from_name(const char *name) {

    const char *n = name;
    if (strncmp(n, "SIG", 3) == 0) n += 3;
    for (int i = 0; signal_names[i].name; i++) {
        if (strcasecmp(signal_names[i].name, n) == 0)
            return signal_names[i].signum;
    }

    char *end;
    long num = strtol(name, &end, 10);
    if (*end == '\0' && num >= 0 && num < 32)
        return (int)num;
    return -1;
}

static const char *signal_to_name(int signum) {
    for (int i = 0; signal_names[i].name; i++) {
        if (signal_names[i].signum == signum)
            return signal_names[i].name;
    }
    return NULL;
}

const char *trap_lookup(int signum) {
    for (size_t i = 0; i < trap_count; i++) {
        if (trap_table[i].signum == signum)
            return trap_table[i].command;
    }
    return NULL;
}

const char *trap_get_exit_handler(void) {
    return trap_lookup(0);
}

void trap_check_pending(EvalCtx *ctx) {
    for (int sig = 1; sig < 32; sig++) {
        if (trap_pending[sig]) {
            trap_pending[sig] = 0;
            const char *cmd = trap_lookup(sig);
            if (cmd && cmd[0] != '\0') {

                Parser p = parser_init(cmd, ctx->arena);
                ASTNode *stmt = parser_parse_line(&p);
                if (stmt && !p.had_error) {
                    VexValue *result = eval(ctx, stmt);
                    vval_release(result);
                }
                arena_reset(ctx->arena);
            }
        }
    }
}

VexValue *builtin_trap(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;

    if (argc == 0) {
        for (size_t i = 0; i < trap_count; i++) {
            const char *name = signal_to_name(trap_table[i].signum);
            if (name) {
                if (trap_table[i].command[0] == '\0')
                    printf("trap -- '' %s\n", name);
                else
                    printf("trap -- '%s' %s\n", trap_table[i].command, name);
            } else {
                if (trap_table[i].command[0] == '\0')
                    printf("trap -- '' %d\n", trap_table[i].signum);
                else
                    printf("trap -- '%s' %d\n", trap_table[i].command, trap_table[i].signum);
            }
        }
        return vval_null();
    }

    if (argc < 2) {
        vex_err("trap: usage: trap [-] [command] [signal ...]");
        return vval_error("trap: invalid arguments");
    }

    VexStr action_str = vval_to_str(args[0]);
    const char *action = vstr_data(&action_str);

    for (size_t i = 1; i < argc; i++) {
        VexStr sig_str = vval_to_str(args[i]);
        int signum = signal_from_name(vstr_data(&sig_str));
        vstr_free(&sig_str);

        if (signum < 0) {
            VexStr tmp = vval_to_str(args[i]);
            vex_err("trap: unknown signal: %s", vstr_data(&tmp));
            vstr_free(&tmp);
            vstr_free(&action_str);
            return vval_error("trap: unknown signal");
        }

        if (strcmp(action, "-") == 0) {

            for (size_t j = 0; j < trap_count; j++) {
                if (trap_table[j].signum == signum) {
                    free(trap_table[j].command);
                    trap_table[j] = trap_table[--trap_count];
                    break;
                }
            }
            if (signum > 0) {

                if (signum == SIGINT || signum == SIGQUIT)
                    signal(signum, SIG_IGN);
                else
                    signal(signum, SIG_DFL);
                trap_pending[signum] = 0;
            }
        } else {

            size_t slot = trap_count;
            for (size_t j = 0; j < trap_count; j++) {
                if (trap_table[j].signum == signum) {
                    free(trap_table[j].command);
                    slot = j;
                    break;
                }
            }
            if (slot == trap_count) {
                if (trap_count >= TRAP_MAX) {
                    vex_err("trap: too many traps");
                    vstr_free(&action_str);
                    return vval_error("trap: too many traps");
                }
                trap_count++;
            }
            trap_table[slot].signum = signum;
            trap_table[slot].command = strdup(action);

            if (signum > 0) {
                if (action[0] == '\0') {

                    signal(signum, SIG_IGN);
                } else {
                    struct sigaction sa;
                    sa.sa_handler = trap_signal_handler;
                    sigemptyset(&sa.sa_mask);
                    sa.sa_flags = SA_RESTART;
                    sigaction(signum, &sa, NULL);
                }
                trap_pending[signum] = 0;
            }
        }
    }

    vstr_free(&action_str);
    return vval_null();
}

VexValue *builtin_hash(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input; (void)args; (void)argc;
    const char **names, **paths;
    size_t count = path_cache_list(&names, &paths);

    if (count == 0) {
        if (!ctx->in_pipeline) printf("hash: cache is empty\n");
        free(names);
        free(paths);
        return vval_list();
    }

    VexValue *list = vval_list();
    for (size_t i = 0; i < count; i++) {
        VexValue *rec = vval_record();
        VexValue *n = vval_string_cstr(names[i]);
        VexValue *p = vval_string_cstr(paths[i]);
        vval_record_set(rec, "name", n);
        vval_record_set(rec, "path", p);
        vval_release(n);
        vval_release(p);
        vval_list_push(list, rec);
        vval_release(rec);
    }

    if (!ctx->in_pipeline) {
        printf("\033[1m%-20s %s\033[0m\n", "command", "path");
        for (size_t i = 0; i < count; i++) {
            printf("%-20s %s\n", names[i], paths[i]);
        }
    }

    free(names);
    free(paths);
    return list;
}

VexValue *builtin_rehash(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    path_cache_clear();
    return vval_null();
}

VexValue *builtin_time(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc == 0) {
        vex_err("time: expected command");
        return vval_error("expected command");
    }

    VexStr cmd = vstr_empty();
    for (size_t i = 0; i < argc; i++) {
        if (i > 0) vstr_append_char(&cmd, ' ');
        VexStr s = vval_to_str(args[i]);
        if (i > 0) {
            vstr_append_char(&cmd, '"');
            vstr_append_str(&cmd, &s);
            vstr_append_char(&cmd, '"');
        } else {
            vstr_append_str(&cmd, &s);
        }
        vstr_free(&s);
    }

    struct timeval t_start, t_end;
    gettimeofday(&t_start, NULL);

    const char *src = vstr_data(&cmd);
    Parser p = parser_init(src, ctx->arena);
    ASTNode *stmt = parser_parse_line(&p);
    VexValue *result = vval_null();
    if (stmt && !p.had_error) {
        result = eval(ctx, stmt);
    }

    gettimeofday(&t_end, NULL);
    fflush(stdout);
    double elapsed = (double)(t_end.tv_sec - t_start.tv_sec) +
                     (double)(t_end.tv_usec - t_start.tv_usec) / 1000000.0;

    if (elapsed >= 60.0) {
        int mins = (int)(elapsed / 60.0);
        double secs = elapsed - mins * 60.0;
        fprintf(stderr, "\nreal\t%dm%.3fs\n", mins, secs);
    } else if (elapsed >= 1.0) {
        fprintf(stderr, "\nreal\t%.3fs\n", elapsed);
    } else {
        fprintf(stderr, "\nreal\t%.1fms\n", elapsed * 1000.0);
    }

    vstr_free(&cmd);
    return result;
}

VexValue *builtin_read(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;

    const char *prompt = NULL;
    bool silent = false;
    size_t start = 0;

    while (start < argc && args[start]->type == VEX_VAL_STRING) {
        const char *a = vstr_data(&args[start]->string);
        if (strcmp(a, "-p") == 0 && start + 1 < argc) {
            prompt = vstr_data(&args[start + 1]->string);
            start += 2;
        } else if (strcmp(a, "-s") == 0) {
            silent = true;
            start++;
        } else {
            break;
        }
    }

    if (start >= argc) {
        vex_err("read: expected variable name(s)");
        return vval_error("expected variable name(s)");
    }

    if (prompt) {
        fprintf(stderr, "%s", prompt);
        fflush(stderr);
    }

    char line[4096];
    if (input && input->type == VEX_VAL_STRING) {
        snprintf(line, sizeof(line), "%s", vstr_data(&input->string));
    } else {

        struct termios old_term, new_term;
        bool restored = false;
        if (silent && isatty(STDIN_FILENO)) {
            tcgetattr(STDIN_FILENO, &old_term);
            new_term = old_term;
            new_term.c_lflag &= ~(ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
            restored = true;
        }

        if (!fgets(line, sizeof(line), stdin)) {
            if (restored) {
                tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
                fprintf(stderr, "\n");
            }
            ctx->had_error = true;
            return vval_error("EOF");
        }
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';

        if (restored) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
            fprintf(stderr, "\n");
        }
    }

    size_t var_count = argc - start;
    if (var_count == 1) {

        const char *varname = vstr_data(&args[start]->string);
        VexValue *val = vval_string_cstr(line);
        scope_set(ctx->current, varname, val);
        vval_release(val);
    } else {

        const char *p = line;
        for (size_t i = 0; i < var_count; i++) {
            const char *varname = vstr_data(&args[start + i]->string);
            while (*p == ' ' || *p == '\t') p++;
            if (i == var_count - 1) {
                VexValue *val = vval_string_cstr(p);
                scope_set(ctx->current, varname, val);
                vval_release(val);
            } else {
                const char *word_start = p;
                while (*p && *p != ' ' && *p != '\t') p++;
                VexValue *val = vval_string(vstr_newn(word_start,
                                                      (size_t)(p - word_start)));
                scope_set(ctx->current, varname, val);
                vval_release(val);
            }
        }
    }

    return vval_string_cstr(line);
}

static EditState *global_editor = NULL;

void builtin_set_editor(void *e) {
    global_editor = (EditState *)e;
}

VexValue *builtin_history(EvalCtx *ctx, VexValue *input,
                           VexValue **args, size_t argc) {
    (void)input;
    if (!global_editor) {
        vex_err("history: not available in non-interactive mode");
        return vval_error("not available");
    }

    EditHistory *h = &global_editor->history;

    if (argc > 0 && args[0]->type == VEX_VAL_STRING &&
        strcmp(vstr_data(&args[0]->string), "clear") == 0) {
        for (size_t i = 0; i < h->count; i++) free(h->entries[i]);
        h->count = 0;
        return vval_null();
    }

    size_t show = h->count;
    if (argc > 0 && args[0]->type == VEX_VAL_INT && args[0]->integer > 0) {
        show = (size_t)args[0]->integer;
        if (show > h->count) show = h->count;
    }

    VexValue *list = vval_list();
    size_t start = h->count > show ? h->count - show : 0;
    for (size_t i = start; i < h->count; i++) {
        VexValue *rec = vval_record();
        VexValue *idx = vval_int((int64_t)i);
        VexValue *cmd = vval_string_cstr(h->entries[i]);
        vval_record_set(rec, "index", idx);
        vval_record_set(rec, "command", cmd);
        vval_release(idx);
        vval_release(cmd);
        vval_list_push(list, rec);
        vval_release(rec);
    }

    if (!ctx->in_pipeline) {
        for (size_t i = start; i < h->count; i++) {
            printf("%5zu  %s\n", i, h->entries[i]);
        }
    }

    return list;
}

VexValue *builtin_seq(EvalCtx *ctx, VexValue *input,
                       VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    int64_t start = 1, end_val = 1, step = 1;

    if (argc == 1 && args[0]->type == VEX_VAL_INT) {
        end_val = args[0]->integer;
    } else if (argc == 2 && args[0]->type == VEX_VAL_INT &&
               args[1]->type == VEX_VAL_INT) {
        start = args[0]->integer;
        end_val = args[1]->integer;
    } else if (argc == 3 && args[0]->type == VEX_VAL_INT &&
               args[1]->type == VEX_VAL_INT &&
               args[2]->type == VEX_VAL_INT) {
        start = args[0]->integer;
        step = args[1]->integer;
        end_val = args[2]->integer;
    } else {
        vex_err("seq: expected 1-3 integer arguments");
        return vval_error("expected integers");
    }

    if (step == 0) {
        vex_err("seq: step cannot be zero");
        return vval_error("step cannot be zero");
    }

    VexValue *list = vval_list();
    if (step > 0) {
        for (int64_t i = start; i <= end_val; i += step) {
            VexValue *v = vval_int(i);
            vval_list_push(list, v);
            vval_release(v);
        }
    } else {
        for (int64_t i = start; i >= end_val; i += step) {
            VexValue *v = vval_int(i);
            vval_list_push(list, v);
            vval_release(v);
        }
    }

    if (!ctx->in_pipeline) {
        for (size_t i = 0; i < list->list.len; i++) {
            VexValue *v = ((VexValue **)list->list.data)[i];
            printf("%ld\n", (long)v->integer);
        }
    }

    return list;
}

VexValue *builtin_sleep(EvalCtx *ctx, VexValue *input,
                         VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc == 0) {
        vex_err("sleep: expected duration (seconds)");
        return vval_error("expected duration");
    }

    double secs = 0.0;
    if (args[0]->type == VEX_VAL_INT) {
        secs = (double)args[0]->integer;
    } else if (args[0]->type == VEX_VAL_FLOAT) {
        secs = args[0]->floating;
    } else if (args[0]->type == VEX_VAL_STRING) {

        const char *s = vstr_data(&args[0]->string);
        char *endp;
        secs = strtod(s, &endp);
        if (*endp == 'm' && *(endp + 1) == 's') {
            secs /= 1000.0;
        }
    } else {
        vex_err("sleep: expected number");
        return vval_error("expected number");
    }

    if (secs <= 0) return vval_null();

    struct timespec ts;
    ts.tv_sec = (time_t)secs;
    ts.tv_nsec = (long)((secs - (double)ts.tv_sec) * 1e9);
    nanosleep(&ts, NULL);

    return vval_null();
}

VexValue *builtin_test(EvalCtx *ctx, VexValue *input,
                        VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1) {
        return vval_bool(false);
    }

    if (argc == 2 && args[0]->type == VEX_VAL_STRING &&
        args[1]->type == VEX_VAL_STRING) {
        const char *flag = vstr_data(&args[0]->string);
        const char *path = vstr_data(&args[1]->string);
        struct stat st;

        if (strcmp(flag, "-e") == 0) {
            return vval_bool(stat(path, &st) == 0);
        } else if (strcmp(flag, "-f") == 0) {
            return vval_bool(stat(path, &st) == 0 && S_ISREG(st.st_mode));
        } else if (strcmp(flag, "-d") == 0) {
            return vval_bool(stat(path, &st) == 0 && S_ISDIR(st.st_mode));
        } else if (strcmp(flag, "-L") == 0 || strcmp(flag, "-h") == 0) {
            return vval_bool(lstat(path, &st) == 0 && S_ISLNK(st.st_mode));
        } else if (strcmp(flag, "-r") == 0) {
            return vval_bool(access(path, R_OK) == 0);
        } else if (strcmp(flag, "-w") == 0) {
            return vval_bool(access(path, W_OK) == 0);
        } else if (strcmp(flag, "-x") == 0) {
            return vval_bool(access(path, X_OK) == 0);
        } else if (strcmp(flag, "-s") == 0) {
            return vval_bool(stat(path, &st) == 0 && st.st_size > 0);
        } else if (strcmp(flag, "-z") == 0) {

            return vval_bool(path[0] == '\0');
        } else if (strcmp(flag, "-n") == 0) {

            return vval_bool(path[0] != '\0');
        }
    }

    if (argc == 3 && args[1]->type == VEX_VAL_STRING) {
        const char *op = vstr_data(&args[1]->string);
        if (strcmp(op, "=") == 0 || strcmp(op, "==") == 0) {
            VexStr a = vval_to_str(args[0]);
            VexStr b = vval_to_str(args[2]);
            bool eq = vstr_eq(&a, &b);
            vstr_free(&a);
            vstr_free(&b);
            return vval_bool(eq);
        }
        if (strcmp(op, "!=") == 0) {
            VexStr a = vval_to_str(args[0]);
            VexStr b = vval_to_str(args[2]);
            bool neq = !vstr_eq(&a, &b);
            vstr_free(&a);
            vstr_free(&b);
            return vval_bool(neq);
        }

        if (args[0]->type == VEX_VAL_INT && args[2]->type == VEX_VAL_INT) {
            int64_t a = args[0]->integer, b = args[2]->integer;
            if (strcmp(op, "-eq") == 0) return vval_bool(a == b);
            if (strcmp(op, "-ne") == 0) return vval_bool(a != b);
            if (strcmp(op, "-lt") == 0) return vval_bool(a < b);
            if (strcmp(op, "-le") == 0) return vval_bool(a <= b);
            if (strcmp(op, "-gt") == 0) return vval_bool(a > b);
            if (strcmp(op, "-ge") == 0) return vval_bool(a >= b);
        }
    }

    if (argc == 1) {
        if (args[0]->type == VEX_VAL_STRING)
            return vval_bool(vstr_len(&args[0]->string) > 0);
        return vval_bool(vval_truthy(args[0]));
    }

    vex_err("test: unsupported expression");
    return vval_bool(false);
}

VexValue *builtin_is_file(EvalCtx *ctx, VexValue *input,
                           VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc == 0 || args[0]->type != VEX_VAL_STRING)
        return vval_bool(false);
    struct stat st;
    return vval_bool(stat(vstr_data(&args[0]->string), &st) == 0 &&
                     S_ISREG(st.st_mode));
}

VexValue *builtin_is_dir(EvalCtx *ctx, VexValue *input,
                          VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc == 0 || args[0]->type != VEX_VAL_STRING)
        return vval_bool(false);
    struct stat st;
    return vval_bool(stat(vstr_data(&args[0]->string), &st) == 0 &&
                     S_ISDIR(st.st_mode));
}

VexValue *builtin_file_exists(EvalCtx *ctx, VexValue *input,
                               VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc == 0 || args[0]->type != VEX_VAL_STRING)
        return vval_bool(false);
    struct stat st;
    return vval_bool(stat(vstr_data(&args[0]->string), &st) == 0);
}

VexValue *builtin_file_size(EvalCtx *ctx, VexValue *input,
                             VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc == 0 || args[0]->type != VEX_VAL_STRING)
        return vval_int(0);
    struct stat st;
    if (stat(vstr_data(&args[0]->string), &st) != 0) return vval_int(-1);
    return vval_int(st.st_size);
}

VexValue *builtin_basename(EvalCtx *ctx, VexValue *input,
                            VexValue **args, size_t argc) {
    const char *path = NULL;
    if (input && input->type == VEX_VAL_STRING)
        path = vstr_data(&input->string);
    else if (argc > 0 && args[0]->type == VEX_VAL_STRING)
        path = vstr_data(&args[0]->string);
    if (!path) return vval_error("basename: expected path");

    const char *slash = strrchr(path, '/');
    const char *base = slash ? slash + 1 : path;

    VexValue *result;

    if (argc > 1 && args[1]->type == VEX_VAL_STRING) {
        const char *suffix = vstr_data(&args[1]->string);
        size_t blen = strlen(base);
        size_t slen = strlen(suffix);
        if (slen < blen && strcmp(base + blen - slen, suffix) == 0) {
            result = vval_string(vstr_newn(base, blen - slen));
        } else {
            result = vval_string_cstr(base);
        }
    } else {
        result = vval_string_cstr(base);
    }

    if (!ctx->in_pipeline) {
        printf("%s\n", vstr_data(&result->string));
    }
    return result;
}

VexValue *builtin_dirname(EvalCtx *ctx, VexValue *input,
                           VexValue **args, size_t argc) {
    (void)argc;
    const char *path = NULL;
    if (input && input->type == VEX_VAL_STRING)
        path = vstr_data(&input->string);
    else if (argc > 0 && args[0]->type == VEX_VAL_STRING)
        path = vstr_data(&args[0]->string);
    if (!path) return vval_error("dirname: expected path");

    VexValue *result;
    const char *slash = strrchr(path, '/');
    if (!slash) result = vval_string_cstr(".");
    else if (slash == path) result = vval_string_cstr("/");
    else result = vval_string(vstr_newn(path, (size_t)(slash - path)));

    if (!ctx->in_pipeline) {
        printf("%s\n", vstr_data(&result->string));
    }
    return result;
}

VexValue *builtin_mkdir(EvalCtx *ctx, VexValue *input,
                         VexValue **args, size_t argc) {
    (void)input;

    if (has_flag_args(args, argc))
        return fallback_external(ctx, "mkdir", args, argc);
    if (argc == 0) {
        vex_err("mkdir: missing operand");
        return vval_error("missing operand");
    }
    for (size_t i = 0; i < argc; i++) {
        if (args[i]->type != VEX_VAL_STRING) continue;
        const char *dir = vstr_data(&args[i]->string);
        if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
            vex_err("mkdir: %s: %s", dir, strerror(errno));
            ctx->had_error = true;
            return vval_error(strerror(errno));
        }
    }
    return vval_null();
}

static bool copy_file(const char *src, const char *dst);

VexValue *builtin_rm(EvalCtx *ctx, VexValue *input,
                      VexValue **args, size_t argc) {
    (void)input;

    if (has_flag_args(args, argc))
        return fallback_external(ctx, "rm", args, argc);
    if (argc == 0) {
        vex_err("rm: missing operand");
        return vval_error("missing operand");
    }
    time_t now = time(NULL);
    const char *tdir = undo_get_trash_dir();
    for (size_t i = 0; i < argc; i++) {
        if (args[i]->type != VEX_VAL_STRING) continue;
        const char *path = vstr_data(&args[i]->string);

        char abs[4096];
        if (!realpath(path, abs)) {
            vex_err("rm: %s: %s", path, strerror(errno));
            ctx->had_error = true;
            return vval_error(strerror(errno));
        }

        const char *base = strrchr(abs, '/');
        base = base ? base + 1 : abs;
        char trash_path[4096];
        snprintf(trash_path, sizeof(trash_path), "%s/%ld_%s", tdir, (long)now, base);

        if (rename(abs, trash_path) == 0) {
            undo_push_rm(abs, trash_path, now);
        } else if (errno == EXDEV) {
            /* EXDEV: cross-device fallback */
            if (copy_file(abs, trash_path) && unlink(abs) == 0) {
                undo_push_rm(abs, trash_path, now);
            } else {
                vex_err("rm: %s: %s", path, strerror(errno));
                ctx->had_error = true;
                return vval_error(strerror(errno));
            }
        } else {
            if (unlink(path) != 0) {
                vex_err("rm: %s: %s", path, strerror(errno));
                ctx->had_error = true;
                return vval_error(strerror(errno));
            }
            vex_err("rm: warning: %s permanently deleted (could not move to trash)", path);
        }
    }
    return vval_null();
}

static bool copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) return false;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return false; }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        fwrite(buf, 1, n, out);
    }
    fclose(in);
    fclose(out);
    return true;
}

VexValue *builtin_cp(EvalCtx *ctx, VexValue *input,
                      VexValue **args, size_t argc) {
    (void)input;

    if (has_flag_args(args, argc))
        return fallback_external(ctx, "cp", args, argc);
    if (argc < 2) {
        vex_err("cp: expected source and destination");
        return vval_error("expected source and destination");
    }
    const char *src = vstr_data(&args[0]->string);
    const char *dst = vstr_data(&args[1]->string);
    if (!copy_file(src, dst)) {
        vex_err("cp: %s -> %s: %s", src, dst, strerror(errno));
        ctx->had_error = true;
        return vval_error(strerror(errno));
    }
    char abs_dst[4096];
    if (realpath(dst, abs_dst))
        undo_push_cp(abs_dst, time(NULL));
    return vval_null();
}

VexValue *builtin_mv(EvalCtx *ctx, VexValue *input,
                      VexValue **args, size_t argc) {
    (void)input;

    if (has_flag_args(args, argc))
        return fallback_external(ctx, "mv", args, argc);
    if (argc < 2) {
        vex_err("mv: expected source and destination");
        return vval_error("expected source and destination");
    }
    const char *src = vstr_data(&args[0]->string);
    const char *dst = vstr_data(&args[1]->string);
    char abs_src[4096];
    if (!realpath(src, abs_src)) {
        vex_err("mv: %s: %s", src, strerror(errno));
        ctx->had_error = true;
        return vval_error(strerror(errno));
    }
    if (rename(src, dst) != 0) {
        vex_err("mv: %s -> %s: %s", src, dst, strerror(errno));
        ctx->had_error = true;
        return vval_error(strerror(errno));
    }
    char abs_dst[4096];
    if (realpath(dst, abs_dst))
        undo_push_mv(abs_src, abs_dst, time(NULL));
    return vval_null();
}

VexValue *builtin_undo(EvalCtx *ctx, VexValue *input,
                        VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    char msg[4096];
    bool ok = undo_pop(msg, sizeof(msg));
    if (msg[0]) printf("%s\n", msg);
    return ok ? vval_null() : vval_error(msg);
}

VexValue *builtin_undo_list(EvalCtx *ctx, VexValue *input,
                             VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    size_t count = undo_count();
    if (count == 0) {
        printf("no undoable operations\n");
        return vval_null();
    }

    VexValue *list = vval_list();
    time_t now = time(NULL);

    for (size_t i = count; i > 0; i--) {
        const UndoEntry *e = undo_get(i - 1);
        if (!e) continue;

        VexValue *rec = vval_record();
        long ago = (long)(now - e->timestamp);
        char age[64];
        if (ago < 60) snprintf(age, sizeof(age), "%lds ago", ago);
        else if (ago < 3600) snprintf(age, sizeof(age), "%ldm ago", ago / 60);
        else snprintf(age, sizeof(age), "%ldh ago", ago / 3600);

        const char *op = e->kind == UNDO_RM ? "rm" :
                         e->kind == UNDO_MV ? "mv" : "cp";

        vval_record_set(rec, "op", vval_string_cstr(op));

        if (e->kind == UNDO_RM) {
            vval_record_set(rec, "path", vval_string_cstr(e->original_path));
        } else if (e->kind == UNDO_MV) {
            char desc[8192];
            snprintf(desc, sizeof(desc), "%s -> %s", e->original_path, e->dest_path);
            vval_record_set(rec, "path", vval_string_cstr(desc));
        } else {
            vval_record_set(rec, "path", vval_string_cstr(e->dest_path));
        }

        vval_record_set(rec, "age", vval_string_cstr(age));
        VexValue *op_v = vval_string_cstr(op);
        VexValue *age_v = vval_string_cstr(age);
        vval_release(op_v);
        vval_release(age_v);

        vval_list_push(list, rec);
        vval_release(rec);
    }

    return list;
}

static int parse_key_name(const char *name) {

    if (strncasecmp(name, "ctrl-", 5) == 0 && name[5] && !name[6]) {
        char c = (char)tolower(name[5]);
        return c - 'a' + 1;
    }
    if (strcasecmp(name, "up") == 0)     return KEY_UP;
    if (strcasecmp(name, "down") == 0)   return KEY_DOWN;
    if (strcasecmp(name, "left") == 0)   return KEY_LEFT;
    if (strcasecmp(name, "right") == 0)  return KEY_RIGHT;
    if (strcasecmp(name, "home") == 0)   return KEY_HOME;
    if (strcasecmp(name, "end") == 0)    return KEY_END;
    if (strcasecmp(name, "delete") == 0) return KEY_DELETE;
    if (strcasecmp(name, "tab") == 0)    return KEY_TAB;
    if (strcasecmp(name, "enter") == 0)  return KEY_ENTER;
    if (strcasecmp(name, "escape") == 0 || strcasecmp(name, "esc") == 0)
        return KEY_ESC;
    if (strcasecmp(name, "backspace") == 0) return KEY_BACKSPACE;
    if (strcasecmp(name, "pageup") == 0 || strcasecmp(name, "page-up") == 0)
        return KEY_PAGE_UP;
    if (strcasecmp(name, "pagedown") == 0 || strcasecmp(name, "page-down") == 0)
        return KEY_PAGE_DOWN;
    if (strcasecmp(name, "ctrl-left") == 0 || strcasecmp(name, "alt-b") == 0)
        return KEY_CTRL_LEFT;
    if (strcasecmp(name, "ctrl-right") == 0 || strcasecmp(name, "alt-f") == 0)
        return KEY_CTRL_RIGHT;
    return -1;
}

VexValue *builtin_bindkey(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (!global_editor) {
        vex_err("bindkey: not available in non-interactive mode");
        return vval_error("not available");
    }

    if (argc < 1) {

        VexValue *list = vval_list();
        for (size_t i = 0; i < global_editor->binding_count; i++) {
            VexValue *rec = vval_record();
            char keybuf[32];
            int k = global_editor->bindings[i].key;
            if (k >= 1 && k <= 26)
                snprintf(keybuf, sizeof(keybuf), "ctrl-%c", 'a' + k - 1);
            else if (k == KEY_UP)    snprintf(keybuf, sizeof(keybuf), "up");
            else if (k == KEY_DOWN)  snprintf(keybuf, sizeof(keybuf), "down");
            else if (k == KEY_LEFT)  snprintf(keybuf, sizeof(keybuf), "left");
            else if (k == KEY_RIGHT) snprintf(keybuf, sizeof(keybuf), "right");
            else snprintf(keybuf, sizeof(keybuf), "key-%d", k);

            VexValue *kv = vval_string_cstr(keybuf);
            VexValue *cv = vval_string_cstr(global_editor->bindings[i].command);
            vval_record_set(rec, "key", kv);
            vval_record_set(rec, "command", cv);
            vval_release(kv);
            vval_release(cv);
            vval_list_push(list, rec);
            vval_release(rec);
        }
        if (!ctx->in_pipeline) {
            for (size_t i = 0; i < global_editor->binding_count; i++) {
                char keybuf[32];
                int k = global_editor->bindings[i].key;
                if (k >= 1 && k <= 26)
                    snprintf(keybuf, sizeof(keybuf), "ctrl-%c", 'a' + k - 1);
                else
                    snprintf(keybuf, sizeof(keybuf), "key-%d", k);
                printf("%-12s -> %s\n", keybuf, global_editor->bindings[i].command);
            }
        }
        return list;
    }

    if (argc < 2) {
        vex_err("bindkey: usage: bindkey <key> <command>");
        return vval_error("usage: bindkey <key> <command>");
    }

    const char *key_name = vstr_data(&args[0]->string);
    const char *cmd = vstr_data(&args[1]->string);

    int key_code = parse_key_name(key_name);
    if (key_code < 0) {
        vex_err("bindkey: unknown key '%s'", key_name);
        return vval_error("unknown key");
    }

    for (size_t i = 0; i < global_editor->binding_count; i++) {
        if (global_editor->bindings[i].key == key_code) {
            free(global_editor->bindings[i].command);
            global_editor->bindings[i].command = strdup(cmd);
            return vval_null();
        }
    }

    if (global_editor->binding_count >= 32) {
        vex_err("bindkey: too many bindings (max 32)");
        return vval_error("too many bindings");
    }

    global_editor->bindings[global_editor->binding_count].key = key_code;
    global_editor->bindings[global_editor->binding_count].command = strdup(cmd);
    global_editor->binding_count++;
    return vval_null();
}

VexValue *builtin_true(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    ctx->last_exit_code = 0;
    return vval_bool(true);
}

VexValue *builtin_false_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input; (void)args; (void)argc;
    ctx->last_exit_code = 1;
    ctx->had_error = true;
    return vval_bool(false);
}

VexValue *builtin_clear(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    printf("\033[2J\033[H");
    fflush(stdout);
    return vval_null();
}

VexValue *builtin_yes(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    const char *text = "y";
    if (argc > 0 && args[0]->type == VEX_VAL_STRING) {
        text = vstr_data(&args[0]->string);
    }

    while (printf("%s\n", text) > 0) {

    }
    return vval_null();
}

VexValue *builtin_getopts(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;

    if (argc < 2) {
        vex_err("getopts: usage: getopts optstring varname [args...]");
        return vval_error("usage: getopts optstring varname");
    }

    const char *optstring = vstr_data(&args[0]->string);
    const char *varname   = vstr_data(&args[1]->string);

    VexValue *optind_val = scope_get(ctx->current, "OPTIND");
    int optind = 1;
    if (optind_val && optind_val->type == VEX_VAL_INT) {
        optind = (int)optind_val->integer;
    }

    size_t arg_start = 2;
    size_t arg_count = argc - arg_start;
    if (arg_count == 0) {

        VexValue *v = vval_string_cstr("?");
        scope_set(ctx->current, varname, v);
        vval_release(v);
        return vval_bool(false);
    }

    if ((size_t)optind > arg_count) {

        VexValue *v = vval_string_cstr("?");
        scope_set(ctx->current, varname, v);
        vval_release(v);
        return vval_bool(false);
    }

    const char *current_arg = vstr_data(&args[arg_start + optind - 1]->string);

    if (current_arg[0] != '-' || current_arg[1] == '\0') {

        VexValue *v = vval_string_cstr("?");
        scope_set(ctx->current, varname, v);
        vval_release(v);
        return vval_bool(false);
    }

    if (current_arg[1] == '-' && current_arg[2] == '\0') {

        optind++;
        VexValue *oi = vval_int(optind);
        scope_set(ctx->current, "OPTIND", oi);
        vval_release(oi);
        VexValue *v = vval_string_cstr("?");
        scope_set(ctx->current, varname, v);
        vval_release(v);
        return vval_bool(false);
    }

    char opt = current_arg[1];
    const char *spec = strchr(optstring, opt);

    if (!spec) {

        VexValue *v = vval_string_cstr("?");
        scope_set(ctx->current, varname, v);
        vval_release(v);
        VexValue *oa = vval_string(vstr_newn(&opt, 1));
        scope_set(ctx->current, "OPTARG", oa);
        vval_release(oa);
        optind++;
        VexValue *oi = vval_int(optind);
        scope_set(ctx->current, "OPTIND", oi);
        vval_release(oi);
        return vval_bool(true);
    }

    char optch[2] = {opt, '\0'};
    VexValue *v = vval_string_cstr(optch);
    scope_set(ctx->current, varname, v);
    vval_release(v);

    if (spec[1] == ':') {

        if (current_arg[2] != '\0') {

            VexValue *oa = vval_string_cstr(current_arg + 2);
            scope_set(ctx->current, "OPTARG", oa);
            vval_release(oa);
        } else {

            optind++;
            if ((size_t)optind > arg_count) {
                vex_err("getopts: option -%c requires argument", opt);
                VexValue *qv = vval_string_cstr("?");
                scope_set(ctx->current, varname, qv);
                vval_release(qv);
                VexValue *oi = vval_int(optind);
                scope_set(ctx->current, "OPTIND", oi);
                vval_release(oi);
                return vval_bool(false);
            }
            const char *optarg_str = vstr_data(&args[arg_start + optind - 1]->string);
            VexValue *oa = vval_string_cstr(optarg_str);
            scope_set(ctx->current, "OPTARG", oa);
            vval_release(oa);
        }
    }

    optind++;
    VexValue *oi = vval_int(optind);
    scope_set(ctx->current, "OPTIND", oi);
    vval_release(oi);
    return vval_bool(true);
}

VexValue *builtin_select_menu(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;

    VexValue *list = NULL;
    const char *prompt_str = "? ";

    if (input && input->type == VEX_VAL_LIST && vval_list_len(input) > 0) {
        list = input;
    } else if (argc > 0 && args[0]->type == VEX_VAL_LIST) {
        list = args[0];
    }

    for (size_t i = 0; i < argc; i++) {
        if (args[i]->type == VEX_VAL_STRING &&
            strcmp(vstr_data(&args[i]->string), "-p") == 0 && i + 1 < argc) {
            prompt_str = vstr_data(&args[i + 1]->string);
            break;
        }
    }

    if (!list) {
        vex_err("select-menu: expected a list");
        return vval_error("expected a list");
    }

    size_t count = vval_list_len(list);

    for (size_t i = 0; i < count; i++) {
        VexValue *item = vval_list_get(list, i);
        VexStr s = vval_to_str(item);
        fprintf(stderr, "  %zu) %s\n", i + 1, vstr_data(&s));
        vstr_free(&s);
    }

    fprintf(stderr, "%s", prompt_str);
    fflush(stderr);

    char buf[64];
    if (!fgets(buf, sizeof(buf), stdin)) {
        return vval_null();
    }
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';

    char *endp;
    long choice = strtol(buf, &endp, 10);
    if (endp == buf || choice < 1 || (size_t)choice > count) {
        return vval_null();
    }

    VexValue *selected = vval_list_get(list, (size_t)(choice - 1));
    vval_retain(selected);
    return selected;
}

VexValue *builtin_printf(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1) {
        vex_err("printf: expected format string");
        return vval_error("expected format string");
    }

    const char *fmt = vstr_data(&args[0]->string);
    VexStr out = vstr_empty();
    size_t ai = 1;

    for (const char *p = fmt; *p; p++) {
        if (*p == '%' && p[1]) {
            p++;

            char spec[32];
            int si = 0;
            spec[si++] = '%';

            while (*p == '-' || *p == '+' || *p == ' ' || *p == '0' || *p == '#') {
                if (si < 30) spec[si++] = *p;
                p++;
            }

            while (*p >= '0' && *p <= '9') {
                if (si < 30) spec[si++] = *p;
                p++;
            }

            if (*p == '.') {
                if (si < 30) spec[si++] = *p;
                p++;
                while (*p >= '0' && *p <= '9') {
                    if (si < 30) spec[si++] = *p;
                    p++;
                }
            }

            switch (*p) {
            case 's': {
                spec[si++] = 's'; spec[si] = '\0';
                const char *s = (ai < argc) ? vstr_data(&args[ai]->string) : "";
                char buf[4096];
                snprintf(buf, sizeof(buf), spec, s);
                vstr_append_cstr(&out, buf);
                ai++;
                break;
            }
            case 'd': case 'i': {
                spec[si++] = 'l'; spec[si++] = 'd'; spec[si] = '\0';
                int64_t v = 0;
                if (ai < argc) {
                    if (args[ai]->type == VEX_VAL_INT) v = args[ai]->integer;
                    else if (args[ai]->type == VEX_VAL_FLOAT) v = (int64_t)args[ai]->floating;
                    else if (args[ai]->type == VEX_VAL_STRING) v = strtol(vstr_data(&args[ai]->string), NULL, 10);
                }
                char buf[128];
                snprintf(buf, sizeof(buf), spec, v);
                vstr_append_cstr(&out, buf);
                ai++;
                break;
            }
            case 'f': case 'g': case 'e': {
                spec[si++] = *p; spec[si] = '\0';
                double v = 0.0;
                if (ai < argc) {
                    if (args[ai]->type == VEX_VAL_FLOAT) v = args[ai]->floating;
                    else if (args[ai]->type == VEX_VAL_INT) v = (double)args[ai]->integer;
                    else if (args[ai]->type == VEX_VAL_STRING) v = strtod(vstr_data(&args[ai]->string), NULL);
                }
                char buf[128];
                snprintf(buf, sizeof(buf), spec, v);
                vstr_append_cstr(&out, buf);
                ai++;
                break;
            }
            case 'x': case 'X': case 'o': {
                spec[si++] = 'l'; spec[si++] = *p; spec[si] = '\0';
                int64_t v = 0;
                if (ai < argc) {
                    if (args[ai]->type == VEX_VAL_INT) v = args[ai]->integer;
                    else if (args[ai]->type == VEX_VAL_STRING) v = strtol(vstr_data(&args[ai]->string), NULL, 10);
                }
                char buf[128];
                snprintf(buf, sizeof(buf), spec, v);
                vstr_append_cstr(&out, buf);
                ai++;
                break;
            }
            case '%':
                vstr_append_char(&out, '%');
                break;
            default:
                vstr_append_char(&out, '%');
                vstr_append_char(&out, *p);
                break;
            }
        } else if (*p == '\\') {

            p++;
            switch (*p) {
            case 'n': vstr_append_char(&out, '\n'); break;
            case 't': vstr_append_char(&out, '\t'); break;
            case 'r': vstr_append_char(&out, '\r'); break;
            case 'e': vstr_append_char(&out, '\033'); break;
            case '\\': vstr_append_char(&out, '\\'); break;
            case '\0': p--; break;
            default: vstr_append_char(&out, '\\'); vstr_append_char(&out, *p); break;
            }
        } else {
            vstr_append_char(&out, *p);
        }
    }

    if (!ctx->in_pipeline) {
        printf("%s", vstr_data(&out));
        fflush(stdout);
    }
    return vval_string(out);
}

VexValue *builtin_exec(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1) {
        vex_err("exec: expected command");
        return vval_error("expected command");
    }

    char **argv = malloc((argc + 1) * sizeof(char *));
    for (size_t i = 0; i < argc; i++) {
        VexStr s = vval_to_str(args[i]);
        argv[i] = strdup(vstr_data(&s));
        vstr_free(&s);
    }
    argv[argc] = NULL;

    const char *cmd = argv[0];
    char *resolved = NULL;
    if (cmd[0] != '/' && cmd[0] != '.') {
        resolved = find_in_path(cmd);
        if (resolved) cmd = resolved;
    }

    execvp(cmd, argv);

    vex_err("exec: %s: %s", argv[0], strerror(errno));
    for (size_t i = 0; i < argc; i++) free(argv[i]);
    free(argv);
    free(resolved);
    return vval_error(strerror(errno));
}

VexValue *builtin_eval(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1) {
        vex_err("eval: expected string to evaluate");
        return vval_error("expected string");
    }

    VexStr code = vstr_empty();
    for (size_t i = 0; i < argc; i++) {
        if (i > 0) vstr_append_char(&code, ' ');
        VexStr s = vval_to_str(args[i]);
        vstr_append_str(&code, &s);
        vstr_free(&s);
    }

    Parser p = parser_init(vstr_data(&code), ctx->arena);
    VexValue *result = vval_null();

    for (;;) {
        ASTNode *stmt = parser_parse_line(&p);
        if (!stmt || p.had_error) break;
        vval_release(result);
        result = eval(ctx, stmt);
    }

    vstr_free(&code);
    return result;
}

VexValue *builtin_date(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);

    if (argc > 0 && args[0]->type == VEX_VAL_STRING) {

        const char *fmt = vstr_data(&args[0]->string);

        if (fmt[0] == '+') fmt++;
        char buf[512];
        strftime(buf, sizeof(buf), fmt, tm);
        if (!ctx->in_pipeline) printf("%s\n", buf);
        return vval_string_cstr(buf);
    }

    VexValue *rec = vval_record();

    VexValue *v;
    v = vval_int(tm->tm_year + 1900);
    vval_record_set(rec, "year", v); vval_release(v);
    v = vval_int(tm->tm_mon + 1);
    vval_record_set(rec, "month", v); vval_release(v);
    v = vval_int(tm->tm_mday);
    vval_record_set(rec, "day", v); vval_release(v);
    v = vval_int(tm->tm_hour);
    vval_record_set(rec, "hour", v); vval_release(v);
    v = vval_int(tm->tm_min);
    vval_record_set(rec, "minute", v); vval_release(v);
    v = vval_int(tm->tm_sec);
    vval_record_set(rec, "second", v); vval_release(v);
    v = vval_int(tm->tm_wday);
    vval_record_set(rec, "weekday", v); vval_release(v);
    v = vval_int(tm->tm_yday + 1);
    vval_record_set(rec, "yearday", v); vval_release(v);
    v = vval_int((int64_t)now);
    vval_record_set(rec, "epoch", v); vval_release(v);

    static const char *wday_names[] = {
        "Sunday", "Monday", "Tuesday", "Wednesday",
        "Thursday", "Friday", "Saturday"
    };
    v = vval_string_cstr(wday_names[tm->tm_wday]);
    vval_record_set(rec, "weekday_name", v); vval_release(v);

    char iso[32];
    strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%S", tm);
    v = vval_string_cstr(iso);
    vval_record_set(rec, "iso", v); vval_release(v);

    return rec;
}

static bool random_seeded = false;

VexValue *builtin_random(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;

    if (!random_seeded) {
        srand((unsigned)time(NULL) ^ (unsigned)getpid());
        random_seeded = true;
    }

    if (argc == 0) {

        int64_t val = (int64_t)rand();
        if (!ctx->in_pipeline) printf("%ld\n", (long)val);
        return vval_int(val);
    }

    if (argc == 1 && args[0]->type == VEX_VAL_INT) {

        int64_t max = args[0]->integer;
        if (max <= 0) return vval_int(0);
        int64_t val = (int64_t)(rand() % (int)max);
        if (!ctx->in_pipeline) printf("%ld\n", (long)val);
        return vval_int(val);
    }

    if (argc == 2 && args[0]->type == VEX_VAL_INT && args[1]->type == VEX_VAL_INT) {

        int64_t lo = args[0]->integer;
        int64_t hi = args[1]->integer;
        if (hi < lo) { int64_t t = lo; lo = hi; hi = t; }
        int64_t range = hi - lo + 1;
        int64_t val = lo + (int64_t)(rand() % (int)range);
        if (!ctx->in_pipeline) printf("%ld\n", (long)val);
        return vval_int(val);
    }

    vex_err("random: usage: random [max] or random <min> <max>");
    return vval_error("invalid args");
}

VexValue *builtin_unset(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1) {
        vex_err("unset: expected variable name(s)");
        return vval_error("expected variable name(s)");
    }
    for (size_t i = 0; i < argc; i++) {
        const char *name = vstr_data(&args[i]->string);
        scope_del(ctx->current, name);
        unsetenv(name);
    }
    return vval_null();
}

VexValue *builtin_unalias(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1) {
        vex_err("unalias: expected alias name(s)");
        return vval_error("expected alias name(s)");
    }
    for (size_t i = 0; i < argc; i++) {
        const char *name = vstr_data(&args[i]->string);
        for (size_t j = 0; j < alias_count; j++) {
            if (strcmp(alias_table[j].name, name) == 0) {
                free(alias_table[j].name);
                free(alias_table[j].expansion);
                alias_table[j] = alias_table[alias_count - 1];
                alias_count--;
                break;
            }
        }
    }
    return vval_null();
}

VexValue *builtin_command(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1) {
        vex_err("command: expected command name");
        return vval_error("expected command name");
    }

    const char *cmd_name = vstr_data(&args[0]->string);

    char **argv = malloc((argc + 1) * sizeof(char *));
    for (size_t i = 0; i < argc; i++) {
        VexStr s = vval_to_str(args[i]);
        argv[i] = strdup(vstr_data(&s));
        vstr_free(&s);
    }
    argv[argc] = NULL;

    char *path = find_in_path(cmd_name);
    if (!path) {
        vex_err("command: %s: not found", cmd_name);
        for (size_t i = 0; i < argc; i++) free(argv[i]);
        free(argv);
        ctx->had_error = true;
        ctx->last_exit_code = 127;
        return vval_error("not found");
    }

    ctx->last_exit_code = exec_external(path, argv, -1, -1);
    for (size_t i = 0; i < argc; i++) free(argv[i]);
    free(argv);
    free(path);
    return vval_int(ctx->last_exit_code);
}

VexValue *builtin_wc(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (argc > 0)
        return fallback_external(ctx, "wc", args, argc);
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) {
        vex_err("wc: expected string input");
        return vval_error("expected string input");
    }

    const char *s = vstr_data(&input->string);
    size_t bytes = vstr_len(&input->string);
    size_t lines = 0, words = 0, chars = 0;
    bool in_word = false;

    for (const char *p = s; *p; ) {
        if (*p == '\n') lines++;
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
            in_word = false;
        } else if (!in_word) {
            in_word = true;
            words++;
        }

        unsigned char c = (unsigned char)*p;
        size_t clen = 1;
        if (c >= 0xF0) clen = 4;
        else if (c >= 0xE0) clen = 3;
        else if (c >= 0xC0) clen = 2;

        for (size_t ci = 1; ci < clen; ci++) {
            if (!p[ci]) { clen = ci; break; }
        }
        chars++;
        p += clen;
    }

    if (bytes > 0 && s[bytes - 1] != '\n') lines++;

    VexValue *rec = vval_record();
    VexValue *v;
    v = vval_int((int64_t)lines);
    vval_record_set(rec, "lines", v); vval_release(v);
    v = vval_int((int64_t)words);
    vval_record_set(rec, "words", v); vval_release(v);
    v = vval_int((int64_t)chars);
    vval_record_set(rec, "chars", v); vval_release(v);
    v = vval_int((int64_t)bytes);
    vval_record_set(rec, "bytes", v); vval_release(v);
    return rec;
}

VexValue *builtin_zip(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;

    VexValue *list_a = input;
    VexValue *list_b = (argc > 0) ? args[0] : NULL;

    if (!list_a || list_a->type != VEX_VAL_LIST ||
        !list_b || list_b->type != VEX_VAL_LIST) {
        vex_err("zip: expected two lists");
        return vval_error("expected two lists");
    }

    size_t len_a = list_a->list.len;
    size_t len_b = list_b->list.len;
    size_t min_len = len_a < len_b ? len_a : len_b;

    VexValue *result = vval_list();
    for (size_t i = 0; i < min_len; i++) {
        VexValue *pair = vval_list();
        vval_list_push(pair, list_a->list.data[i]);
        vval_list_push(pair, list_b->list.data[i]);
        vval_list_push(result, pair);
        vval_release(pair);
    }
    return result;
}

VexValue *builtin_group_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST || argc < 1) {
        vex_err("group-by: expected list and field name");
        return vval_error("expected list and field name");
    }

    const char *field = vstr_data(&args[0]->string);
    VexValue *result = vval_record();

    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];

        VexValue *key_val = NULL;
        if (item->type == VEX_VAL_RECORD) {
            key_val = vval_record_get(item, field);
        }
        VexStr key_str = key_val ? vval_to_str(key_val) : vstr_new("null");
        const char *key = vstr_data(&key_str);

        VexValue *group = vval_record_get(result, key);
        if (!group) {
            group = vval_list();
            vval_record_set(result, key, group);
            vval_release(group);
            group = vval_record_get(result, key);
        }
        vval_list_push(group, item);
        vstr_free(&key_str);
    }
    return result;
}

VexValue *builtin_merge(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_RECORD || argc < 1 ||
        args[0]->type != VEX_VAL_RECORD) {
        vex_err("merge: expected two records");
        return vval_error("expected two records");
    }

    VexValue *result = vval_record();

    VexMapIter it = vmap_iter(&input->record);
    const char *key;
    void *val;
    while (vmap_next(&it, &key, &val)) {
        vval_record_set(result, key, val);
    }

    it = vmap_iter(&args[0]->record);
    while (vmap_next(&it, &key, &val)) {
        vval_record_set(result, key, val);
    }

    return result;
}

VexValue *builtin_append(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("append: expected list input");
    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        vval_list_push(result, input->list.data[i]);
    }
    for (size_t i = 0; i < argc; i++) {
        vval_list_push(result, args[i]);
    }
    return result;
}

VexValue *builtin_prepend(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("prepend: expected list input");
    VexValue *result = vval_list();
    for (size_t i = 0; i < argc; i++) {
        vval_list_push(result, args[i]);
    }
    for (size_t i = 0; i < input->list.len; i++) {
        vval_list_push(result, input->list.data[i]);
    }
    return result;
}

static int sort_generic_compare(const void *a, const void *b) {
    VexValue *va = *(VexValue **)a;
    VexValue *vb = *(VexValue **)b;

    if (va->type == VEX_VAL_INT && vb->type == VEX_VAL_INT) {
        if (va->integer < vb->integer) return -1;
        if (va->integer > vb->integer) return 1;
        return 0;
    }
    if (va->type == VEX_VAL_FLOAT && vb->type == VEX_VAL_FLOAT) {
        if (va->floating < vb->floating) return -1;
        if (va->floating > vb->floating) return 1;
        return 0;
    }

    if ((va->type == VEX_VAL_INT || va->type == VEX_VAL_FLOAT) &&
        (vb->type == VEX_VAL_INT || vb->type == VEX_VAL_FLOAT)) {
        double da = va->type == VEX_VAL_INT ? (double)va->integer : va->floating;
        double db = vb->type == VEX_VAL_INT ? (double)vb->integer : vb->floating;
        if (da < db) return -1;
        if (da > db) return 1;
        return 0;
    }

    VexStr sa = vval_to_str(va);
    VexStr sb = vval_to_str(vb);
    int cmp = strcmp(vstr_data(&sa), vstr_data(&sb));
    vstr_free(&sa);
    vstr_free(&sb);
    return cmp;
}

VexValue *builtin_sort(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (has_flag_args(args, argc))
        return fallback_external(ctx, "sort", args, argc);
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("sort: expected list input");

    if (argc > 0 && args[0]->type == VEX_VAL_STRING) {
        return builtin_sort_by(ctx, input, args, argc);
    }

    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        vval_list_push(result, input->list.data[i]);
    }

    qsort(result->list.data, result->list.len, sizeof(void *), sort_generic_compare);
    return result;
}

VexValue *builtin_compact(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("compact: expected list input");

    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        if (item->type != VEX_VAL_NULL) {
            vval_list_push(result, item);
        }
    }
    return result;
}

static size_t display_width_str(const char *s) {
    size_t w = 0;
    bool in_esc = false;
    while (*s) {
        if (*s == '\033') { in_esc = true; s++; continue; }
        if (in_esc) {
            if ((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z')) in_esc = false;
            s++;
            continue;
        }
        w++;
        s++;
    }
    return w;
}

VexValue *builtin_to_table(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("to-table: expected list input");
    if (input->list.len == 0) return vval_string_cstr("");

    size_t col_cap = 32;
    char **cols = malloc(col_cap * sizeof(char *));
    size_t col_count = 0;

    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *row = input->list.data[i];
        if (row->type != VEX_VAL_RECORD) continue;
        VexMapIter it = vmap_iter(&row->record);
        const char *key;
        void *val;
        while (vmap_next(&it, &key, &val)) {
            bool found = false;
            for (size_t c = 0; c < col_count; c++) {
                if (strcmp(cols[c], key) == 0) { found = true; break; }
            }
            if (!found) {
                if (col_count >= col_cap) {
                    col_cap *= 2;
                    char **tmp = realloc(cols, col_cap * sizeof(char *));
                    if (!tmp) break;
                    cols = tmp;
                }
                cols[col_count++] = strdup(key);
            }
        }
    }

    if (col_count == 0) {
        free(cols);
        return vval_null();
    }

    size_t *widths = calloc(col_count, sizeof(size_t));
    for (size_t c = 0; c < col_count; c++) {
        widths[c] = strlen(cols[c]);
    }

    size_t row_count = input->list.len;
    char ***cells = malloc(row_count * sizeof(char **));
    for (size_t i = 0; i < row_count; i++) {
        cells[i] = malloc(col_count * sizeof(char *));
        VexValue *row = input->list.data[i];
        for (size_t c = 0; c < col_count; c++) {
            VexValue *val = (row->type == VEX_VAL_RECORD)
                ? vval_record_get(row, cols[c]) : NULL;
            if (val) {
                VexStr s = vval_to_str(val);
                cells[i][c] = strdup(vstr_data(&s));
                vstr_free(&s);
            } else {
                cells[i][c] = strdup("");
            }
            size_t w = display_width_str(cells[i][c]);
            if (w > widths[c]) widths[c] = w;
        }
    }

    VexStr out = vstr_empty();
    for (size_t c = 0; c < col_count; c++) {
        if (c > 0) vstr_append_cstr(&out, " | ");
        int pad = (int)widths[c] - (int)strlen(cols[c]);
        vstr_append_cstr(&out, cols[c]);
        for (int p = 0; p < pad; p++) vstr_append_char(&out, ' ');
    }
    vstr_append_char(&out, '\n');

    for (size_t c = 0; c < col_count; c++) {
        if (c > 0) vstr_append_cstr(&out, "-+-");
        for (size_t w = 0; w < widths[c]; w++) vstr_append_char(&out, '-');
    }
    vstr_append_char(&out, '\n');

    for (size_t i = 0; i < row_count; i++) {
        for (size_t c = 0; c < col_count; c++) {
            if (c > 0) vstr_append_cstr(&out, " | ");
            size_t w = display_width_str(cells[i][c]);
            vstr_append_cstr(&out, cells[i][c]);
            for (size_t p = w; p < widths[c]; p++) vstr_append_char(&out, ' ');
        }
        vstr_append_char(&out, '\n');
    }

    for (size_t i = 0; i < row_count; i++) {
        for (size_t c = 0; c < col_count; c++) free(cells[i][c]);
        free(cells[i]);
    }
    free(cells);
    free(widths);
    for (size_t c = 0; c < col_count; c++) free(cols[c]);
    free(cols);

    return vval_string(out);
}

VexValue *builtin_columns(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    VexValue *result = vval_list();

    if (input && input->type == VEX_VAL_RECORD) {
        VexMapIter it = vmap_iter(&input->record);
        const char *key;
        void *val;
        while (vmap_next(&it, &key, &val)) {
            VexValue *k = vval_string_cstr(key);
            vval_list_push(result, k);
            vval_release(k);
        }
    } else if (input && input->type == VEX_VAL_LIST && input->list.len > 0) {

        VexValue *first = input->list.data[0];
        if (first->type == VEX_VAL_RECORD) {
            VexMapIter it = vmap_iter(&first->record);
            const char *key;
            void *val;
            while (vmap_next(&it, &key, &val)) {
                VexValue *k = vval_string_cstr(key);
                vval_list_push(result, k);
                vval_release(k);
            }
        }
    }
    return result;
}

VexValue *builtin_values(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    VexValue *result = vval_list();

    if (input && input->type == VEX_VAL_RECORD) {
        VexMapIter it = vmap_iter(&input->record);
        const char *key;
        void *val;
        while (vmap_next(&it, &key, &val)) {
            VexValue *v = (VexValue *)val;
            vval_list_push(result, v);
        }
    }
    return result;
}

VexValue *builtin_update(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (argc < 2) {
        vex_err("update: expected field name and value/closure");
        return vval_error("expected field and value");
    }

    const char *field = vstr_data(&args[0]->string);

    if (input && input->type == VEX_VAL_RECORD) {
        VexValue *rec = vval_record();
        VexMapIter it = vmap_iter(&input->record);
        const char *key;
        void *val;
        while (vmap_next(&it, &key, &val)) {
            vval_record_set(rec, key, val);
        }
        if (args[1]->type == VEX_VAL_CLOSURE) {
            VexValue *old = vval_record_get(input, field);
            if (old) {
                VexValue *call_args[1] = { old };
                VexValue *new_val = eval_call_closure(ctx, args[1], call_args, 1);
                vval_record_set(rec, field, new_val);
                vval_release(new_val);
            }
        } else {
            vval_record_set(rec, field, args[1]);
        }
        return rec;
    }

    if (input && input->type == VEX_VAL_LIST) {
        VexValue *result = vval_list();
        for (size_t i = 0; i < input->list.len; i++) {
            VexValue *row = input->list.data[i];
            if (row->type != VEX_VAL_RECORD) {
                vval_list_push(result, row);
                continue;
            }
            VexValue *rec = vval_record();
            VexMapIter it = vmap_iter(&row->record);
            const char *key;
            void *val;
            while (vmap_next(&it, &key, &val)) {
                vval_record_set(rec, key, val);
            }
            if (args[1]->type == VEX_VAL_CLOSURE) {
                VexValue *old = vval_record_get(row, field);
                if (old) {
                    VexValue *call_args[1] = { old };
                    VexValue *new_val = eval_call_closure(ctx, args[1], call_args, 1);
                    vval_record_set(rec, field, new_val);
                    vval_release(new_val);
                }
            } else {
                vval_record_set(rec, field, args[1]);
            }
            vval_list_push(result, rec);
            vval_release(rec);
        }
        return result;
    }

    return vval_retain(input);
}

VexValue *builtin_insert(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (argc < 2) {
        vex_err("insert: expected field name and value");
        return vval_error("expected field and value");
    }

    const char *field = vstr_data(&args[0]->string);

    if (input && input->type == VEX_VAL_RECORD) {
        VexValue *rec = vval_record();
        VexMapIter it = vmap_iter(&input->record);
        const char *key;
        void *val;
        while (vmap_next(&it, &key, &val)) {
            vval_record_set(rec, key, val);
        }
        if (!vval_record_get(input, field)) {
            vval_record_set(rec, field, args[1]);
        }
        return rec;
    }

    if (input && input->type == VEX_VAL_LIST) {
        VexValue *result = vval_list();
        for (size_t i = 0; i < input->list.len; i++) {
            VexValue *row = input->list.data[i];
            if (row->type != VEX_VAL_RECORD) {
                vval_list_push(result, row);
                continue;
            }
            VexValue *rec = vval_record();
            VexMapIter it = vmap_iter(&row->record);
            const char *key;
            void *val;
            while (vmap_next(&it, &key, &val)) {
                vval_record_set(rec, key, val);
            }
            if (!vval_record_get(row, field)) {
                vval_record_set(rec, field, args[1]);
            }
            vval_list_push(result, rec);
            vval_release(rec);
        }
        return result;
    }

    return vval_retain(input);
}

VexValue *builtin_any(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST) return vval_bool(false);

    if (argc > 0 && args[0]->type == VEX_VAL_CLOSURE) {
        for (size_t i = 0; i < input->list.len; i++) {
            VexValue *call_args[1] = { input->list.data[i] };
            VexValue *result = eval_call_closure(ctx, args[0], call_args, 1);
            bool t = vval_truthy(result);
            vval_release(result);
            if (t) return vval_bool(true);
        }
        return vval_bool(false);
    }

    for (size_t i = 0; i < input->list.len; i++) {
        if (vval_truthy(input->list.data[i])) return vval_bool(true);
    }
    return vval_bool(false);
}

VexValue *builtin_all(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST) return vval_bool(true);

    if (argc > 0 && args[0]->type == VEX_VAL_CLOSURE) {
        for (size_t i = 0; i < input->list.len; i++) {
            VexValue *call_args[1] = { input->list.data[i] };
            VexValue *result = eval_call_closure(ctx, args[0], call_args, 1);
            bool t = vval_truthy(result);
            vval_release(result);
            if (!t) return vval_bool(false);
        }
        return vval_bool(true);
    }

    for (size_t i = 0; i < input->list.len; i++) {
        if (!vval_truthy(input->list.data[i])) return vval_bool(false);
    }
    return vval_bool(true);
}

VexValue *builtin_find(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if ((!input || input->type != VEX_VAL_LIST) && argc > 0)
        return fallback_external(ctx, "find", args, argc);
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST || argc < 1)
        return vval_null();

    if (args[0]->type == VEX_VAL_STRING) {

        const char *needle = vstr_data(&args[0]->string);
        VexValue *result = vval_list();
        for (size_t i = 0; i < input->list.len; i++) {
            VexValue *item = input->list.data[i];
            VexStr s = vval_to_str(item);
            if (strstr(vstr_data(&s), needle)) {
                vval_list_push(result, item);
            }
            vstr_free(&s);
        }
        return result;
    }

    if (args[0]->type == VEX_VAL_CLOSURE) {

        VexValue *result = vval_list();
        for (size_t i = 0; i < input->list.len; i++) {
            VexValue *call_args[1] = { input->list.data[i] };
            VexValue *r = eval_call_closure(ctx, args[0], call_args, 1);
            if (vval_truthy(r)) {
                vval_list_push(result, input->list.data[i]);
            }
            vval_release(r);
        }
        return result;
    }

    return vval_null();
}

VexValue *builtin_into_int(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_int(0);
    switch (input->type) {
    case VEX_VAL_INT:    return vval_retain(input);
    case VEX_VAL_FLOAT:  return vval_int((int64_t)input->floating);
    case VEX_VAL_BOOL:   return vval_int(input->boolean ? 1 : 0);
    case VEX_VAL_STRING: {
        char *end;
        int64_t v = strtol(vstr_data(&input->string), &end, 10);
        if (end == vstr_data(&input->string)) return vval_error("cannot convert to int");
        return vval_int(v);
    }
    default: return vval_error("cannot convert to int");
    }
}

VexValue *builtin_into_float(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_float(0.0);
    switch (input->type) {
    case VEX_VAL_FLOAT:  return vval_retain(input);
    case VEX_VAL_INT:    return vval_float((double)input->integer);
    case VEX_VAL_BOOL:   return vval_float(input->boolean ? 1.0 : 0.0);
    case VEX_VAL_STRING: {
        char *end;
        double v = strtod(vstr_data(&input->string), &end);
        if (end == vstr_data(&input->string)) return vval_error("cannot convert to float");
        return vval_float(v);
    }
    default: return vval_error("cannot convert to float");
    }
}

VexValue *builtin_into_string(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_string_cstr("null");
    VexStr s = vval_to_str(input);
    return vval_string(s);
}

VexValue *builtin_str_substring(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1) {
        vex_err("str-substring: expected string input and start index");
        return vval_error("expected string and start");
    }

    const char *s = vstr_data(&input->string);
    size_t slen = vstr_len(&input->string);

    int64_t start = 0;
    if (args[0]->type == VEX_VAL_INT) start = args[0]->integer;
    else if (args[0]->type == VEX_VAL_STRING) start = strtol(vstr_data(&args[0]->string), NULL, 10);

    if (start < 0) start = (int64_t)slen + start;
    if (start < 0) start = 0;
    if ((size_t)start >= slen) return vval_string_cstr("");

    size_t end = slen;
    if (argc >= 2) {
        int64_t len_or_end = 0;
        if (args[1]->type == VEX_VAL_INT) len_or_end = args[1]->integer;
        else if (args[1]->type == VEX_VAL_STRING) len_or_end = strtol(vstr_data(&args[1]->string), NULL, 10);

        if (len_or_end < 0) {
            end = (size_t)((int64_t)slen + len_or_end);
        } else {
            end = (size_t)start + (size_t)len_or_end;
        }
        if (end > slen) end = slen;
    }

    if ((size_t)start >= end) return vval_string_cstr("");
    return vval_string(vstr_newn(s + start, end - (size_t)start));
}

VexValue *builtin_chunks(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST || argc < 1) {
        vex_err("chunks: expected list and chunk size");
        return vval_error("expected list and size");
    }

    int64_t size = 1;
    if (args[0]->type == VEX_VAL_INT) size = args[0]->integer;
    if (size < 1) size = 1;

    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i += (size_t)size) {
        VexValue *chunk = vval_list();
        for (size_t j = 0; j < (size_t)size && i + j < input->list.len; j++) {
            vval_list_push(chunk, input->list.data[i + j]);
        }
        vval_list_push(result, chunk);
        vval_release(chunk);
    }
    return result;
}

VexValue *builtin_window(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST || argc < 1) {
        vex_err("window: expected list and window size");
        return vval_error("expected list and size");
    }

    int64_t size = 2;
    if (args[0]->type == VEX_VAL_INT) size = args[0]->integer;
    if (size < 1) size = 1;

    VexValue *result = vval_list();
    if (input->list.len < (size_t)size) return result;

    for (size_t i = 0; i + (size_t)size <= input->list.len; i++) {
        VexValue *win = vval_list();
        for (size_t j = 0; j < (size_t)size; j++) {
            vval_list_push(win, input->list.data[i + j]);
        }
        vval_list_push(result, win);
        vval_release(win);
    }
    return result;
}

VexValue *builtin_input(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;

    const char *prompt = "";
    bool silent = false;
    size_t pi = 0;

    while (pi < argc && args[pi]->type == VEX_VAL_STRING) {
        const char *a = vstr_data(&args[pi]->string);
        if (strcmp(a, "-s") == 0) { silent = true; pi++; continue; }
        break;
    }
    if (pi < argc && args[pi]->type == VEX_VAL_STRING) {
        prompt = vstr_data(&args[pi]->string);
    }

    if (prompt[0]) {
        fprintf(stderr, "%s", prompt);
        fflush(stderr);
    }

    struct termios old_term, new_term;
    bool restored = false;
    if (silent && isatty(STDIN_FILENO)) {
        tcgetattr(STDIN_FILENO, &old_term);
        new_term = old_term;
        new_term.c_lflag &= ~(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
        restored = true;
    }

    char line[4096];
    if (!fgets(line, sizeof(line), stdin)) {
        if (restored) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
            fprintf(stderr, "\n");
        }
        return vval_null();
    }
    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';

    if (restored) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        fprintf(stderr, "\n");
    }

    return vval_string_cstr(line);
}

VexValue *builtin_default(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (argc < 1) {
        fprintf(stderr, "default: expected default value\n");
        return vval_null();
    }

    if (!input || input->type == VEX_VAL_NULL) {
        return vval_retain(args[0]);
    }
    return vval_retain(input);
}

static void record_set_str(VexValue *rec, const char *key, const char *s) {
    VexValue *v = vval_string_cstr(s);
    vval_record_set(rec, key, v);
    vval_release(v);
}
static void record_set_int(VexValue *rec, const char *key, int64_t n) {
    VexValue *v = vval_int(n);
    vval_record_set(rec, key, v);
    vval_release(v);
}

VexValue *builtin_describe(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    VexValue *result = vval_record();
    if (!input || input->type == VEX_VAL_NULL) {
        record_set_str(result, "type", "null");
        return result;
    }
    switch (input->type) {
    case VEX_VAL_INT:
        record_set_str(result, "type", "int");
        break;
    case VEX_VAL_FLOAT:
        record_set_str(result, "type", "float");
        break;
    case VEX_VAL_STRING:
        record_set_str(result, "type", "string");
        record_set_int(result, "length", (int64_t)vstr_len(&input->string));
        break;
    case VEX_VAL_BOOL:
        record_set_str(result, "type", "bool");
        break;
    case VEX_VAL_LIST: {
        record_set_str(result, "type", "list");
        record_set_int(result, "length", (int64_t)vval_list_len(input));

        if (vval_list_len(input) > 0) {
            VexValue *first = vval_list_get(input, 0);
            if (first && first->type == VEX_VAL_RECORD) {
                VexValue *cols = vval_list();
                VexMapIter it = vmap_iter(&first->record);
                const char *key; void *val;
                while (vmap_next(&it, &key, &val)) {
                    VexValue *kv = vval_string_cstr(key);
                    vval_list_push(cols, kv);
                    vval_release(kv);
                }
                vval_record_set(result, "columns", cols);
                vval_release(cols);
            }
        }
        break;
    }
    case VEX_VAL_RECORD: {
        record_set_str(result, "type", "record");
        VexValue *cols = vval_list();
        VexMapIter it = vmap_iter(&input->record);
        const char *key; void *val;
        while (vmap_next(&it, &key, &val)) {
            VexValue *kv = vval_string_cstr(key);
            vval_list_push(cols, kv);
            vval_release(kv);
        }
        vval_record_set(result, "columns", cols);
        vval_release(cols);
        break;
    }
    case VEX_VAL_CLOSURE:
        record_set_str(result, "type", "closure");
        break;
    default:
        record_set_str(result, "type", "unknown");
        break;
    }
    return result;
}

VexValue *builtin_wrap(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (argc < 1) {
        fprintf(stderr, "wrap: expected field name\n");
        return vval_null();
    }
    const char *field = vstr_data(&args[0]->string);
    VexValue *rec = vval_record();
    if (input) {
        vval_record_set(rec, field, input);
    } else {
        VexValue *n = vval_null();
        vval_record_set(rec, field, n);
        vval_release(n);
    }
    return rec;
}

VexValue *builtin_do(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (argc < 1 || args[0]->type != VEX_VAL_CLOSURE) {
        fprintf(stderr, "do: expected closure argument\n");
        return vval_null();
    }

    size_t call_argc = (input && input->type != VEX_VAL_NULL) ? 1 + (argc - 1) : (argc - 1);
    VexValue **call_args = NULL;
    if (call_argc > 0) {
        call_args = malloc(call_argc * sizeof(VexValue *));
        size_t idx = 0;
        if (input && input->type != VEX_VAL_NULL)
            call_args[idx++] = input;
        for (size_t i = 1; i < argc; i++)
            call_args[idx++] = args[i];
    }
    VexValue *result = eval_call_closure(ctx, args[0], call_args, call_argc);
    free(call_args);
    return result;
}

VexValue *builtin_is_empty(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type == VEX_VAL_NULL) return vval_bool(true);
    switch (input->type) {
    case VEX_VAL_STRING:
        return vval_bool(vstr_len(&input->string) == 0);
    case VEX_VAL_LIST:
        return vval_bool(vval_list_len(input) == 0);
    case VEX_VAL_RECORD: {
        VexMapIter it = vmap_iter(&input->record);
        const char *key; void *val;
        return vval_bool(!vmap_next(&it, &key, &val));
    }
    default:
        return vval_bool(false);
    }
}

VexValue *builtin_str_index_of(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_STRING) {
        fprintf(stderr, "str-index-of: expected string input and search argument\n");
        return vval_int(-1);
    }
    const char *haystack = vstr_data(&input->string);
    const char *needle = vstr_data(&args[0]->string);
    const char *found = strstr(haystack, needle);
    if (!found) return vval_int(-1);
    return vval_int((int64_t)(found - haystack));
}

VexValue *builtin_str_pad_left(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1) {
        fprintf(stderr, "str-pad-left: expected string input and width\n");
        return input ? vval_retain(input) : vval_null();
    }
    int64_t width = 0;
    if (args[0]->type == VEX_VAL_INT) width = args[0]->integer;
    else if (args[0]->type == VEX_VAL_STRING) width = strtol(vstr_data(&args[0]->string), NULL, 10);

    const char *fill = " ";
    if (argc >= 2 && args[1]->type == VEX_VAL_STRING)
        fill = vstr_data(&args[1]->string);

    const char *s = vstr_data(&input->string);
    size_t slen = vstr_len(&input->string);
    if ((int64_t)slen >= width) return vval_retain(input);

    size_t pad_chars = (size_t)(width - (int64_t)slen);
    size_t fill_len = strlen(fill);
    if (fill_len == 0) return vval_retain(input);

    size_t total = pad_chars + slen + 1;
    char *buf = malloc(total);
    size_t pos = 0;
    for (size_t i = 0; i < pad_chars; i++) {
        buf[pos++] = fill[i % fill_len];
    }
    memcpy(buf + pos, s, slen);
    buf[pos + slen] = '\0';
    VexValue *result = vval_string_cstr(buf);
    free(buf);
    return result;
}

VexValue *builtin_str_pad_right(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1) {
        fprintf(stderr, "str-pad-right: expected string input and width\n");
        return input ? vval_retain(input) : vval_null();
    }
    int64_t width = 0;
    if (args[0]->type == VEX_VAL_INT) width = args[0]->integer;
    else if (args[0]->type == VEX_VAL_STRING) width = strtol(vstr_data(&args[0]->string), NULL, 10);

    const char *fill = " ";
    if (argc >= 2 && args[1]->type == VEX_VAL_STRING)
        fill = vstr_data(&args[1]->string);

    const char *s = vstr_data(&input->string);
    size_t slen = vstr_len(&input->string);
    if ((int64_t)slen >= width) return vval_retain(input);

    size_t pad_chars = (size_t)(width - (int64_t)slen);
    size_t fill_len = strlen(fill);
    if (fill_len == 0) return vval_retain(input);

    size_t total = slen + pad_chars + 1;
    char *buf = malloc(total);
    memcpy(buf, s, slen);
    for (size_t i = 0; i < pad_chars; i++) {
        buf[slen + i] = fill[i % fill_len];
    }
    buf[slen + pad_chars] = '\0';
    VexValue *result = vval_string_cstr(buf);
    free(buf);
    return result;
}

VexValue *builtin_touch(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1) {
        fprintf(stderr, "touch: expected filename(s)\n");
        return vval_null();
    }
    for (size_t i = 0; i < argc; i++) {
        const char *path = vstr_data(&args[i]->string);
        FILE *f = fopen(path, "a");
        if (f) {
            fclose(f);

            utimes(path, NULL);
        } else {
            fprintf(stderr, "touch: cannot touch '%s': %s\n", path, strerror(errno));
        }
    }
    return vval_null();
}

VexValue *builtin_path_join(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;

    char result[PATH_MAX] = {0};
    size_t pos = 0;

    if (input && input->type == VEX_VAL_STRING) {
        const char *s = vstr_data(&input->string);
        size_t len = strlen(s);
        if (len < PATH_MAX) {
            memcpy(result, s, len);
            pos = len;
        }
    }

    for (size_t i = 0; i < argc; i++) {
        if (args[i]->type != VEX_VAL_STRING) continue;
        const char *part = vstr_data(&args[i]->string);
        size_t plen = strlen(part);
        if (plen == 0) continue;

        if (part[0] == '/') {
            memcpy(result, part, plen);
            pos = plen;
            result[pos] = '\0';
            continue;
        }

        if (pos > 0 && result[pos - 1] != '/') {
            if (pos < PATH_MAX - 1) result[pos++] = '/';
        }
        size_t copy = (plen < PATH_MAX - pos) ? plen : PATH_MAX - pos - 1;
        memcpy(result + pos, part, copy);
        pos += copy;
        result[pos] = '\0';
    }

    result[pos] = '\0';
    return vval_string_cstr(result);
}

/* NB: dirname/basename may return pointers into their arg; strdup before use,
   and copy derived strings (base, dot) before freeing tmp2 to avoid UAF. */
VexValue *builtin_path_parse(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) {
        fprintf(stderr, "path-parse: expected string input\n");
        return vval_null();
    }
    const char *path = vstr_data(&input->string);

    char *tmp1 = strdup(path);
    char *dir = dirname(tmp1);
    VexValue *dir_val = vval_string_cstr(dir);
    free(tmp1);

    char *tmp2 = strdup(path);
    char *base = basename(tmp2);
    VexValue *base_val = vval_string_cstr(base);

    char ext_buf[PATH_MAX] = {0};
    char stem_buf[PATH_MAX] = {0};
    const char *dot = strrchr(base, '.');
    if (dot && dot != base) {
        snprintf(ext_buf, sizeof(ext_buf), "%s", dot + 1);
        size_t stem_len = (size_t)(dot - base);
        if (stem_len < PATH_MAX) {
            memcpy(stem_buf, base, stem_len);
            stem_buf[stem_len] = '\0';
        }
    } else {
        snprintf(stem_buf, sizeof(stem_buf), "%s", base);
    }
    free(tmp2);

    VexValue *rec = vval_record();
    vval_record_set(rec, "dir", dir_val);
    vval_release(dir_val);
    vval_record_set(rec, "name", base_val);
    vval_release(base_val);
    record_set_str(rec, "stem", stem_buf);
    record_set_str(rec, "ext", ext_buf);
    return rec;
}

VexValue *builtin_str_capitalize(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    if (len == 0) return vval_retain(input);
    char *buf = malloc(len + 1);
    memcpy(buf, s, len + 1);
    buf[0] = (char)toupper((unsigned char)buf[0]);
    VexValue *result = vval_string_cstr(buf);
    free(buf);
    return result;
}

VexValue *builtin_take_while(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("take-while: expected list input");
    if (argc < 1 || args[0]->type != VEX_VAL_CLOSURE) {
        fprintf(stderr, "take-while: expected closure argument\n");
        return vval_retain(input);
    }
    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        VexValue *call_args[1] = { item };
        VexValue *test = eval_call_closure(ctx, args[0], call_args, 1);
        bool keep = vval_truthy(test);
        vval_release(test);
        if (!keep) break;
        vval_list_push(result, item);
    }
    return result;
}

VexValue *builtin_skip_while(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("skip-while: expected list input");
    if (argc < 1 || args[0]->type != VEX_VAL_CLOSURE) {
        fprintf(stderr, "skip-while: expected closure argument\n");
        return vval_retain(input);
    }
    VexValue *result = vval_list();
    bool skipping = true;
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        if (skipping) {
            VexValue *call_args[1] = { item };
            VexValue *test = eval_call_closure(ctx, args[0], call_args, 1);
            bool skip = vval_truthy(test);
            vval_release(test);
            if (skip) continue;
            skipping = false;
        }
        vval_list_push(result, item);
    }
    return result;
}

VexValue *builtin_rotate(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("rotate: expected list input");
    size_t len = input->list.len;
    if (len == 0) return vval_retain(input);

    int64_t n = 1;
    if (argc >= 1) {
        if (args[0]->type == VEX_VAL_INT) n = args[0]->integer;
        else if (args[0]->type == VEX_VAL_STRING) n = strtol(vstr_data(&args[0]->string), NULL, 10);
    }

    n = n % (int64_t)len;
    if (n < 0) n += (int64_t)len;

    VexValue *result = vval_list();
    for (size_t i = 0; i < len; i++) {
        size_t idx = ((size_t)n + i) % len;
        vval_list_push(result, input->list.data[idx]);
    }
    return result;
}

VexValue *builtin_transpose(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("transpose: expected list input");
    if (input->list.len == 0)
        return vval_null();

    VexValue *first = input->list.data[0];
    if (!first || first->type != VEX_VAL_RECORD) {
        fprintf(stderr, "transpose: expected list of records\n");
        return vval_null();
    }

    VexValue *result = vval_record();
    VexMapIter it = vmap_iter(&first->record);
    const char *key; void *val;
    while (vmap_next(&it, &key, &val)) {
        VexValue *col_list = vval_list();
        for (size_t i = 0; i < input->list.len; i++) {
            VexValue *row = input->list.data[i];
            if (row->type == VEX_VAL_RECORD) {
                VexValue *cell = vval_record_get(row, key);
                if (cell) {
                    vval_list_push(col_list, cell);
                } else {
                    VexValue *n = vval_null();
                    vval_list_push(col_list, n);
                    vval_release(n);
                }
            } else {
                VexValue *n = vval_null();
                vval_list_push(col_list, n);
                vval_release(n);
            }
        }
        vval_record_set(result, key, col_list);
        vval_release(col_list);
    }
    return result;
}

VexValue *builtin_path_expand(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    const char *path = NULL;
    if (input && input->type == VEX_VAL_STRING)
        path = vstr_data(&input->string);
    else if (argc >= 1 && args[0]->type == VEX_VAL_STRING)
        path = vstr_data(&args[0]->string);
    if (!path) {
        fprintf(stderr, "path-expand: expected string\n");
        return vval_null();
    }

    char resolved[PATH_MAX];

    if (path[0] == '~') {
        const char *home = getenv("HOME");
        if (!home) home = "/";
        snprintf(resolved, sizeof(resolved), "%s%s", home, path + 1);
    } else {
        snprintf(resolved, sizeof(resolved), "%s", path);
    }

    if (resolved[0] != '/') {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd))) {
            char abs_path[PATH_MAX];
            snprintf(abs_path, sizeof(abs_path), "%s/%s", cwd, resolved);
            return vval_string_cstr(abs_path);
        }
    }
    return vval_string_cstr(resolved);
}

static const char b64_enc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const char *data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    size_t j = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = ((uint32_t)(unsigned char)data[i]) << 16;
        if (i + 1 < len) n |= ((uint32_t)(unsigned char)data[i + 1]) << 8;
        if (i + 2 < len) n |= (uint32_t)(unsigned char)data[i + 2];
        out[j++] = b64_enc[(n >> 18) & 0x3F];
        out[j++] = b64_enc[(n >> 12) & 0x3F];
        out[j++] = (i + 1 < len) ? b64_enc[(n >> 6) & 0x3F] : '=';
        out[j++] = (i + 2 < len) ? b64_enc[n & 0x3F] : '=';
    }
    out[j] = '\0';
    return out;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static char *base64_decode(const char *data, size_t *out_len) {
    size_t len = strlen(data);

    while (len > 0 && (data[len-1] == '\n' || data[len-1] == '\r' || data[len-1] == ' '))
        len--;
    size_t alloc = (len / 4) * 3 + 3;
    char *out = malloc(alloc);
    size_t j = 0;
    for (size_t i = 0; i < len; i += 4) {
        int a = (i < len) ? b64_val(data[i]) : 0;
        int b = (i+1 < len) ? b64_val(data[i+1]) : 0;
        int c = (i+2 < len) ? b64_val(data[i+2]) : 0;
        int d = (i+3 < len) ? b64_val(data[i+3]) : 0;
        if (a < 0) a = 0;
        if (b < 0) b = 0;
        if (c < 0) c = 0;
        if (d < 0) d = 0;
        uint32_t n = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        out[j++] = (char)((n >> 16) & 0xFF);
        if (i+2 < len && data[i+2] != '=') out[j++] = (char)((n >> 8) & 0xFF);
        if (i+3 < len && data[i+3] != '=') out[j++] = (char)(n & 0xFF);
    }
    out[j] = '\0';
    *out_len = j;
    return out;
}

VexValue *builtin_encode(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING) {
        fprintf(stderr, "encode: expected string input\n");
        return vval_null();
    }
    const char *format = "base64";
    if (argc >= 1 && args[0]->type == VEX_VAL_STRING)
        format = vstr_data(&args[0]->string);

    const char *data = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);

    if (strcmp(format, "base64") == 0) {
        char *encoded = base64_encode(data, len);
        VexValue *result = vval_string_cstr(encoded);
        free(encoded);
        return result;
    } else if (strcmp(format, "hex") == 0) {
        char *hex = malloc(len * 2 + 1);
        for (size_t i = 0; i < len; i++)
            sprintf(hex + i * 2, "%02x", (unsigned char)data[i]);
        hex[len * 2] = '\0';
        VexValue *result = vval_string_cstr(hex);
        free(hex);
        return result;
    } else {
        fprintf(stderr, "encode: unknown format '%s' (use base64 or hex)\n", format);
        return vval_retain(input);
    }
}

VexValue *builtin_decode(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING) {
        fprintf(stderr, "decode: expected string input\n");
        return vval_null();
    }
    const char *format = "base64";
    if (argc >= 1 && args[0]->type == VEX_VAL_STRING)
        format = vstr_data(&args[0]->string);

    const char *data = vstr_data(&input->string);

    if (strcmp(format, "base64") == 0) {
        size_t out_len;
        char *decoded = base64_decode(data, &out_len);
        VexValue *result = vval_string_cstr(decoded);
        free(decoded);
        return result;
    } else if (strcmp(format, "hex") == 0) {
        size_t len = strlen(data);
        if (len % 2 != 0) {
            fprintf(stderr, "decode hex: odd-length string\n");
            return vval_retain(input);
        }
        size_t out_len = len / 2;
        char *decoded = malloc(out_len + 1);
        for (size_t i = 0; i < out_len; i++) {
            unsigned int byte;
            sscanf(data + i * 2, "%2x", &byte);
            decoded[i] = (char)byte;
        }
        decoded[out_len] = '\0';
        VexValue *result = vval_string_cstr(decoded);
        free(decoded);
        return result;
    } else {
        fprintf(stderr, "decode: unknown format '%s' (use base64 or hex)\n", format);
        return vval_retain(input);
    }
}

VexValue *builtin_inspect(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)args; (void)argc;

    fprintf(stderr, "[inspect] ");
    if (input) {
        vval_print(input, stderr);
    } else {
        fprintf(stderr, "null");
    }
    fprintf(stderr, "\n");
    return input ? vval_retain(input) : vval_null();
    (void)ctx;
}

VexValue *builtin_tee_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (argc < 1 || args[0]->type != VEX_VAL_CLOSURE) {
        fprintf(stderr, "tee: expected closure argument\n");
        return input ? vval_retain(input) : vval_null();
    }

    VexValue *call_args[1] = { input ? input : vval_null() };
    VexValue *side = eval_call_closure(ctx, args[0], call_args, 1);
    vval_release(side);

    return input ? vval_retain(input) : vval_null();
}

VexValue *builtin_umask_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc == 0) {

        mode_t m = umask(0);
        umask(m);
        char buf[8];
        snprintf(buf, sizeof(buf), "%04o", m);
        if (!ctx->in_pipeline) printf("%s\n", buf);
        return vval_string_cstr(buf);
    }

    const char *val = vstr_data(&args[0]->string);
    unsigned int m;
    if (sscanf(val, "%o", &m) == 1) {
        umask((mode_t)m);
        return vval_null();
    }
    fprintf(stderr, "umask: invalid mask '%s'\n", val);
    return vval_null();
}

VexValue *builtin_cal(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    int year = tm->tm_year + 1900;
    int month = tm->tm_mon + 1;
    int today = tm->tm_mday;

    if (argc >= 2) {
        if (args[0]->type == VEX_VAL_STRING) month = (int)strtol(vstr_data(&args[0]->string), NULL, 10);
        else if (args[0]->type == VEX_VAL_INT) month = (int)args[0]->integer;
        if (args[1]->type == VEX_VAL_STRING) year = (int)strtol(vstr_data(&args[1]->string), NULL, 10);
        else if (args[1]->type == VEX_VAL_INT) year = (int)args[1]->integer;
        today = -1;
    } else if (argc == 1) {
        if (args[0]->type == VEX_VAL_STRING) month = (int)strtol(vstr_data(&args[0]->string), NULL, 10);
        else if (args[0]->type == VEX_VAL_INT) month = (int)args[0]->integer;
        today = -1;
    }

    static const char *month_names[] = {
        "", "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December"
    };

    int days_in_month[] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if ((year % 4 == 0 && year % 100 != 0) || year % 400 == 0) days_in_month[2] = 29;

    if (month < 1 || month > 12) {
        fprintf(stderr, "cal: invalid month %d\n", month);
        return vval_null();
    }

    struct tm first = {0};
    first.tm_year = year - 1900;
    first.tm_mon = month - 1;
    first.tm_mday = 1;
    mktime(&first);
    int start_dow = first.tm_wday;

    char buf[1024];
    int pos = 0;

    char header[64];
    snprintf(header, sizeof(header), "%s %d", month_names[month], year);
    int pad = (20 - (int)strlen(header)) / 2;
    if (pad < 0) pad = 0;
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "%*s%s\n", pad, "", header);
    pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "Su Mo Tu We Th Fr Sa\n");

    for (int d = 0; d < start_dow; d++)
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "   ");

    for (int d = 1; d <= days_in_month[month]; d++) {
        if (d == today) {
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "\033[7m%2d\033[0m ", d);
        } else {
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "%2d ", d);
        }
        if ((start_dow + d) % 7 == 0)
            pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "\n");
    }
    if ((start_dow + days_in_month[month]) % 7 != 0)
        pos += snprintf(buf + pos, sizeof(buf) - (size_t)pos, "\n");

    printf("%s", buf);
    return vval_null();
}

VexValue *builtin_str_reverse(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    char *buf = malloc(len + 1);

    for (size_t i = 0; i < len; i++)
        buf[i] = s[len - 1 - i];
    buf[len] = '\0';
    VexValue *result = vval_string_cstr(buf);
    free(buf);
    return result;
}

VexValue *builtin_str_repeat(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1) {
        fprintf(stderr, "str-repeat: expected string input and count\n");
        return vval_null();
    }
    int64_t n = 0;
    if (args[0]->type == VEX_VAL_INT) n = args[0]->integer;
    else if (args[0]->type == VEX_VAL_STRING) n = strtol(vstr_data(&args[0]->string), NULL, 10);
    if (n <= 0) return vval_string_cstr("");

    const char *s = vstr_data(&input->string);
    size_t slen = vstr_len(&input->string);
    size_t total = slen * (size_t)n;
    char *buf = malloc(total + 1);
    for (int64_t i = 0; i < n; i++)
        memcpy(buf + (size_t)i * slen, s, slen);
    buf[total] = '\0';
    VexValue *result = vval_string_cstr(buf);
    free(buf);
    return result;
}

VexValue *builtin_str_chars(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    VexValue *result = vval_list();
    size_t i = 0;
    while (i < len) {

        size_t clen = 1;
        unsigned char c = (unsigned char)s[i];
        if (c >= 0xF0) clen = 4;
        else if (c >= 0xE0) clen = 3;
        else if (c >= 0xC0) clen = 2;
        if (i + clen > len) clen = 1;
        char ch[5] = {0};
        memcpy(ch, s + i, clen);
        VexValue *cv = vval_string_cstr(ch);
        vval_list_push(result, cv);
        vval_release(cv);
        i += clen;
    }
    return result;
}

VexValue *builtin_str_words(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    VexValue *result = vval_list();
    size_t i = 0;
    while (i < len) {
        while (i < len && isspace((unsigned char)s[i])) i++;
        if (i >= len) break;
        size_t start = i;
        while (i < len && !isspace((unsigned char)s[i])) i++;
        char *word = malloc(i - start + 1);
        memcpy(word, s + start, i - start);
        word[i - start] = '\0';
        VexValue *wv = vval_string_cstr(word);
        vval_list_push(result, wv);
        vval_release(wv);
        free(word);
    }
    return result;
}

VexValue *builtin_range(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    int64_t start = 0, end = 0, step = 1;
    if (argc >= 2) {
        start = (args[0]->type == VEX_VAL_INT) ? args[0]->integer : 0;
        end = (args[1]->type == VEX_VAL_INT) ? args[1]->integer : 0;
        if (argc >= 3 && args[2]->type == VEX_VAL_INT) step = args[2]->integer;
    } else if (argc == 1) {
        end = (args[0]->type == VEX_VAL_INT) ? args[0]->integer : 0;
    } else {
        fprintf(stderr, "range: expected at least 1 argument\n");
        return vval_null();
    }
    if (step == 0) { fprintf(stderr, "range: step cannot be 0\n"); return vval_null(); }
    if (step < 0 && start < end) return vval_list();
    if (step > 0 && start > end) return vval_list();

    VexValue *result = vval_list();
    if (step > 0) {
        for (int64_t i = start; i < end; i += step) {
            VexValue *iv = vval_int(i);
            vval_list_push(result, iv);
            vval_release(iv);
        }
    } else {
        for (int64_t i = start; i > end; i += step) {
            VexValue *iv = vval_int(i);
            vval_list_push(result, iv);
            vval_release(iv);
        }
    }
    return result;
}

VexValue *builtin_par_each(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {

    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("par-each: expected list input");
    if (argc == 0 || args[0]->type != VEX_VAL_CLOSURE) {
        fprintf(stderr, "par-each: expected closure argument\n");
        return vval_retain(input);
    }

    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        VexValue *call_args[1] = { item };
        VexValue *mapped = eval_call_closure(ctx, args[0], call_args, 1);
        vval_list_push(result, mapped);
        vval_release(mapped);
    }
    return result;
}

VexValue *builtin_which_all(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_STRING) {
        fprintf(stderr, "which-all: expected command name\n");
        return vval_null();
    }
    const char *name = vstr_data(&args[0]->string);
    const char *path_env = getenv("PATH");
    if (!path_env) return vval_list();

    VexValue *result = vval_list();
    char *path_copy = strdup(path_env);
    char *saveptr;
    char *dir = strtok_r(path_copy, ":", &saveptr);
    while (dir) {
        char full[PATH_MAX];
        snprintf(full, sizeof(full), "%s/%s", dir, name);
        if (access(full, X_OK) == 0) {
            VexValue *pv = vval_string_cstr(full);
            vval_list_push(result, pv);
            vval_release(pv);
        }
        dir = strtok_r(NULL, ":", &saveptr);
    }
    free(path_copy);
    return result;
}

VexValue *builtin_has(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || argc < 1) return vval_bool(false);

    if (input->type == VEX_VAL_RECORD && args[0]->type == VEX_VAL_STRING) {
        return vval_bool(vval_record_get(input, vstr_data(&args[0]->string)) != NULL);
    }
    if (input->type == VEX_VAL_LIST) {

        for (size_t i = 0; i < input->list.len; i++) {
            VexValue *item = input->list.data[i];
            if (item->type == args[0]->type) {
                switch (item->type) {
                case VEX_VAL_INT: if (item->integer == args[0]->integer) return vval_bool(true); break;
                case VEX_VAL_FLOAT: if (item->floating == args[0]->floating) return vval_bool(true); break;
                case VEX_VAL_STRING: if (strcmp(vstr_data(&item->string), vstr_data(&args[0]->string)) == 0) return vval_bool(true); break;
                case VEX_VAL_BOOL: if (item->boolean == args[0]->boolean) return vval_bool(true); break;
                default: break;
                }
            }
        }
        return vval_bool(false);
    }
    return vval_bool(false);
}

static void nuon_serialize(VexValue *v, VexStr *out, int depth) {
    if (!v || v->type == VEX_VAL_NULL) { vstr_append_cstr(out, "null"); return; }
    if (depth > 20) { vstr_append_cstr(out, "..."); return; }
    switch (v->type) {
    case VEX_VAL_BOOL:
        vstr_append_cstr(out, v->boolean ? "true" : "false");
        break;
    case VEX_VAL_INT: {
        VexStr s = vstr_fmt("%ld", v->integer);
        vstr_append_str(out, &s);
        vstr_free(&s);
        break;
    }
    case VEX_VAL_FLOAT: {
        VexStr s = vstr_fmt("%g", v->floating);
        vstr_append_str(out, &s);
        vstr_free(&s);
        break;
    }
    case VEX_VAL_STRING:
        vstr_append_char(out, '"');

        for (size_t i = 0; i < vstr_len(&v->string); i++) {
            char c = vstr_data(&v->string)[i];
            switch (c) {
            case '"': vstr_append_cstr(out, "\\\""); break;
            case '\\': vstr_append_cstr(out, "\\\\"); break;
            case '\n': vstr_append_cstr(out, "\\n"); break;
            case '\t': vstr_append_cstr(out, "\\t"); break;
            case '\r': vstr_append_cstr(out, "\\r"); break;
            default: vstr_append_char(out, c); break;
            }
        }
        vstr_append_char(out, '"');
        break;
    case VEX_VAL_LIST:
        vstr_append_char(out, '[');
        for (size_t i = 0; i < v->list.len; i++) {
            if (i > 0) vstr_append_cstr(out, ", ");
            nuon_serialize(v->list.data[i], out, depth + 1);
        }
        vstr_append_char(out, ']');
        break;
    case VEX_VAL_RECORD: {
        vstr_append_char(out, '{');
        VexMapIter it = vmap_iter(&v->record);
        const char *key; void *val;
        bool first = true;
        while (vmap_next(&it, &key, &val)) {
            if (!first) vstr_append_cstr(out, ", ");
            vstr_append_cstr(out, key);
            vstr_append_cstr(out, ": ");
            nuon_serialize(val, out, depth + 1);
            first = false;
        }
        vstr_append_char(out, '}');
        break;
    }
    default:
        vstr_append_cstr(out, "null");
        break;
    }
}

VexValue *builtin_to_nuon(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    VexStr out = vstr_new("");
    nuon_serialize(input, &out, 0);
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_from_tsv(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *data = vstr_data(&input->string);

    VexValue *result = vval_list();
    const char *line_start = data;
    const char *headers[256];
    size_t header_count = 0;
    bool is_header = true;

    while (*line_start) {
        const char *line_end = strchr(line_start, '\n');
        if (!line_end) line_end = line_start + strlen(line_start);
        size_t line_len = (size_t)(line_end - line_start);

        if (line_len > 0 && line_start[line_len - 1] == '\r') line_len--;

        if (line_len == 0) {
            line_start = *line_end ? line_end + 1 : line_end;
            continue;
        }

        const char *fields[256];
        size_t field_lens[256];
        size_t field_count = 0;
        const char *p = line_start;
        const char *end = line_start + line_len;
        while (p < end && field_count < 256) {
            const char *tab = memchr(p, '\t', (size_t)(end - p));
            if (!tab) tab = end;
            fields[field_count] = p;
            field_lens[field_count] = (size_t)(tab - p);
            field_count++;
            p = (tab < end) ? tab + 1 : end;
        }

        if (is_header) {
            header_count = field_count;
            for (size_t i = 0; i < field_count; i++) {
                char *h = malloc(field_lens[i] + 1);
                memcpy(h, fields[i], field_lens[i]);
                h[field_lens[i]] = '\0';
                headers[i] = h;
            }
            is_header = false;
        } else {
            VexValue *rec = vval_record();
            for (size_t i = 0; i < field_count && i < header_count; i++) {
                char *val = malloc(field_lens[i] + 1);
                memcpy(val, fields[i], field_lens[i]);
                val[field_lens[i]] = '\0';
                vval_record_set(rec, headers[i], vval_string_cstr(val));
                free(val);
            }
            vval_list_push(result, rec);
            vval_release(rec);
        }
        line_start = *line_end ? line_end + 1 : line_end;
    }

    for (size_t i = 0; i < header_count; i++)
        free((char *)headers[i]);

    return result;
}

VexValue *builtin_to_tsv(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("to-tsv: expected list input");
    if (input->list.len == 0) return vval_string_cstr("");

    VexValue *first = input->list.data[0];
    if (!first || first->type != VEX_VAL_RECORD) return vval_null();

    VexStr out = vstr_new("");

    const char *keys[256];
    size_t key_count = 0;
    VexMapIter it = vmap_iter(&first->record);
    const char *key; void *val;
    while (vmap_next(&it, &key, &val) && key_count < 256) {
        keys[key_count++] = key;
    }

    for (size_t i = 0; i < key_count; i++) {
        if (i > 0) vstr_append_char(&out, '\t');
        vstr_append_cstr(&out, keys[i]);
    }
    vstr_append_char(&out, '\n');

    for (size_t r = 0; r < input->list.len; r++) {
        VexValue *row = input->list.data[r];
        if (row->type != VEX_VAL_RECORD) continue;
        for (size_t c = 0; c < key_count; c++) {
            if (c > 0) vstr_append_char(&out, '\t');
            VexValue *cell = vval_record_get(row, keys[c]);
            if (cell) {
                VexStr s = vval_to_str(cell);
                vstr_append_str(&out, &s);
                vstr_free(&s);
            }
        }
        vstr_append_char(&out, '\n');
    }

    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

#include <sys/utsname.h>

VexValue *builtin_uname(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (has_flag_args(args, argc))
        return fallback_external(ctx, "uname", args, argc);
    (void)ctx; (void)input; (void)args; (void)argc;
    struct utsname u;
    if (uname(&u) < 0) {
        fprintf(stderr, "uname: failed\n");
        return vval_null();
    }
    VexValue *rec = vval_record();
    vval_record_set(rec, "sysname", vval_string_cstr(u.sysname));
    vval_record_set(rec, "nodename", vval_string_cstr(u.nodename));
    vval_record_set(rec, "release", vval_string_cstr(u.release));
    vval_record_set(rec, "version", vval_string_cstr(u.version));
    vval_record_set(rec, "machine", vval_string_cstr(u.machine));
    return rec;
}

#include <sys/ioctl.h>
#include <regex.h>

VexValue *builtin_ansi(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1) {
        fprintf(stderr, "ansi: expected style name\n");
        return vval_string_cstr("");
    }
    const char *name = vstr_data(&args[0]->string);
    struct { const char *name; const char *code; } codes[] = {
        {"reset",         "\033[0m"},
        {"bold",          "\033[1m"},
        {"dim",           "\033[2m"},
        {"italic",        "\033[3m"},
        {"underline",     "\033[4m"},
        {"blink",         "\033[5m"},
        {"reverse",       "\033[7m"},
        {"strikethrough", "\033[9m"},
        {"black",         "\033[30m"},
        {"red",           "\033[31m"},
        {"green",         "\033[32m"},
        {"yellow",        "\033[33m"},
        {"blue",          "\033[34m"},
        {"magenta",       "\033[35m"},
        {"cyan",          "\033[36m"},
        {"white",         "\033[37m"},
        {"default",       "\033[39m"},
        {"bg_black",      "\033[40m"},
        {"bg_red",        "\033[41m"},
        {"bg_green",      "\033[42m"},
        {"bg_yellow",     "\033[43m"},
        {"bg_blue",       "\033[44m"},
        {"bg_magenta",    "\033[45m"},
        {"bg_cyan",       "\033[46m"},
        {"bg_white",      "\033[47m"},
        {"bg_default",    "\033[49m"},
        {"bright_black",  "\033[90m"},
        {"bright_red",    "\033[91m"},
        {"bright_green",  "\033[92m"},
        {"bright_yellow", "\033[93m"},
        {"bright_blue",   "\033[94m"},
        {"bright_magenta","\033[95m"},
        {"bright_cyan",   "\033[96m"},
        {"bright_white",  "\033[97m"},
        {NULL, NULL}
    };
    for (int i = 0; codes[i].name; i++) {
        if (strcmp(name, codes[i].name) == 0) {
            if (!ctx->in_pipeline) printf("%s", codes[i].code);
            return vval_string_cstr(codes[i].code);
        }
    }
    fprintf(stderr, "ansi: unknown style '%s'\n", name);
    return vval_string_cstr("");
}

VexValue *builtin_char_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1) {
        fprintf(stderr, "char: expected character name\n");
        return vval_null();
    }
    const char *name = vstr_data(&args[0]->string);
    struct { const char *name; const char *ch; } chars[] = {
        {"newline",  "\n"},  {"nl",       "\n"},
        {"tab",      "\t"},  {"space",    " "},
        {"nul",      "\0"},  {"null",     "\0"},
        {"cr",       "\r"},  {"crlf",     "\r\n"},
        {"lf",       "\n"},  {"esc",      "\033"},
        {"backspace","\b"},  {"bell",     "\a"},
        {"del",      "\x7f"},
        {"pipe",     "|"},   {"hash",     "#"},
        {"lparen",   "("},   {"rparen",   ")"},
        {"lbrace",   "{"},   {"rbrace",   "}"},
        {"lbracket", "["},   {"rbracket", "]"},
        {NULL, NULL}
    };
    for (int i = 0; chars[i].name; i++) {
        if (strcmp(name, chars[i].name) == 0) {
            if (!ctx->in_pipeline) printf("%s", chars[i].ch);
            return vval_string_cstr(chars[i].ch);
        }
    }

    if (strncmp(name, "0x", 2) == 0) {
        unsigned int code = (unsigned int)strtoul(name + 2, NULL, 16);
        if (code < 128) {
            char buf[2] = { (char)code, '\0' };
            if (!ctx->in_pipeline) printf("%s", buf);
            return vval_string_cstr(buf);
        }
    }
    fprintf(stderr, "char: unknown character '%s'\n", name);
    return vval_null();
}

VexValue *builtin_term_size(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0) {
        fprintf(stderr, "term-size: cannot get terminal size\n");
        return vval_null();
    }
    VexValue *rec = vval_record();
    vval_record_set(rec, "rows", vval_int(ws.ws_row));
    vval_record_set(rec, "cols", vval_int(ws.ws_col));
    return rec;
}

VexValue *builtin_url_parse(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) {
        fprintf(stderr, "url-parse: expected string input\n");
        return vval_null();
    }
    const char *url = vstr_data(&input->string);
    VexValue *rec = vval_record();

    const char *scheme_end = strstr(url, "://");
    if (scheme_end) {
        char scheme[64] = {0};
        size_t slen = (size_t)(scheme_end - url);
        if (slen < sizeof(scheme)) { memcpy(scheme, url, slen); }
        vval_record_set(rec, "scheme", vval_string_cstr(scheme));
        url = scheme_end + 3;
    } else {
        vval_record_set(rec, "scheme", vval_string_cstr(""));
    }

    const char *at = strchr(url, '@');
    const char *slash = strchr(url, '/');
    if (at && (!slash || at < slash)) {
        char userinfo[256] = {0};
        size_t ulen = (size_t)(at - url);
        if (ulen < sizeof(userinfo)) memcpy(userinfo, url, ulen);

        char *colon = strchr(userinfo, ':');
        if (colon) {
            *colon = '\0';
            vval_record_set(rec, "user", vval_string_cstr(userinfo));
            vval_record_set(rec, "password", vval_string_cstr(colon + 1));
        } else {
            vval_record_set(rec, "user", vval_string_cstr(userinfo));
            vval_record_set(rec, "password", vval_string_cstr(""));
        }
        url = at + 1;
    } else {
        vval_record_set(rec, "user", vval_string_cstr(""));
        vval_record_set(rec, "password", vval_string_cstr(""));
    }

    slash = strchr(url, '/');
    const char *query_start = strchr(url, '?');
    const char *frag_start = strchr(url, '#');
    const char *host_end = slash ? slash : (query_start ? query_start : (frag_start ? frag_start : url + strlen(url)));

    char hostport[256] = {0};
    size_t hlen = (size_t)(host_end - url);
    if (hlen < sizeof(hostport)) memcpy(hostport, url, hlen);

    char *port_colon = strrchr(hostport, ':');
    if (port_colon) {
        *port_colon = '\0';
        vval_record_set(rec, "host", vval_string_cstr(hostport));
        int port = atoi(port_colon + 1);
        vval_record_set(rec, "port", vval_int(port));
    } else {
        vval_record_set(rec, "host", vval_string_cstr(hostport));
        vval_record_set(rec, "port", vval_null());
    }

    url = host_end;

    const char *path_end = query_start ? query_start : (frag_start ? frag_start : url + strlen(url));
    char path[2048] = {0};
    size_t plen = (size_t)(path_end - url);
    if (plen < sizeof(path)) memcpy(path, url, plen);
    vval_record_set(rec, "path", vval_string_cstr(plen > 0 ? path : "/"));

    if (query_start) {
        const char *qend = frag_start ? frag_start : query_start + strlen(query_start);
        char query[2048] = {0};
        size_t qlen = (size_t)(qend - query_start - 1);
        if (qlen < sizeof(query)) memcpy(query, query_start + 1, qlen);
        vval_record_set(rec, "query", vval_string_cstr(query));
    } else {
        vval_record_set(rec, "query", vval_string_cstr(""));
    }

    if (frag_start) {
        vval_record_set(rec, "fragment", vval_string_cstr(frag_start + 1));
    } else {
        vval_record_set(rec, "fragment", vval_string_cstr(""));
    }

    return rec;
}

VexValue *builtin_split_at(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST || argc < 1) {
        fprintf(stderr, "split-at: expected list input and index\n");
        return vval_null();
    }
    int64_t idx = 0;
    if (args[0]->type == VEX_VAL_INT) idx = args[0]->integer;
    else if (args[0]->type == VEX_VAL_STRING) idx = strtol(vstr_data(&args[0]->string), NULL, 10);

    size_t len = input->list.len;
    if (idx < 0) idx = 0;
    if ((size_t)idx > len) idx = (int64_t)len;

    VexValue *left = vval_list();
    VexValue *right = vval_list();
    for (size_t i = 0; i < (size_t)idx; i++)
        vval_list_push(left, input->list.data[i]);
    for (size_t i = (size_t)idx; i < len; i++)
        vval_list_push(right, input->list.data[i]);

    VexValue *result = vval_list();
    vval_list_push(result, left);
    vval_release(left);
    vval_list_push(result, right);
    vval_release(right);
    return result;
}

VexValue *builtin_each_while(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("each-while: expected list input");
    if (argc < 1 || args[0]->type != VEX_VAL_CLOSURE) {
        fprintf(stderr, "each-while: expected closure argument\n");
        return vval_retain(input);
    }
    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        VexValue *call_args[1] = { item };
        VexValue *mapped = eval_call_closure(ctx, args[0], call_args, 1);
        if (!vval_truthy(mapped)) {
            vval_release(mapped);
            break;
        }
        vval_list_push(result, mapped);
        vval_release(mapped);
    }
    return result;
}

VexValue *builtin_str_match(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_STRING) {
        fprintf(stderr, "str-match: expected string input and pattern\n");
        return vval_bool(false);
    }
    const char *s = vstr_data(&input->string);
    const char *pattern = vstr_data(&args[0]->string);

    regex_t reg;
    int ret = regcomp(&reg, pattern, REG_EXTENDED | REG_NOSUB);
    if (ret != 0) {
        char errbuf[128];
        regerror(ret, &reg, errbuf, sizeof(errbuf));
        fprintf(stderr, "str-match: bad regex: %s\n", errbuf);
        return vval_bool(false);
    }
    bool matched = (regexec(&reg, s, 0, NULL, 0) == 0);
    regfree(&reg);

    if (argc >= 2 && strcmp(vstr_data(&args[1]->string), "--capture") == 0) {
        regex_t reg2;
        regcomp(&reg2, pattern, REG_EXTENDED);
        regmatch_t matches[10];
        if (regexec(&reg2, s, 10, matches, 0) == 0) {
            VexValue *result = vval_list();
            for (int i = 0; i < 10 && matches[i].rm_so >= 0; i++) {
                size_t mlen = (size_t)(matches[i].rm_eo - matches[i].rm_so);
                char *m = malloc(mlen + 1);
                memcpy(m, s + matches[i].rm_so, mlen);
                m[mlen] = '\0';
                vval_list_push(result, vval_string_cstr(m));
                free(m);
            }
            regfree(&reg2);
            return result;
        }
        regfree(&reg2);
        return vval_list();
    }

    return vval_bool(matched);
}

VexValue *builtin_fill(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING) {

        if (input) {
            VexStr s = vval_to_str(input);
            VexValue *sv = vval_string_cstr(vstr_data(&s));
            vstr_free(&s);
            VexValue *r = builtin_fill(ctx, sv, args, argc);
            vval_release(sv);
            return r;
        }
        return vval_null();
    }

    int64_t width = 20;
    const char *align = "right";
    const char *fill_char = " ";

    for (size_t i = 0; i + 1 < argc; i += 2) {
        if (args[i]->type != VEX_VAL_STRING) continue;
        const char *flag = vstr_data(&args[i]->string);
        const char *val = vstr_data(&args[i+1]->string);
        if (strcmp(flag, "--width") == 0 || strcmp(flag, "-w") == 0) {
            width = strtol(val, NULL, 10);
        } else if (strcmp(flag, "--align") == 0 || strcmp(flag, "-a") == 0) {
            align = val;
        } else if (strcmp(flag, "--char") == 0 || strcmp(flag, "-c") == 0) {
            fill_char = val;
        }
    }

    const char *s = vstr_data(&input->string);
    size_t slen = vstr_len(&input->string);
    if ((int64_t)slen >= width) return vval_retain(input);

    size_t pad_total = (size_t)(width - (int64_t)slen);
    size_t pad_left = 0, pad_right = 0;
    if (strcmp(align, "right") == 0) pad_left = pad_total;
    else if (strcmp(align, "left") == 0) pad_right = pad_total;
    else { pad_left = pad_total / 2; pad_right = pad_total - pad_left; }

    size_t fc_len = strlen(fill_char);
    if (fc_len == 0) fc_len = 1;
    size_t total = pad_left + slen + pad_right + 1;
    char *buf = malloc(total);
    size_t pos = 0;
    for (size_t i = 0; i < pad_left; i++) buf[pos++] = fill_char[i % fc_len];
    memcpy(buf + pos, s, slen); pos += slen;
    for (size_t i = 0; i < pad_right; i++) buf[pos++] = fill_char[i % fc_len];
    buf[pos] = '\0';
    VexValue *result = vval_string_cstr(buf);
    free(buf);
    return result;
}

VexValue *builtin_error_make(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_STRING) {
        fprintf(stderr, "error-make: expected error message\n");
        return vval_error("unknown error");
    }
    return vval_error(vstr_data(&args[0]->string));
}

VexValue *builtin_try_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (argc < 1 || args[0]->type != VEX_VAL_CLOSURE) {
        fprintf(stderr, "try: expected closure argument\n");
        return vval_null();
    }
    VexValue *call_args[1] = { input ? input : vval_null() };
    VexValue *result = eval_call_closure(ctx, args[0], call_args, 1);

    if (result && result->type == VEX_VAL_ERROR) {

        if (argc >= 2 && args[1]->type == VEX_VAL_CLOSURE) {
            VexValue *err_args[1] = { result };
            VexValue *caught = eval_call_closure(ctx, args[1], err_args, 1);
            vval_release(result);
            return caught;
        }

        vval_release(result);
        return vval_null();
    }
    return result;
}

VexValue *builtin_whoami(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    const char *user = getenv("USER");
    if (!user) user = getenv("LOGNAME");
    if (!user) user = "unknown";
    if (!ctx->in_pipeline) printf("%s\n", user);
    return vval_string_cstr(user);
}

VexValue *builtin_hostname_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    char buf[256];
    if (gethostname(buf, sizeof(buf)) == 0) {
        if (!ctx->in_pipeline) printf("%s\n", buf);
        return vval_string_cstr(buf);
    }
    fprintf(stderr, "hostname: failed\n");
    return vval_null();
}

static int64_t dir_size_recursive(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (!S_ISDIR(st.st_mode)) return st.st_size;

    int64_t total = st.st_size;
    DIR *d = opendir(path);
    if (!d) return total;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char child[PATH_MAX];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        total += dir_size_recursive(child);
    }
    closedir(d);
    return total;
}

VexValue *builtin_du(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (has_flag_args(args, argc))
        return fallback_external(ctx, "du", args, argc);
    (void)ctx; (void)input;
    const char *target = ".";
    if (argc >= 1 && args[0]->type == VEX_VAL_STRING)
        target = vstr_data(&args[0]->string);

    DIR *d = opendir(target);
    if (!d) {

        struct stat st;
        if (stat(target, &st) == 0) {
            VexValue *rec = vval_record();
            vval_record_set(rec, "name", vval_string_cstr(target));
            vval_record_set(rec, "size", vval_int(st.st_size));
            return rec;
        }
        fprintf(stderr, "du: cannot access '%s': %s\n", target, strerror(errno));
        return vval_null();
    }

    VexValue *result = vval_list();
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char child[PATH_MAX];
        snprintf(child, sizeof(child), "%s/%s", target, ent->d_name);
        int64_t sz = dir_size_recursive(child);
        VexValue *rec = vval_record();
        vval_record_set(rec, "name", vval_string_cstr(ent->d_name));
        vval_record_set(rec, "size", vval_int(sz));
        struct stat st;
        if (stat(child, &st) == 0)
            vval_record_set(rec, "type", vval_string_cstr(S_ISDIR(st.st_mode) ? "dir" : "file"));
        vval_list_push(result, rec);
        vval_release(rec);
    }
    closedir(d);
    return result;
}

VexValue *builtin_str_regex_replace(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 2 ||
        args[0]->type != VEX_VAL_STRING || args[1]->type != VEX_VAL_STRING) {
        fprintf(stderr, "str-regex-replace: expected string input, pattern, replacement\n");
        return input ? vval_retain(input) : vval_null();
    }
    const char *s = vstr_data(&input->string);
    const char *pattern = vstr_data(&args[0]->string);
    const char *replacement = vstr_data(&args[1]->string);
    bool global = (argc >= 3 && args[2]->type == VEX_VAL_STRING &&
                   strcmp(vstr_data(&args[2]->string), "-g") == 0);

    regex_t reg;
    int ret = regcomp(&reg, pattern, REG_EXTENDED);
    if (ret != 0) {
        char errbuf[128];
        regerror(ret, &reg, errbuf, sizeof(errbuf));
        fprintf(stderr, "str-regex-replace: bad regex: %s\n", errbuf);
        return vval_retain(input);
    }

    VexStr out = vstr_new("");
    const char *cur = s;
    regmatch_t match;
    while (regexec(&reg, cur, 1, &match, 0) == 0) {

        vstr_append(&out, cur, (size_t)match.rm_so);

        vstr_append_cstr(&out, replacement);
        cur += match.rm_eo;
        if (!global) break;
        if (match.rm_so == match.rm_eo) {

            if (*cur) { vstr_append_char(&out, *cur); cur++; }
            else break;
        }
    }

    vstr_append_cstr(&out, cur);
    regfree(&reg);

    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_histogram(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("histogram: expected list input");

    VexValue *result = vval_record();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        VexStr key = vval_to_str(item);
        VexValue *existing = vval_record_get(result, vstr_data(&key));
        int64_t count = existing ? existing->integer + 1 : 1;
        vval_record_set(result, vstr_data(&key), vval_int(count));
        vstr_free(&key);
    }
    return result;
}

VexValue *builtin_into_bool(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_bool(false);
    if (input->type == VEX_VAL_STRING) {
        const char *s = vstr_data(&input->string);
        if (strcmp(s, "true") == 0 || strcmp(s, "yes") == 0 || strcmp(s, "1") == 0)
            return vval_bool(true);
        if (strcmp(s, "false") == 0 || strcmp(s, "no") == 0 || strcmp(s, "0") == 0 || strcmp(s, "") == 0)
            return vval_bool(false);
    }
    return vval_bool(vval_truthy(input));
}

VexValue *builtin_into_record(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("into-record: expected list of pairs");
    VexValue *result = vval_record();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        if (item->type == VEX_VAL_LIST && item->list.len >= 2) {

            VexStr key = vval_to_str(item->list.data[0]);
            vval_record_set(result, vstr_data(&key), item->list.data[1]);
            vstr_free(&key);
        } else if (item->type == VEX_VAL_RECORD) {

            VexValue *k = vval_record_get(item, "key");
            VexValue *v = vval_record_get(item, "value");
            if (k && v) {
                VexStr key = vval_to_str(k);
                vval_record_set(result, vstr_data(&key), v);
                vstr_free(&key);
            }
        }
    }
    return result;
}

VexValue *builtin_into_list(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_RECORD)
        return vval_error("into-list: expected record input");
    VexValue *result = vval_list();
    VexMapIter it = vmap_iter(&input->record);
    const char *key; void *val;
    while (vmap_next(&it, &key, &val)) {
        VexValue *pair = vval_record();
        vval_record_set(pair, "key", vval_string_cstr(key));
        vval_record_set(pair, "value", vval_retain(val));
        vval_list_push(result, pair);
        vval_release(pair);
    }
    return result;
}

static int watch_get_term_cols(void) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        return ws.ws_col;
    return 80;
}

static void watch_render_table(VexValue *data, VexValue *prev) {
    if (!data || data->type != VEX_VAL_LIST || vval_list_len(data) == 0) {
        if (data) {
            vval_print(data, stdout);
            printf("\n");
        }
        return;
    }

    size_t data_len = vval_list_len(data);
    bool is_table = true;
    for (size_t i = 0; i < data_len; i++) {
        VexValue *item = vval_list_get(data, i);
        if (!item || item->type != VEX_VAL_RECORD) {
            is_table = false;
            break;
        }
    }

    if (!is_table) {
        vval_print(data, stdout);
        printf("\n");
        return;
    }

    size_t col_cap = 32, col_count = 0;
    char **cols = vex_xmalloc(col_cap * sizeof(char *));

    for (size_t i = 0; i < data_len; i++) {
        VexValue *row = vval_list_get(data, i);
        VexMapIter it = vmap_iter(&row->record);
        const char *key;
        void *val;
        while (vmap_next(&it, &key, &val)) {
            bool found = false;
            for (size_t c = 0; c < col_count; c++) {
                if (strcmp(cols[c], key) == 0) { found = true; break; }
            }
            if (!found) {
                if (col_count >= col_cap) {
                    col_cap *= 2;
                    cols = vex_xrealloc(cols, col_cap * sizeof(char *));
                }
                cols[col_count++] = strdup(key);
            }
        }
    }

    size_t *widths = calloc(col_count, sizeof(size_t));
    for (size_t c = 0; c < col_count; c++)
        widths[c] = strlen(cols[c]);

    size_t row_count = data_len;
    char ***cells = malloc(row_count * sizeof(char **));
    char ***prev_cells = NULL;
    size_t prev_row_count = 0;

    for (size_t i = 0; i < row_count; i++) {
        cells[i] = malloc(col_count * sizeof(char *));
        VexValue *row = vval_list_get(data, i);
        for (size_t c = 0; c < col_count; c++) {
            VexValue *v = vval_record_get(row, cols[c]);
            if (v) {
                VexStr s = vval_to_str(v);
                cells[i][c] = strdup(vstr_data(&s));
                vstr_free(&s);
            } else {
                cells[i][c] = strdup("");
            }
            size_t w = display_width_str(cells[i][c]);
            if (w > widths[c]) widths[c] = w;
        }
    }

    if (prev && prev->type == VEX_VAL_LIST && vval_list_len(prev) > 0) {
        prev_row_count = vval_list_len(prev);
        prev_cells = malloc(prev_row_count * sizeof(char **));
        for (size_t i = 0; i < prev_row_count; i++) {
            prev_cells[i] = malloc(col_count * sizeof(char *));
            VexValue *row = vval_list_get(prev, i);
            for (size_t c = 0; c < col_count; c++) {
                VexValue *v = (row->type == VEX_VAL_RECORD)
                    ? vval_record_get(row, cols[c]) : NULL;
                if (v) {
                    VexStr s = vval_to_str(v);
                    prev_cells[i][c] = strdup(vstr_data(&s));
                    vstr_free(&s);
                } else {
                    prev_cells[i][c] = strdup("");
                }
            }
        }
    }

    int term_cols = watch_get_term_cols();
    size_t separators = col_count > 1 ? (col_count - 1) * 3 : 0;
    size_t total_w = separators;
    for (size_t c = 0; c < col_count; c++) total_w += widths[c];

    if (total_w > (size_t)term_cols && col_count > 0) {
        while (total_w > (size_t)term_cols) {
            size_t widest = 0;
            for (size_t c = 1; c < col_count; c++) {
                if (widths[c] > widths[widest]) widest = c;
            }
            if (widths[widest] <= 3) break;
            size_t excess = total_w - (size_t)term_cols;
            size_t shrink = excess < widths[widest] - 3 ? excess : widths[widest] - 3;
            widths[widest] -= shrink;
            total_w -= shrink;
        }
    }

    printf("\033[1m");
    for (size_t c = 0; c < col_count; c++) {
        if (c > 0) printf(" \033[90m|\033[0;1m ");
        size_t hlen = strlen(cols[c]);
        if (hlen <= widths[c]) {
            printf("%s", cols[c]);
            for (size_t p = hlen; p < widths[c]; p++) putchar(' ');
        } else {
            printf("%.*s..", (int)(widths[c] > 2 ? widths[c] - 2 : 0), cols[c]);
        }
    }
    printf("\033[0m\n");

    printf("\033[90m");
    for (size_t c = 0; c < col_count; c++) {
        if (c > 0) printf("-+-");
        for (size_t w = 0; w < widths[c]; w++) putchar('-');
    }
    printf("\033[0m\n");

    for (size_t i = 0; i < row_count; i++) {
        for (size_t c = 0; c < col_count; c++) {
            if (c > 0) printf(" \033[90m|\033[0m ");

            bool changed = false;
            if (prev_cells && i < prev_row_count) {
                if (strcmp(cells[i][c], prev_cells[i][c]) != 0)
                    changed = true;
            } else if (prev_cells && i >= prev_row_count) {
                changed = true;
            }

            size_t w = display_width_str(cells[i][c]);
            if (w <= widths[c]) {
                if (changed)
                    printf("\033[1;33m%s\033[0m", cells[i][c]);
                else
                    printf("%s", cells[i][c]);
                for (size_t p = w; p < widths[c]; p++) putchar(' ');
            } else {
                size_t max = widths[c] > 2 ? widths[c] - 2 : 0;
                if (changed) printf("\033[1;33m");
                printf("%.*s..", (int)max, cells[i][c]);
                if (changed) printf("\033[0m");
            }
        }
        putchar('\n');
    }

    for (size_t i = 0; i < row_count; i++) {
        for (size_t c = 0; c < col_count; c++) free(cells[i][c]);
        free(cells[i]);
    }
    free(cells);
    if (prev_cells) {
        for (size_t i = 0; i < prev_row_count; i++) {
            for (size_t c = 0; c < col_count; c++) free(prev_cells[i][c]);
            free(prev_cells[i]);
        }
        free(prev_cells);
    }
    free(widths);
    for (size_t c = 0; c < col_count; c++) free(cols[c]);
    free(cols);
}

static volatile sig_atomic_t watch_interrupted = 0;
static void watch_sigint_handler(int sig) { (void)sig; watch_interrupted = 1; }

VexValue *builtin_watch(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (argc < 1) {
        fprintf(stderr, "watch: expected interval and closure or command\n"
                "Usage: watch <interval> { closure }\n"
                "       watch <interval> <command...>\n"
                "       data | watch <interval> { closure }\n");
        return vval_null();
    }

    double interval = 2.0;
    size_t cmd_start = 0;

    if (args[0]->type == VEX_VAL_INT) {
        interval = (double)args[0]->integer;
        cmd_start = 1;
    } else if (args[0]->type == VEX_VAL_FLOAT) {
        interval = args[0]->floating;
        cmd_start = 1;
    } else if (args[0]->type == VEX_VAL_STRING) {
        const char *s = vstr_data(&args[0]->string);
        char *end;
        double val = strtod(s, &end);
        if (end != s) {
            if (*end == '\0' || strcmp(end, "s") == 0)
                interval = val;
            else if (strcmp(end, "ms") == 0)
                interval = val / 1000.0;
            else
                interval = val;
            cmd_start = 1;
        } else if (strcmp(s, "-n") == 0 && argc >= 2) {
            if (args[1]->type == VEX_VAL_INT)
                interval = (double)args[1]->integer;
            else if (args[1]->type == VEX_VAL_FLOAT)
                interval = args[1]->floating;
            else if (args[1]->type == VEX_VAL_STRING)
                interval = strtod(vstr_data(&args[1]->string), NULL);
            cmd_start = 2;
        }
    }

    if (interval < 0.1) interval = 0.1;

    VexStr cmd = vstr_empty();

    for (size_t i = cmd_start; i < argc; i++) {
        if (i > cmd_start) vstr_append_char(&cmd, ' ');
        if (args[i]->type == VEX_VAL_STRING)
            vstr_append_cstr(&cmd, vstr_data(&args[i]->string));
    }
    const char *display_cmd = vstr_data(&cmd);

    watch_interrupted = 0;
    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = watch_sigint_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, &old_sa);

    VexValue *prev_result = NULL;

    while (!watch_interrupted) {
        printf("\033[2J\033[H");
        time_t now = time(NULL);
        char *timestr = ctime(&now);
        if (timestr) {
            size_t tlen = strlen(timestr);
            if (tlen > 0 && timestr[tlen - 1] == '\n') timestr[tlen - 1] = '\0';
        }
        printf("\033[1mEvery %.1fs:\033[0m %s    \033[90m%s\033[0m\n\n",
               interval, display_cmd, timestr ? timestr : "");
        fflush(stdout);

        VexValue *result = NULL;

        if (vstr_len(&cmd) > 0) {
            Parser p = parser_init(vstr_data(&cmd), ctx->arena);
            ASTNode *node;
            VexValue *last = NULL;
            while ((node = parser_parse_line(&p))) {
                if (last) vval_release(last);
                last = eval(ctx, node);
            }
            result = last;
        }

        if (result && result->type != VEX_VAL_NULL) {
            watch_render_table(result, prev_result);
        }

        if (prev_result) vval_release(prev_result);
        prev_result = result;

        fflush(stdout);

        struct timespec ts;
        ts.tv_sec = (time_t)interval;
        ts.tv_nsec = (long)((interval - (double)ts.tv_sec) * 1e9);
        while (!watch_interrupted) {
            struct timespec rem;
            int ret = nanosleep(&ts, &rem);
            if (ret == 0) break;
            if (errno == EINTR) {
                if (watch_interrupted) break;
                ts = rem;
            } else break;
        }
    }

    if (prev_result) vval_release(prev_result);
    vstr_free(&cmd);

    sigaction(SIGINT, &old_sa, NULL);

    printf("\033[2J\033[H");
    fflush(stdout);

    return vval_null();
}

VexValue *builtin_config_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    VexValue *rec = vval_record();
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";

    char config_path[PATH_MAX];
    snprintf(config_path, sizeof(config_path), "%s/.config/vex/config.vex", home);

    vval_record_set(rec, "global", vval_string_cstr("/etc/vex/config.vex"));
    vval_record_set(rec, "user", vval_string_cstr(config_path));

    if (argc >= 1 && args[0]->type == VEX_VAL_STRING &&
        strcmp(vstr_data(&args[0]->string), "--edit") == 0) {

        const char *editor = getenv("EDITOR");
        if (!editor) editor = "vi";
        char *argv[] = { (char *)editor, config_path, NULL };
        exec_external(editor, argv, -1, -1);
        return vval_null();
    }

    return rec;
}

VexValue *builtin_version(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    VexValue *rec = vval_record();
    vval_record_set(rec, "name", vval_string_cstr("vex"));
    vval_record_set(rec, "version", vval_string_cstr("0.1.0"));
    vval_record_set(rec, "build", vval_string_cstr(__DATE__ " " __TIME__));
    if (!ctx->in_pipeline) {
        printf("vex 0.1.0 (built %s %s)\n", __DATE__, __TIME__);
    }
    return rec;
}

VexValue *builtin_str_camel_case(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    char *buf = malloc(len + 1);
    size_t j = 0;
    bool upper_next = false;
    bool first = true;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '_' || c == '-' || c == ' ') {
            upper_next = true;
            continue;
        }
        if (upper_next && !first) {
            buf[j++] = (char)toupper((unsigned char)c);
            upper_next = false;
        } else if (first) {
            buf[j++] = (char)tolower((unsigned char)c);
            first = false;
        } else {
            buf[j++] = c;
        }
    }
    buf[j] = '\0';
    VexValue *result = vval_string_cstr(buf);
    free(buf);
    return result;
}

VexValue *builtin_str_snake_case(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    char *buf = malloc(len * 2 + 1);
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '-' || c == ' ') {
            buf[j++] = '_';
        } else if (isupper((unsigned char)c)) {
            if (j > 0 && buf[j-1] != '_') buf[j++] = '_';
            buf[j++] = (char)tolower((unsigned char)c);
        } else {
            buf[j++] = c;
        }
    }
    buf[j] = '\0';
    VexValue *result = vval_string_cstr(buf);
    free(buf);
    return result;
}

VexValue *builtin_str_kebab_case(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    char *buf = malloc(len * 2 + 1);
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '_' || c == ' ') {
            buf[j++] = '-';
        } else if (isupper((unsigned char)c)) {
            if (j > 0 && buf[j-1] != '-') buf[j++] = '-';
            buf[j++] = (char)tolower((unsigned char)c);
        } else {
            buf[j++] = c;
        }
    }
    buf[j] = '\0';
    VexValue *result = vval_string_cstr(buf);
    free(buf);
    return result;
}

VexValue *builtin_to_md(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("to-md: expected list input");
    if (input->list.len == 0) return vval_string_cstr("");
    VexValue *first = input->list.data[0];
    if (!first || first->type != VEX_VAL_RECORD) return vval_null();

    const char *keys[256];
    size_t key_count = 0;
    VexMapIter it = vmap_iter(&first->record);
    const char *key; void *val;
    while (vmap_next(&it, &key, &val) && key_count < 256)
        keys[key_count++] = key;

    VexStr out = vstr_new("");

    vstr_append_cstr(&out, "|");
    for (size_t c = 0; c < key_count; c++) {
        vstr_append_cstr(&out, " ");
        vstr_append_cstr(&out, keys[c]);
        vstr_append_cstr(&out, " |");
    }
    vstr_append_char(&out, '\n');

    vstr_append_cstr(&out, "|");
    for (size_t c = 0; c < key_count; c++)
        vstr_append_cstr(&out, " --- |");
    vstr_append_char(&out, '\n');

    for (size_t r = 0; r < input->list.len; r++) {
        VexValue *row = input->list.data[r];
        if (row->type != VEX_VAL_RECORD) continue;
        vstr_append_cstr(&out, "|");
        for (size_t c = 0; c < key_count; c++) {
            vstr_append_cstr(&out, " ");
            VexValue *cell = vval_record_get(row, keys[c]);
            if (cell) {
                VexStr s = vval_to_str(cell);
                vstr_append_str(&out, &s);
                vstr_free(&s);
            }
            vstr_append_cstr(&out, " |");
        }
        vstr_append_char(&out, '\n');
    }
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_flat_map(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("flat-map: expected list input");
    if (argc == 0 || args[0]->type != VEX_VAL_CLOSURE) {
        fprintf(stderr, "flat-map: expected closure argument\n");
        return vval_retain(input);
    }
    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        VexValue *call_args[1] = { item };
        VexValue *mapped = eval_call_closure(ctx, args[0], call_args, 1);
        if (mapped && mapped->type == VEX_VAL_LIST) {
            for (size_t j = 0; j < mapped->list.len; j++)
                vval_list_push(result, mapped->list.data[j]);
        } else if (mapped) {
            vval_list_push(result, mapped);
        }
        if (mapped) vval_release(mapped);
    }
    return result;
}

VexValue *builtin_every(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST || argc < 1) {
        fprintf(stderr, "every: expected list input and step\n");
        return vval_null();
    }
    int64_t step = 2;
    if (args[0]->type == VEX_VAL_INT) step = args[0]->integer;
    else if (args[0]->type == VEX_VAL_STRING) step = strtol(vstr_data(&args[0]->string), NULL, 10);
    if (step <= 0) step = 1;

    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i += (size_t)step)
        vval_list_push(result, input->list.data[i]);
    return result;
}

VexValue *builtin_interleave(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST || argc < 1 ||
        args[0]->type != VEX_VAL_LIST)
        return vval_error("interleave: expected two lists");
    VexValue *other = args[0];
    size_t max = input->list.len > other->list.len ? input->list.len : other->list.len;
    VexValue *result = vval_list();
    for (size_t i = 0; i < max; i++) {
        if (i < input->list.len)
            vval_list_push(result, input->list.data[i]);
        if (i < other->list.len)
            vval_list_push(result, other->list.data[i]);
    }
    return result;
}

VexValue *builtin_load_env(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    const char *path = ".env";
    if (argc >= 1 && args[0]->type == VEX_VAL_STRING)
        path = vstr_data(&args[0]->string);

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "load-env: cannot open '%s': %s\n", path, strerror(errno));
        return vval_null();
    }

    VexValue *rec = vval_record();
    char line[4096];
    while (fgets(line, sizeof(line), f)) {

        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;

        size_t len = strlen(p);
        if (len > 0 && p[len-1] == '\n') p[--len] = '\0';
        if (len > 0 && p[len-1] == '\r') p[--len] = '\0';

        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key_s = p;
        char *val_s = eq + 1;

        size_t vlen = strlen(val_s);
        if (vlen >= 2 && ((val_s[0] == '"' && val_s[vlen-1] == '"') ||
                          (val_s[0] == '\'' && val_s[vlen-1] == '\''))) {
            val_s[vlen-1] = '\0';
            val_s++;
        }

        while (*key_s == ' ') key_s++;
        char *ke = key_s + strlen(key_s) - 1;
        while (ke > key_s && *ke == ' ') *ke-- = '\0';

        if (strncmp(key_s, "export ", 7) == 0) key_s += 7;
        while (*key_s == ' ') key_s++;

        setenv(key_s, val_s, 1);
        vval_record_set(rec, key_s, vval_string_cstr(val_s));
    }
    fclose(f);
    return rec;
}

VexValue *builtin_format_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_STRING) {
        fprintf(stderr, "format: expected format string\n");
        return vval_null();
    }
    const char *fmt = vstr_data(&args[0]->string);
    VexStr out = vstr_new("");
    size_t arg_idx = 1;
    for (const char *p = fmt; *p; p++) {
        if (*p == '{' && *(p+1) == '}') {

            if (arg_idx < argc) {
                VexStr s = vval_to_str(args[arg_idx++]);
                vstr_append_str(&out, &s);
                vstr_free(&s);
            }
            p++;
        } else if (*p == '{' && isdigit((unsigned char)*(p+1))) {

            size_t idx = (size_t)strtoul(p+1, NULL, 10);
            const char *close = strchr(p, '}');
            if (close && idx + 1 < argc) {
                VexStr s = vval_to_str(args[idx + 1]);
                vstr_append_str(&out, &s);
                vstr_free(&s);
                p = close;
            } else {
                vstr_append_char(&out, *p);
            }
        } else {
            vstr_append_char(&out, *p);
        }
    }
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_bench(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_CLOSURE) {
        fprintf(stderr, "bench: expected closure argument\n");
        return vval_null();
    }
    int64_t rounds = 1;
    if (argc >= 2) {
        if (args[1]->type == VEX_VAL_INT) rounds = args[1]->integer;
        else if (args[1]->type == VEX_VAL_STRING) rounds = strtol(vstr_data(&args[1]->string), NULL, 10);
    }
    if (rounds <= 0) rounds = 1;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    VexValue *last = NULL;
    VexValue *null_input = vval_null();
    for (int64_t i = 0; i < rounds; i++) {
        VexValue *call_args[1] = { null_input };
        VexValue *r = eval_call_closure(ctx, args[0], call_args, 1);
        if (last) vval_release(last);
        last = r;
    }
    vval_release(null_input);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    double elapsed = (double)(t1.tv_sec - t0.tv_sec) +
                     (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    double per_round = elapsed / (double)rounds;

    VexValue *rec = vval_record();
    vval_record_set(rec, "total_ms", vval_float(elapsed * 1000.0));
    vval_record_set(rec, "rounds", vval_int(rounds));
    vval_record_set(rec, "avg_ms", vval_float(per_round * 1000.0));
    if (last) vval_release(last);

    if (!ctx->in_pipeline) {
        if (rounds == 1)
            printf("%.3f ms\n", elapsed * 1000.0);
        else
            printf("%.3f ms total, %.3f ms/round (%ld rounds)\n",
                   elapsed * 1000.0, per_round * 1000.0, rounds);
    }
    return rec;
}

VexValue *builtin_open_url(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    const char *target = NULL;
    if (argc >= 1 && args[0]->type == VEX_VAL_STRING)
        target = vstr_data(&args[0]->string);
    else if (input && input->type == VEX_VAL_STRING)
        target = vstr_data(&input->string);
    if (!target) {
        fprintf(stderr, "open-url: expected URL or path\n");
        return vval_null();
    }
    pid_t pid = fork();
    if (pid == 0) {

        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); close(devnull); }
        execlp("xdg-open", "xdg-open", target, (char *)NULL);
        _exit(1);
    }
    return vval_null();
}

VexValue *builtin_input_confirm(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    const char *prompt = "Confirm?";
    if (argc >= 1 && args[0]->type == VEX_VAL_STRING)
        prompt = vstr_data(&args[0]->string);

    fprintf(stderr, "%s [y/N] ", prompt);
    fflush(stderr);
    char buf[16];
    if (!fgets(buf, sizeof(buf), stdin)) return vval_bool(false);
    return vval_bool(buf[0] == 'y' || buf[0] == 'Y');
}

VexValue *builtin_str_count(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_STRING) {
        fprintf(stderr, "str-count: expected string input and search string\n");
        return vval_int(0);
    }
    const char *s = vstr_data(&input->string);
    const char *needle = vstr_data(&args[0]->string);
    size_t nlen = strlen(needle);
    if (nlen == 0) return vval_int(0);
    int64_t count = 0;
    const char *p = s;
    while ((p = strstr(p, needle))) { count++; p += nlen; }
    return vval_int(count);
}

VexValue *builtin_str_bytes(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    VexValue *result = vval_list();
    for (size_t i = 0; i < len; i++)
        vval_list_push(result, vval_int((int64_t)(unsigned char)s[i]));
    return result;
}

VexValue *builtin_take_until(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("take-until: expected list input");
    if (argc < 1 || args[0]->type != VEX_VAL_CLOSURE) {
        fprintf(stderr, "take-until: expected closure argument\n");
        return vval_retain(input);
    }
    VexValue *result = vval_list();
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        VexValue *call_args[1] = { item };
        VexValue *test = eval_call_closure(ctx, args[0], call_args, 1);
        bool stop = vval_truthy(test);
        vval_release(test);
        if (stop) break;
        vval_list_push(result, vval_retain(item));
    }
    return result;
}

static double extract_numeric(VexValue *v) {
    if (!v) return 0.0;
    if (v->type == VEX_VAL_INT) return (double)v->integer;
    if (v->type == VEX_VAL_FLOAT) return v->floating;
    return 0.0;
}

VexValue *builtin_min_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("min-by: expected list input");
    if (input->list.len == 0) return vval_null();
    if (argc < 1) { fprintf(stderr, "min-by: expected field or closure\n"); return vval_null(); }

    VexValue *best = input->list.data[0];
    double best_val;

    if (args[0]->type == VEX_VAL_CLOSURE) {
        VexValue *ca[1] = { best };
        VexValue *r = eval_call_closure(ctx, args[0], ca, 1);
        best_val = extract_numeric(r);
        vval_release(r);
        for (size_t i = 1; i < input->list.len; i++) {
            VexValue *ca2[1] = { input->list.data[i] };
            VexValue *r2 = eval_call_closure(ctx, args[0], ca2, 1);
            double v = extract_numeric(r2);
            vval_release(r2);
            if (v < best_val) { best_val = v; best = input->list.data[i]; }
        }
    } else if (args[0]->type == VEX_VAL_STRING) {
        const char *field = vstr_data(&args[0]->string);
        VexValue *fv = (best->type == VEX_VAL_RECORD) ? vval_record_get(best, field) : NULL;
        best_val = extract_numeric(fv);
        for (size_t i = 1; i < input->list.len; i++) {
            VexValue *row = input->list.data[i];
            VexValue *fv2 = (row->type == VEX_VAL_RECORD) ? vval_record_get(row, field) : NULL;
            double v = extract_numeric(fv2);
            if (v < best_val) { best_val = v; best = row; }
        }
    }
    return vval_retain(best);
}

VexValue *builtin_max_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("max-by: expected list input");
    if (input->list.len == 0) return vval_null();
    if (argc < 1) { fprintf(stderr, "max-by: expected field or closure\n"); return vval_null(); }

    VexValue *best = input->list.data[0];
    double best_val;

    if (args[0]->type == VEX_VAL_CLOSURE) {
        VexValue *ca[1] = { best };
        VexValue *r = eval_call_closure(ctx, args[0], ca, 1);
        best_val = extract_numeric(r);
        vval_release(r);
        for (size_t i = 1; i < input->list.len; i++) {
            VexValue *ca2[1] = { input->list.data[i] };
            VexValue *r2 = eval_call_closure(ctx, args[0], ca2, 1);
            double v = extract_numeric(r2);
            vval_release(r2);
            if (v > best_val) { best_val = v; best = input->list.data[i]; }
        }
    } else if (args[0]->type == VEX_VAL_STRING) {
        const char *field = vstr_data(&args[0]->string);
        VexValue *fv = (best->type == VEX_VAL_RECORD) ? vval_record_get(best, field) : NULL;
        best_val = extract_numeric(fv);
        for (size_t i = 1; i < input->list.len; i++) {
            VexValue *row = input->list.data[i];
            VexValue *fv2 = (row->type == VEX_VAL_RECORD) ? vval_record_get(row, field) : NULL;
            double v = extract_numeric(fv2);
            if (v > best_val) { best_val = v; best = row; }
        }
    }
    return vval_retain(best);
}

VexValue *builtin_sum_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("sum-by: expected list input");
    if (argc < 1) { fprintf(stderr, "sum-by: expected field or closure\n"); return vval_null(); }

    double total = 0.0;
    bool all_int = true;
    int64_t int_total = 0;

    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        double v;
        if (args[0]->type == VEX_VAL_CLOSURE) {
            VexValue *ca[1] = { item };
            VexValue *r = eval_call_closure(ctx, args[0], ca, 1);
            v = extract_numeric(r);
            if (r->type != VEX_VAL_INT) all_int = false;
            else int_total += r->integer;
            vval_release(r);
        } else if (args[0]->type == VEX_VAL_STRING && item->type == VEX_VAL_RECORD) {
            VexValue *fv = vval_record_get(item, vstr_data(&args[0]->string));
            v = extract_numeric(fv);
            if (!fv || fv->type != VEX_VAL_INT) all_int = false;
            else int_total += fv->integer;
        } else { v = 0; all_int = false; }
        total += v;
    }
    return all_int ? vval_int(int_total) : vval_float(total);
}

VexValue *builtin_frequencies(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("frequencies: expected list input");

    VexMap counts = vmap_new();
    for (size_t i = 0; i < input->list.len; i++) {
        VexStr key = vval_to_str(input->list.data[i]);
        VexValue *existing = vmap_get(&counts, vstr_data(&key));
        int64_t c = existing ? existing->integer + 1 : 1;
        VexValue *cv = vval_int(c);
        if (existing) vval_release(existing);
        vmap_set(&counts, vstr_data(&key), cv);
        vstr_free(&key);
    }

    VexValue *result = vval_list();
    VexMapIter it = vmap_iter(&counts);
    const char *key; void *val;
    while (vmap_next(&it, &key, &val)) {
        VexValue *rec = vval_record();
        vval_record_set(rec, "value", vval_string_cstr(key));
        vval_record_set(rec, "count", vval_retain(val));
        vval_list_push(result, rec);
        vval_release(rec);
    }

    VexMapIter it2 = vmap_iter(&counts);
    while (vmap_next(&it2, &key, &val))
        vval_release(val);
    vmap_free(&counts);
    return result;
}

static void yaml_serialize(VexValue *v, VexStr *out, int indent) {
    if (!v || v->type == VEX_VAL_NULL) { vstr_append_cstr(out, "null"); return; }
    switch (v->type) {
    case VEX_VAL_BOOL:
        vstr_append_cstr(out, v->boolean ? "true" : "false");
        break;
    case VEX_VAL_INT: {
        VexStr s = vstr_fmt("%ld", v->integer);
        vstr_append_str(out, &s); vstr_free(&s);
        break;
    }
    case VEX_VAL_FLOAT: {
        VexStr s = vstr_fmt("%g", v->floating);
        vstr_append_str(out, &s); vstr_free(&s);
        break;
    }
    case VEX_VAL_STRING: {
        const char *s = vstr_data(&v->string);

        bool need_quote = false;
        for (const char *p = s; *p; p++) {
            if (*p == ':' || *p == '#' || *p == '\n' || *p == '"' ||
                *p == '\'' || *p == '{' || *p == '}' || *p == '[' || *p == ']') {
                need_quote = true; break;
            }
        }
        if (need_quote) {
            vstr_append_char(out, '"');
            for (const char *p = s; *p; p++) {
                if (*p == '"') vstr_append_cstr(out, "\\\"");
                else if (*p == '\\') vstr_append_cstr(out, "\\\\");
                else if (*p == '\n') vstr_append_cstr(out, "\\n");
                else vstr_append_char(out, *p);
            }
            vstr_append_char(out, '"');
        } else {
            vstr_append_cstr(out, s);
        }
        break;
    }
    case VEX_VAL_LIST:
        if (v->list.len == 0) { vstr_append_cstr(out, "[]"); break; }
        for (size_t i = 0; i < v->list.len; i++) {
            if (i > 0 || indent > 0) {
                vstr_append_char(out, '\n');
                for (int k = 0; k < indent; k++) vstr_append_cstr(out, "  ");
            }
            vstr_append_cstr(out, "- ");
            VexValue *item = v->list.data[i];
            if (item && item->type == VEX_VAL_RECORD) {

                VexMapIter it = vmap_iter(&item->record);
                const char *key; void *val;
                bool first = true;
                while (vmap_next(&it, &key, &val)) {
                    if (!first) {
                        vstr_append_char(out, '\n');
                        for (int k = 0; k < indent + 1; k++) vstr_append_cstr(out, "  ");
                    }
                    vstr_append_cstr(out, key);
                    vstr_append_cstr(out, ": ");
                    yaml_serialize(val, out, indent + 2);
                    first = false;
                }
            } else {
                yaml_serialize(item, out, indent + 1);
            }
        }
        break;
    case VEX_VAL_RECORD: {
        VexMapIter it = vmap_iter(&v->record);
        const char *key; void *val;
        bool first = true;
        while (vmap_next(&it, &key, &val)) {
            if (!first) {
                vstr_append_char(out, '\n');
                for (int k = 0; k < indent; k++) vstr_append_cstr(out, "  ");
            }
            vstr_append_cstr(out, key);
            vstr_append_cstr(out, ": ");
            if (val && (((VexValue*)val)->type == VEX_VAL_RECORD ||
                        ((VexValue*)val)->type == VEX_VAL_LIST)) {
                yaml_serialize(val, out, indent + 1);
            } else {
                yaml_serialize(val, out, indent);
            }
            first = false;
        }
        break;
    }
    default:
        vstr_append_cstr(out, "null");
        break;
    }
}

VexValue *builtin_to_yaml(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    VexStr out = vstr_new("");
    yaml_serialize(input, &out, 0);
    vstr_append_char(&out, '\n');
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_from_ini(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *data = vstr_data(&input->string);

    VexValue *result = vval_record();
    VexValue *current_section = result;
    const char *line_start = data;

    while (*line_start) {
        const char *line_end = strchr(line_start, '\n');
        if (!line_end) line_end = line_start + strlen(line_start);
        size_t line_len = (size_t)(line_end - line_start);
        if (line_len > 0 && line_start[line_len - 1] == '\r') line_len--;

        const char *p = line_start;
        while (p < line_start + line_len && (*p == ' ' || *p == '\t')) p++;
        size_t trimmed_len = line_len - (size_t)(p - line_start);

        if (trimmed_len == 0 || *p == '#' || *p == ';') {

        } else if (*p == '[') {

            const char *close = memchr(p, ']', trimmed_len);
            if (close) {
                char section[256] = {0};
                size_t slen = (size_t)(close - p - 1);
                if (slen < sizeof(section)) memcpy(section, p + 1, slen);
                current_section = vval_record();
                vval_record_set(result, section, current_section);
                vval_release(current_section);

                current_section = vval_record_get(result, section);
            }
        } else {

            const char *eq = memchr(p, '=', trimmed_len);
            if (eq) {

                const char *ke = eq - 1;
                while (ke > p && (*ke == ' ' || *ke == '\t')) ke--;
                char key[256] = {0};
                size_t klen = (size_t)(ke - p + 1);
                if (klen < sizeof(key)) memcpy(key, p, klen);

                const char *vs = eq + 1;
                while (*vs == ' ' || *vs == '\t') vs++;
                const char *ve = line_start + line_len - 1;
                while (ve > vs && (*ve == ' ' || *ve == '\t')) ve--;
                char val[4096] = {0};
                size_t vlen = (size_t)(ve - vs + 1);
                if (vlen < sizeof(val)) memcpy(val, vs, vlen);

                vval_record_set(current_section, key, vval_string_cstr(val));
            }
        }
        line_start = *line_end ? line_end + 1 : line_end;
    }
    return result;
}

VexValue *builtin_to_ini(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_RECORD) return vval_null();

    VexStr out = vstr_new("");
    VexMapIter it = vmap_iter(&input->record);
    const char *key; void *val;

    while (vmap_next(&it, &key, &val)) {
        VexValue *v = val;
        if (v->type != VEX_VAL_RECORD) {
            vstr_append_cstr(&out, key);
            vstr_append_cstr(&out, " = ");
            VexStr s = vval_to_str(v);
            vstr_append_str(&out, &s);
            vstr_free(&s);
            vstr_append_char(&out, '\n');
        }
    }

    it = vmap_iter(&input->record);
    while (vmap_next(&it, &key, &val)) {
        VexValue *v = val;
        if (v->type == VEX_VAL_RECORD) {
            vstr_append_char(&out, '\n');
            vstr_append_char(&out, '[');
            vstr_append_cstr(&out, key);
            vstr_append_cstr(&out, "]\n");
            VexMapIter sit = vmap_iter(&v->record);
            const char *sk; void *sv;
            while (vmap_next(&sit, &sk, &sv)) {
                vstr_append_cstr(&out, sk);
                vstr_append_cstr(&out, " = ");
                VexStr s = vval_to_str(sv);
                vstr_append_str(&out, &s);
                vstr_free(&s);
                vstr_append_char(&out, '\n');
            }
        }
    }
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_mktemp_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    bool is_dir = false;
    const char *prefix = "vex";
    for (size_t i = 0; i < argc; i++) {
        if (args[i]->type != VEX_VAL_STRING) continue;
        const char *a = vstr_data(&args[i]->string);
        if (strcmp(a, "-d") == 0) is_dir = true;
        else prefix = a;
    }

    char tmpl[PATH_MAX];
    snprintf(tmpl, sizeof(tmpl), "/tmp/%s.XXXXXX", prefix);

    if (is_dir) {
        char *result = mkdtemp(tmpl);
        if (!result) {
            fprintf(stderr, "mktemp: failed: %s\n", strerror(errno));
            return vval_null();
        }
        if (!ctx->in_pipeline) printf("%s\n", result);
        return vval_string_cstr(result);
    } else {
        int fd = mkstemp(tmpl);
        if (fd < 0) {
            fprintf(stderr, "mktemp: failed: %s\n", strerror(errno));
            return vval_null();
        }
        close(fd);
        if (!ctx->in_pipeline) printf("%s\n", tmpl);
        return vval_string_cstr(tmpl);
    }
}

VexValue *builtin_realpath_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    const char *path = NULL;
    if (input && input->type == VEX_VAL_STRING)
        path = vstr_data(&input->string);
    else if (argc >= 1 && args[0]->type == VEX_VAL_STRING)
        path = vstr_data(&args[0]->string);
    if (!path) { fprintf(stderr, "realpath: expected path\n"); return vval_null(); }

    char cmd[PATH_MAX + 32];
    snprintf(cmd, sizeof(cmd), "realpath -- '%s' 2>/dev/null", path);
    FILE *f = popen(cmd, "r");
    if (f) {
        char resolved[PATH_MAX];
        if (fgets(resolved, sizeof(resolved), f)) {
            size_t len = strlen(resolved);
            if (len > 0 && resolved[len-1] == '\n') resolved[len-1] = '\0';
            pclose(f);
            if (!ctx->in_pipeline) printf("%s\n", resolved);
            return vval_string_cstr(resolved);
        }
        pclose(f);
    }

    if (path[0] == '/') {
        if (!ctx->in_pipeline) printf("%s\n", path);
        return vval_string_cstr(path);
    }
    char cwd[PATH_MAX];
    char resolved[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) return vval_string_cstr(path);
    snprintf(resolved, sizeof(resolved), "%s/%s", cwd, path);
    if (!ctx->in_pipeline) printf("%s\n", resolved);
    return vval_string_cstr(resolved);
}

VexValue *builtin_ln(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 2) {
        fprintf(stderr, "ln: expected target and link name\nUsage: ln [-s] <target> <link>\n");
        return vval_null();
    }
    bool symbolic = false;
    size_t target_idx = 0;
    if (args[0]->type == VEX_VAL_STRING && strcmp(vstr_data(&args[0]->string), "-s") == 0) {
        symbolic = true;
        target_idx = 1;
    }
    if (target_idx + 1 >= argc) {
        fprintf(stderr, "ln: expected target and link name\n");
        return vval_null();
    }
    const char *target = vstr_data(&args[target_idx]->string);
    const char *linkname = vstr_data(&args[target_idx + 1]->string);

    int ret;
    if (symbolic)
        ret = symlink(target, linkname);
    else
        ret = link(target, linkname);

    if (ret != 0) {
        fprintf(stderr, "ln: failed: %s\n", strerror(errno));
        return vval_bool(false);
    }
    return vval_bool(true);
}

VexValue *builtin_readlink(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    const char *path = NULL;
    if (input && input->type == VEX_VAL_STRING)
        path = vstr_data(&input->string);
    else if (argc >= 1 && args[0]->type == VEX_VAL_STRING)
        path = vstr_data(&args[0]->string);
    if (!path) { fprintf(stderr, "readlink: expected path\n"); return vval_null(); }

    char buf[PATH_MAX];
    ssize_t len = readlink(path, buf, sizeof(buf) - 1);
    if (len < 0) {
        fprintf(stderr, "readlink: %s: %s\n", path, strerror(errno));
        return vval_null();
    }
    buf[len] = '\0';
    if (!ctx->in_pipeline) printf("%s\n", buf);
    return vval_string_cstr(buf);
}

VexValue *builtin_chmod(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;

    if (has_flag_args(args, argc))
        return fallback_external(ctx, "chmod", args, argc);
    if (argc < 2) {
        fprintf(stderr, "chmod: expected mode and file(s)\nUsage: chmod <mode> <file...>\n");
        return vval_null();
    }
    const char *mode_str = vstr_data(&args[0]->string);
    unsigned int mode;
    if (sscanf(mode_str, "%o", &mode) != 1) {
        fprintf(stderr, "chmod: invalid mode '%s'\n", mode_str);
        return vval_null();
    }
    for (size_t i = 1; i < argc; i++) {
        const char *path = vstr_data(&args[i]->string);
        if (chmod(path, (mode_t)mode) != 0)
            fprintf(stderr, "chmod: %s: %s\n", path, strerror(errno));
    }
    return vval_null();
}

VexValue *builtin_head_text(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {

    if (has_flag_args(args, argc))
        return fallback_external(ctx, "head", args, argc);
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    int64_t n = 10;
    if (argc >= 1) {
        if (args[0]->type == VEX_VAL_INT) n = args[0]->integer;
        else if (args[0]->type == VEX_VAL_STRING) n = strtol(vstr_data(&args[0]->string), NULL, 10);
    }
    if (n <= 0) return vval_string_cstr("");

    const char *s = vstr_data(&input->string);
    const char *p = s;
    int64_t count = 0;
    while (*p && count < n) {
        if (*p == '\n') count++;
        p++;
    }
    size_t len = (size_t)(p - s);
    char *buf = malloc(len + 1);
    memcpy(buf, s, len);
    buf[len] = '\0';
    VexValue *result = vval_string_cstr(buf);
    free(buf);
    return result;
}

VexValue *builtin_tail_text(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {

    if (has_flag_args(args, argc))
        return fallback_external(ctx, "tail", args, argc);
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    int64_t n = 10;
    if (argc >= 1) {
        if (args[0]->type == VEX_VAL_INT) n = args[0]->integer;
        else if (args[0]->type == VEX_VAL_STRING) n = strtol(vstr_data(&args[0]->string), NULL, 10);
    }
    if (n <= 0) return vval_string_cstr("");

    const char *s = vstr_data(&input->string);
    size_t slen = vstr_len(&input->string);

    int64_t total = 0;
    for (size_t i = 0; i < slen; i++)
        if (s[i] == '\n') total++;
    if (slen > 0 && s[slen-1] != '\n') total++;

    int64_t skip = total - n;
    if (skip < 0) skip = 0;

    const char *p = s;
    int64_t count = 0;
    while (*p && count < skip) {
        if (*p == '\n') count++;
        p++;
    }
    return vval_string_cstr(p);
}

VexValue *builtin_tac(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (argc > 0)
        return fallback_external(ctx, "tac", args, argc);
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_null();
    const char *s = vstr_data(&input->string);

    VexStr out = vstr_new("");
    size_t slen = vstr_len(&input->string);

    const char *lines[8192];
    size_t line_lens[8192];
    size_t line_count = 0;
    const char *p = s;
    while (p < s + slen && line_count < 8192) {
        const char *nl = strchr(p, '\n');
        if (!nl) nl = s + slen;
        lines[line_count] = p;
        line_lens[line_count] = (size_t)(nl - p);
        line_count++;
        p = (*nl) ? nl + 1 : nl;
    }

    for (size_t i = line_count; i > 0; i--) {
        vstr_append(&out, lines[i-1], line_lens[i-1]);
        if (i > 1) vstr_append_char(&out, '\n');
    }
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_with_env(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 2 || args[0]->type != VEX_VAL_RECORD || args[1]->type != VEX_VAL_CLOSURE) {
        fprintf(stderr, "with-env: expected record and closure\nUsage: with-env {KEY: val} {|| cmd}\n");
        return vval_null();
    }

    VexMapIter it = vmap_iter(&args[0]->record);
    const char *key; void *val;

    const char *keys[64];
    char *old_vals[64];
    size_t count = 0;
    while (vmap_next(&it, &key, &val) && count < 64) {
        keys[count] = key;
        const char *old = getenv(key);
        old_vals[count] = old ? strdup(old) : NULL;
        VexStr sv = vval_to_str(val);
        setenv(key, vstr_data(&sv), 1);
        vstr_free(&sv);
        count++;
    }

    VexValue *null_in = vval_null();
    VexValue *call_args[1] = { null_in };
    VexValue *result = eval_call_closure(ctx, args[1], call_args, 1);
    vval_release(null_in);

    for (size_t i = 0; i < count; i++) {
        if (old_vals[i]) {
            setenv(keys[i], old_vals[i], 1);
            free(old_vals[i]);
        } else {
            unsetenv(keys[i]);
        }
    }
    return result;
}

VexValue *builtin_retry(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_CLOSURE) {
        fprintf(stderr, "retry: expected closure\nUsage: retry <closure> [max_attempts] [delay_secs]\n");
        return vval_null();
    }
    int64_t max_attempts = 3;
    double delay = 1.0;
    if (argc >= 2) {
        if (args[1]->type == VEX_VAL_INT) max_attempts = args[1]->integer;
        else if (args[1]->type == VEX_VAL_STRING) max_attempts = strtol(vstr_data(&args[1]->string), NULL, 10);
    }
    if (argc >= 3) {
        if (args[2]->type == VEX_VAL_FLOAT) delay = args[2]->floating;
        else if (args[2]->type == VEX_VAL_INT) delay = (double)args[2]->integer;
        else if (args[2]->type == VEX_VAL_STRING) delay = strtod(vstr_data(&args[2]->string), NULL);
    }

    VexValue *null_in = vval_null();
    VexValue *result = NULL;
    for (int64_t attempt = 0; attempt < max_attempts; attempt++) {
        VexValue *call_args[1] = { null_in };
        result = eval_call_closure(ctx, args[0], call_args, 1);
        if (result && result->type != VEX_VAL_ERROR && vval_truthy(result)) {
            vval_release(null_in);
            return result;
        }
        if (result) vval_release(result);
        if (attempt + 1 < max_attempts) {
            struct timespec ts;
            ts.tv_sec = (time_t)delay;
            ts.tv_nsec = (long)((delay - (double)ts.tv_sec) * 1e9);
            nanosleep(&ts, NULL);
        }
    }
    vval_release(null_in);
    fprintf(stderr, "retry: all %ld attempts failed\n", max_attempts);
    return vval_null();
}

VexValue *builtin_timeout_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 2) {
        fprintf(stderr, "timeout: expected seconds and closure\nUsage: timeout <secs> <closure>\n");
        return vval_null();
    }
    double secs = 0;
    if (args[0]->type == VEX_VAL_INT) secs = (double)args[0]->integer;
    else if (args[0]->type == VEX_VAL_FLOAT) secs = args[0]->floating;
    else if (args[0]->type == VEX_VAL_STRING) secs = strtod(vstr_data(&args[0]->string), NULL);

    if (args[1]->type != VEX_VAL_CLOSURE) {
        fprintf(stderr, "timeout: second argument must be a closure\n");
        return vval_null();
    }

    alarm((unsigned int)secs);
    VexValue *null_in = vval_null();
    VexValue *call_args[1] = { null_in };
    VexValue *result = eval_call_closure(ctx, args[1], call_args, 1);
    alarm(0);
    vval_release(null_in);
    return result;
}

static char *defer_commands[64];
static size_t defer_count = 0;

VexValue *builtin_defer(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1) {
        fprintf(stderr, "defer: expected command string\n");
        return vval_null();
    }
    if (defer_count >= 64) {
        fprintf(stderr, "defer: too many deferred commands\n");
        return vval_null();
    }

    VexStr cmd = vstr_new("");
    for (size_t i = 0; i < argc; i++) {
        if (i > 0) vstr_append_char(&cmd, ' ');
        if (args[i]->type == VEX_VAL_STRING)
            vstr_append_cstr(&cmd, vstr_data(&args[i]->string));
        else {
            VexStr s = vval_to_str(args[i]);
            vstr_append_str(&cmd, &s);
            vstr_free(&s);
        }
    }
    defer_commands[defer_count++] = strdup(vstr_data(&cmd));
    vstr_free(&cmd);
    return vval_null();
}

void builtin_run_defers(EvalCtx *ctx) {

    while (defer_count > 0) {
        defer_count--;
        char *cmd = defer_commands[defer_count];
        Parser p = parser_init(cmd, ctx->arena);
        ASTNode *node;
        while ((node = parser_parse_line(&p))) {
            VexValue *r = eval(ctx, node);
            if (r) vval_release(r);
        }
        free(cmd);
    }
}

VexValue *builtin_parallel(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1) {
        fprintf(stderr, "parallel: expected closures\nUsage: parallel {|| a} {|| b} ...\n");
        return vval_null();
    }

    size_t n = argc;
    int pipes[64][2];
    pid_t pids[64];
    if (n > 64) n = 64;

    for (size_t i = 0; i < n; i++) {
        if (args[i]->type != VEX_VAL_CLOSURE) {
            fprintf(stderr, "parallel: argument %zu is not a closure\n", i);
            return vval_null();
        }
        if (pipe(pipes[i]) < 0) {
            fprintf(stderr, "parallel: pipe failed\n");
            return vval_null();
        }
        pids[i] = fork();
        if (pids[i] == 0) {

            close(pipes[i][0]);
            VexValue *null_in = vval_null();
            VexValue *ca[1] = { null_in };
            VexValue *result = eval_call_closure(ctx, args[i], ca, 1);

            VexStr s = vval_to_str(result);
            write(pipes[i][1], vstr_data(&s), vstr_len(&s));
            vstr_free(&s);
            if (result) vval_release(result);
            vval_release(null_in);
            close(pipes[i][1]);
            _exit(0);
        }
        close(pipes[i][1]);
    }

    VexValue *result = vval_list();
    for (size_t i = 0; i < n; i++) {
        char buf[65536];
        ssize_t nread = read(pipes[i][0], buf, sizeof(buf) - 1);
        close(pipes[i][0]);
        waitpid(pids[i], NULL, 0);
        if (nread > 0) {
            buf[nread] = '\0';
            vval_list_push(result, vval_string_cstr(buf));
        } else {
            vval_list_push(result, vval_null());
        }
    }
    return result;
}

VexValue *builtin_disown(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    int id;
    if (argc > 0 && args[0]->type == VEX_VAL_INT) {
        id = (int)args[0]->integer;
    } else {
        id = job_last_id();
        if (id < 0) {
            vex_err("disown: no current job");
            return vval_error("no current job");
        }
    }
    job_disown(id);
    return vval_null();
}

VexValue *builtin_math_sqrt(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    double v;
    if (input->type == VEX_VAL_INT) v = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) v = input->floating;
    else return vval_error("math-sqrt: expected number");
    if (v < 0) return vval_error("math-sqrt: negative input");
    return vval_float(sqrt(v));
}

VexValue *builtin_math_pow(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || argc < 1) return vval_error("math-pow: expected base | math-pow <exp>");
    double base, exp_v;
    if (input->type == VEX_VAL_INT) base = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) base = input->floating;
    else return vval_error("math-pow: base must be number");
    if (args[0]->type == VEX_VAL_INT) exp_v = (double)args[0]->integer;
    else if (args[0]->type == VEX_VAL_FLOAT) exp_v = args[0]->floating;
    else return vval_error("math-pow: exponent must be number");
    double result = pow(base, exp_v);

    if (input->type == VEX_VAL_INT && args[0]->type == VEX_VAL_INT &&
        exp_v >= 0 && result == (double)(int64_t)result) {
        return vval_int((int64_t)result);
    }
    return vval_float(result);
}

VexValue *builtin_math_log(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input) return vval_error("math-log: expected number");
    double v;
    if (input->type == VEX_VAL_INT) v = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) v = input->floating;
    else return vval_error("math-log: expected number");
    if (v <= 0) return vval_error("math-log: non-positive input");

    if (argc > 0) {
        double base;
        if (args[0]->type == VEX_VAL_INT) base = (double)args[0]->integer;
        else if (args[0]->type == VEX_VAL_FLOAT) base = args[0]->floating;
        else return vval_error("math-log: base must be number");
        if (base <= 0 || base == 1.0) return vval_error("math-log: invalid base");
        return vval_float(log(v) / log(base));
    }
    return vval_float(log(v));
}

VexValue *builtin_math_ceil(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    if (input->type == VEX_VAL_INT) return vval_int(input->integer);
    if (input->type == VEX_VAL_FLOAT) return vval_int((int64_t)ceil(input->floating));
    return vval_error("math-ceil: expected number");
}

VexValue *builtin_math_floor(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    if (input->type == VEX_VAL_INT) return vval_int(input->integer);
    if (input->type == VEX_VAL_FLOAT) return vval_int((int64_t)floor(input->floating));
    return vval_error("math-floor: expected number");
}

VexValue *builtin_math_sin(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    double v;
    if (input->type == VEX_VAL_INT) v = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) v = input->floating;
    else return vval_error("math-sin: expected number");
    return vval_float(sin(v));
}

VexValue *builtin_math_cos(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    double v;
    if (input->type == VEX_VAL_INT) v = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) v = input->floating;
    else return vval_error("math-cos: expected number");
    return vval_float(cos(v));
}

VexValue *builtin_math_tan(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    double v;
    if (input->type == VEX_VAL_INT) v = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) v = input->floating;
    else return vval_error("math-tan: expected number");
    return vval_float(tan(v));
}

VexValue *builtin_http_get(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_STRING) {
        vex_err("http-get: expected URL");
        return vval_error("missing URL");
    }
    const char *url = vstr_data(&args[0]->string);

    int pipefd[2];
    if (pipe(pipefd) < 0) return vval_error("http-get: pipe failed");

    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        execlp("curl", "curl", "-sS", "-L", url, (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);

    VexStr buf = vstr_new("");
    char chunk[4096];
    ssize_t n;
    while ((n = read(pipefd[0], chunk, sizeof(chunk) - 1)) > 0) {
        chunk[n] = '\0';
        vstr_append_cstr(&buf, chunk);
    }
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
        vstr_free(&buf);
        return vval_error("http-get: curl not found in PATH");
    }
    ctx->last_exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

    VexValue *result = vval_string_cstr(vstr_data(&buf));
    vstr_free(&buf);
    return result;
}

VexValue *builtin_http_post(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (argc < 1 || args[0]->type != VEX_VAL_STRING) {
        vex_err("http-post: expected URL");
        return vval_error("missing URL");
    }
    const char *url = vstr_data(&args[0]->string);

    const char *body = NULL;
    VexStr body_str = vstr_new("");
    if (argc > 1 && args[1]->type == VEX_VAL_STRING) {
        body = vstr_data(&args[1]->string);
    } else if (input && input->type == VEX_VAL_STRING) {
        body = vstr_data(&input->string);
    } else if (input && input->type != VEX_VAL_NULL) {
        body_str = vval_to_str(input);
        body = vstr_data(&body_str);
    }

    const char *content_type = "application/json";
    if (body && body[0] != '{' && body[0] != '[') {
        content_type = "text/plain";
    }

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        vstr_free(&body_str);
        return vval_error("http-post: pipe failed");
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        char ct_header[128];
        snprintf(ct_header, sizeof(ct_header), "Content-Type: %s", content_type);

        if (body) {
            execlp("curl", "curl", "-sS", "-L", "-X", "POST",
                   "-H", ct_header, "-d", body, url, (char *)NULL);
        } else {
            execlp("curl", "curl", "-sS", "-L", "-X", "POST",
                   url, (char *)NULL);
        }
        _exit(127);
    }
    close(pipefd[1]);

    VexStr buf = vstr_new("");
    char chunk[4096];
    ssize_t n;
    while ((n = read(pipefd[0], chunk, sizeof(chunk) - 1)) > 0) {
        chunk[n] = '\0';
        vstr_append_cstr(&buf, chunk);
    }
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
        vstr_free(&buf);
        vstr_free(&body_str);
        return vval_error("http-post: curl not found in PATH");
    }
    ctx->last_exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

    VexValue *result = vval_string_cstr(vstr_data(&buf));
    vstr_free(&buf);
    vstr_free(&body_str);
    return result;
}

VexValue *builtin_str_truncate(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING) return input ? vval_retain(input) : vval_null();
    if (argc < 1 || args[0]->type != VEX_VAL_INT) {
        vex_err("str-truncate: expected width");
        return vval_retain(input);
    }
    int64_t width = args[0]->integer;
    if (width < 0) width = 0;

    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);

    if ((int64_t)len <= width) return vval_retain(input);

    if (width <= 3) {
        VexStr out = vstr_new("");
        for (int64_t i = 0; i < width; i++) vstr_append_char(&out, '.');
        VexValue *result = vval_string_cstr(vstr_data(&out));
        vstr_free(&out);
        return result;
    }

    VexStr out = vstr_new("");
    for (int64_t i = 0; i < width - 3; i++) vstr_append_char(&out, s[i]);
    vstr_append_cstr(&out, "...");
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

#ifdef __APPLE__
#include <sys/sysctl.h>
#include <mach/mach.h>
#else
#include <sys/sysinfo.h>
#endif

VexValue *builtin_uptime(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    long secs;
#ifdef __APPLE__
    struct timeval boottime;
    size_t bt_len = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if (sysctl(mib, 2, &boottime, &bt_len, NULL, 0) < 0)
        return vval_error("uptime: failed");
    secs = (long)(time(NULL) - boottime.tv_sec);
#else
    struct sysinfo si;
    if (sysinfo(&si) < 0) return vval_error("uptime: failed");
    secs = si.uptime;
#endif
    long days = secs / 86400;
    long hours = (secs % 86400) / 3600;
    long mins = (secs % 3600) / 60;
    long rem_secs = secs % 60;

    VexValue *rec = vval_record();
    vval_record_set(rec, "days", vval_int(days));
    vval_record_set(rec, "hours", vval_int(hours));
    vval_record_set(rec, "minutes", vval_int(mins));
    vval_record_set(rec, "seconds", vval_int(rem_secs));
    vval_record_set(rec, "total_seconds", vval_int(secs));

    char pretty[128];
    if (days > 0) {
        snprintf(pretty, sizeof(pretty), "%ldd %ldh %ldm %lds", days, hours, mins, rem_secs);
    } else if (hours > 0) {
        snprintf(pretty, sizeof(pretty), "%ldh %ldm %lds", hours, mins, rem_secs);
    } else {
        snprintf(pretty, sizeof(pretty), "%ldm %lds", mins, rem_secs);
    }
    vval_record_set(rec, "pretty", vval_string_cstr(pretty));

    return rec;
}

static VexValue *http_method(EvalCtx *ctx, const char *method,
                             const char *url, const char *body) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return vval_error("http: pipe failed");

    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        if (body) {
            execlp("curl", "curl", "-sS", "-L", "-X", method,
                   "-H", "Content-Type: application/json",
                   "-d", body, url, (char *)NULL);
        } else {
            execlp("curl", "curl", "-sS", "-L", "-X", method,
                   url, (char *)NULL);
        }
        _exit(127);
    }
    close(pipefd[1]);

    VexStr buf = vstr_new("");
    char chunk[4096];
    ssize_t n;
    while ((n = read(pipefd[0], chunk, sizeof(chunk) - 1)) > 0) {
        chunk[n] = '\0';
        vstr_append_cstr(&buf, chunk);
    }
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
        vstr_free(&buf);
        return vval_error("http: curl not found in PATH");
    }
    ctx->last_exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

    VexValue *result = vval_string_cstr(vstr_data(&buf));
    vstr_free(&buf);
    return result;
}

VexValue *builtin_http_put(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (argc < 1 || args[0]->type != VEX_VAL_STRING) {
        vex_err("http-put: expected URL");
        return vval_error("missing URL");
    }
    const char *url = vstr_data(&args[0]->string);
    const char *body = NULL;
    VexStr body_str = vstr_new("");
    if (argc > 1 && args[1]->type == VEX_VAL_STRING) {
        body = vstr_data(&args[1]->string);
    } else if (input && input->type == VEX_VAL_STRING) {
        body = vstr_data(&input->string);
    } else if (input && input->type != VEX_VAL_NULL) {
        body_str = vval_to_str(input);
        body = vstr_data(&body_str);
    }
    VexValue *result = http_method(ctx, "PUT", url, body);
    vstr_free(&body_str);
    return result;
}

VexValue *builtin_http_delete(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_STRING) {
        vex_err("http-delete: expected URL");
        return vval_error("missing URL");
    }
    return http_method(ctx, "DELETE", vstr_data(&args[0]->string), NULL);
}

VexValue *builtin_http_head(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_STRING) {
        vex_err("http-head: expected URL");
        return vval_error("missing URL");
    }
    const char *url = vstr_data(&args[0]->string);

    int pipefd[2];
    if (pipe(pipefd) < 0) return vval_error("http-head: pipe failed");

    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        execlp("curl", "curl", "-sS", "-L", "-I", url, (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);

    VexStr buf = vstr_new("");
    char chunk[4096];
    ssize_t n;
    while ((n = read(pipefd[0], chunk, sizeof(chunk) - 1)) > 0) {
        chunk[n] = '\0';
        vstr_append_cstr(&buf, chunk);
    }
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
        vstr_free(&buf);
        return vval_error("http-head: curl not found in PATH");
    }
    ctx->last_exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;

    VexValue *rec = vval_record();
    const char *data = vstr_data(&buf);
    const char *line = data;
    while (*line) {
        const char *eol = strstr(line, "\r\n");
        if (!eol) eol = line + strlen(line);
        size_t llen = (size_t)(eol - line);
        if (llen == 0) { line = eol + 2; continue; }

        const char *colon = memchr(line, ':', llen);
        if (colon) {
            char key[256];
            size_t klen = (size_t)(colon - line);
            if (klen >= sizeof(key)) klen = sizeof(key) - 1;
            memcpy(key, line, klen);
            key[klen] = '\0';

            for (size_t i = 0; i < klen; i++) key[i] = (char)tolower(key[i]);

            const char *val = colon + 1;
            while (*val == ' ') val++;
            size_t vlen = (size_t)(eol - val);
            char *vbuf = malloc(vlen + 1);
            memcpy(vbuf, val, vlen);
            vbuf[vlen] = '\0';
            vval_record_set(rec, key, vval_string_cstr(vbuf));
            free(vbuf);
        }
        line = (*eol) ? eol + 2 : eol;
    }
    vstr_free(&buf);
    return rec;
}

VexValue *builtin_math_pi(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    return vval_float(3.14159265358979323846);
}

VexValue *builtin_math_e(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    return vval_float(2.71828182845904523536);
}

VexValue *builtin_date_format(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (argc < 1 || args[0]->type != VEX_VAL_STRING) {
        vex_err("date-format: expected format string");
        return vval_error("missing format");
    }
    const char *fmt = vstr_data(&args[0]->string);

    time_t epoch;
    if (input && input->type == VEX_VAL_INT) {
        epoch = (time_t)input->integer;
    } else if (input && input->type == VEX_VAL_RECORD) {
        VexValue *ep = vval_record_get(input, "epoch");
        if (!ep || ep->type != VEX_VAL_INT) {
            return vval_error("date-format: record needs 'epoch' field");
        }
        epoch = (time_t)ep->integer;
    } else {

        epoch = time(NULL);
    }

    struct tm *tm = localtime(&epoch);
    char buf[512];
    strftime(buf, sizeof(buf), fmt, tm);
    return vval_string_cstr(buf);
}

VexValue *builtin_date_humanize(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_error("date-humanize: expected epoch timestamp");

    time_t epoch;
    if (input->type == VEX_VAL_INT) {
        epoch = (time_t)input->integer;
    } else if (input->type == VEX_VAL_RECORD) {
        VexValue *ep = vval_record_get(input, "epoch");
        if (!ep || ep->type != VEX_VAL_INT)
            return vval_error("date-humanize: record needs 'epoch' field");
        epoch = (time_t)ep->integer;
    } else {
        return vval_error("date-humanize: expected int or date record");
    }

    time_t now = time(NULL);
    long diff = (long)(now - epoch);
    bool future = diff < 0;
    if (future) diff = -diff;

    char buf[128];
    if (diff < 60) {
        snprintf(buf, sizeof(buf), "just now");
    } else if (diff < 3600) {
        long mins = diff / 60;
        snprintf(buf, sizeof(buf), "%ld minute%s %s",
                 mins, mins == 1 ? "" : "s", future ? "from now" : "ago");
    } else if (diff < 86400) {
        long hrs = diff / 3600;
        snprintf(buf, sizeof(buf), "%ld hour%s %s",
                 hrs, hrs == 1 ? "" : "s", future ? "from now" : "ago");
    } else if (diff < 2592000) {
        long days = diff / 86400;
        snprintf(buf, sizeof(buf), "%ld day%s %s",
                 days, days == 1 ? "" : "s", future ? "from now" : "ago");
    } else if (diff < 31536000) {
        long months = diff / 2592000;
        snprintf(buf, sizeof(buf), "%ld month%s %s",
                 months, months == 1 ? "" : "s", future ? "from now" : "ago");
    } else {
        long years = diff / 31536000;
        snprintf(buf, sizeof(buf), "%ld year%s %s",
                 years, years == 1 ? "" : "s", future ? "from now" : "ago");
    }
    return vval_string_cstr(buf);
}

VexValue *builtin_uniq_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST || argc < 1)
        return input ? vval_retain(input) : vval_null();

    VexValue *result = vval_list();

    VexMap seen = vmap_new();

    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *item = input->list.data[i];
        VexStr key_str;

        if (args[0]->type == VEX_VAL_STRING) {

            const char *field = vstr_data(&args[0]->string);
            VexValue *fv = (item->type == VEX_VAL_RECORD) ? vval_record_get(item, field) : NULL;
            key_str = fv ? vval_to_str(fv) : vstr_new("");
        } else if (args[0]->type == VEX_VAL_CLOSURE) {
            VexValue *ca[1] = { item };
            VexValue *kv = eval_call_closure(ctx, args[0], ca, 1);
            key_str = vval_to_str(kv);
            vval_release(kv);
        } else {
            key_str = vval_to_str(item);
        }

        if (!vmap_has(&seen, vstr_data(&key_str))) {
            vmap_set(&seen, vstr_data(&key_str), (void *)1);
            vval_list_push(result, item);
        }
        vstr_free(&key_str);
    }
    vmap_free(&seen);
    return result;
}

VexValue *builtin_rename(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || argc < 2) {
        vex_err("rename: usage: rename <old-name> <new-name>");
        return input ? vval_retain(input) : vval_null();
    }
    if (args[0]->type != VEX_VAL_STRING || args[1]->type != VEX_VAL_STRING) {
        vex_err("rename: expected string arguments");
        return vval_retain(input);
    }
    const char *old_name = vstr_data(&args[0]->string);
    const char *new_name = vstr_data(&args[1]->string);

    if (input->type == VEX_VAL_RECORD) {
        VexValue *rec = vval_record();
        VexMapIter it = vmap_iter(&input->record);
        const char *k;
        void *v;
        while (vmap_next(&it, &k, &v)) {
            if (strcmp(k, old_name) == 0) {
                vval_record_set(rec, new_name, (VexValue *)v);
            } else {
                vval_record_set(rec, k, (VexValue *)v);
            }
        }
        return rec;
    }
    if (input->type == VEX_VAL_LIST) {

        VexValue *result = vval_list();
        for (size_t i = 0; i < input->list.len; i++) {
            VexValue *item = input->list.data[i];
            if (item->type == VEX_VAL_RECORD) {
                VexValue *rec = vval_record();
                VexMapIter it = vmap_iter(&item->record);
                const char *k;
                void *v;
                while (vmap_next(&it, &k, &v)) {
                    if (strcmp(k, old_name) == 0)
                        vval_record_set(rec, new_name, (VexValue *)v);
                    else
                        vval_record_set(rec, k, (VexValue *)v);
                }
                vval_list_push(result, rec);
                vval_release(rec);
            } else {
                vval_list_push(result, item);
            }
        }
        return result;
    }
    return vval_retain(input);
}

VexValue *builtin_drop(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST) return input ? vval_retain(input) : vval_null();
    int64_t n = 1;
    if (argc > 0 && args[0]->type == VEX_VAL_INT) n = args[0]->integer;

    VexValue *result = vval_list();
    size_t len = input->list.len;

    if (n >= 0) {

        for (size_t i = (size_t)(n < (int64_t)len ? n : (int64_t)len); i < len; i++)
            vval_list_push(result, input->list.data[i]);
    } else {

        int64_t keep = (int64_t)len + n;
        if (keep < 0) keep = 0;
        for (int64_t i = 0; i < keep; i++)
            vval_list_push(result, input->list.data[i]);
    }
    return result;
}

VexValue *builtin_str_encode_uri(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return input ? vval_retain(input) : vval_null();
    const char *s = vstr_data(&input->string);
    VexStr out = vstr_new("");
    for (size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            vstr_append_char(&out, (char)c);
        } else {
            char hex[4];
            snprintf(hex, sizeof(hex), "%%%02X", c);
            vstr_append_cstr(&out, hex);
        }
    }
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

VexValue *builtin_str_decode_uri(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return input ? vval_retain(input) : vval_null();
    const char *s = vstr_data(&input->string);
    VexStr out = vstr_new("");
    for (size_t i = 0; s[i]; i++) {
        if (s[i] == '%' && s[i+1] && s[i+2]) {
            int hi = hex_digit(s[i+1]);
            int lo = hex_digit(s[i+2]);
            if (hi >= 0 && lo >= 0) {
                vstr_append_char(&out, (char)(hi * 16 + lo));
                i += 2;
                continue;
            }
        }
        if (s[i] == '+') {
            vstr_append_char(&out, ' ');
        } else {
            vstr_append_char(&out, s[i]);
        }
    }
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

VexValue *builtin_math_median(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST || input->list.len == 0)
        return vval_error("math-median: expected non-empty list");

    size_t n = input->list.len;
    double *vals = malloc(n * sizeof(double));
    for (size_t i = 0; i < n; i++) {
        VexValue *v = input->list.data[i];
        if (v->type == VEX_VAL_INT) vals[i] = (double)v->integer;
        else if (v->type == VEX_VAL_FLOAT) vals[i] = v->floating;
        else { free(vals); return vval_error("math-median: non-numeric item"); }
    }
    qsort(vals, n, sizeof(double), cmp_double);

    double median;
    if (n % 2 == 1) {
        median = vals[n / 2];
    } else {
        median = (vals[n / 2 - 1] + vals[n / 2]) / 2.0;
    }
    free(vals);
    return vval_float(median);
}

VexValue *builtin_math_stddev(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST || input->list.len == 0)
        return vval_error("math-stddev: expected non-empty list");

    size_t n = input->list.len;
    double sum = 0;
    for (size_t i = 0; i < n; i++) {
        VexValue *v = input->list.data[i];
        if (v->type == VEX_VAL_INT) sum += (double)v->integer;
        else if (v->type == VEX_VAL_FLOAT) sum += v->floating;
        else return vval_error("math-stddev: non-numeric item");
    }
    double mean = sum / (double)n;
    double var = 0;
    for (size_t i = 0; i < n; i++) {
        VexValue *v = input->list.data[i];
        double d = (v->type == VEX_VAL_INT ? (double)v->integer : v->floating) - mean;
        var += d * d;
    }
    return vval_float(sqrt(var / (double)n));
}

VexValue *builtin_math_product(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST) return vval_error("math-product: expected list");

    bool all_int = true;
    int64_t iprod = 1;
    double fprod = 1.0;
    for (size_t i = 0; i < input->list.len; i++) {
        VexValue *v = input->list.data[i];
        if (v->type == VEX_VAL_INT) {
            iprod *= v->integer;
            fprod *= (double)v->integer;
        } else if (v->type == VEX_VAL_FLOAT) {
            all_int = false;
            fprod *= v->floating;
        } else {
            return vval_error("math-product: non-numeric item");
        }
    }
    return all_int ? vval_int(iprod) : vval_float(fprod);
}

VexValue *builtin_from_yaml(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING)
        return vval_error("from-yaml: expected string input");

    const char *s = vstr_data(&input->string);

    VexValue *rec = vval_record();
    const char *line = s;
    char current_key[256] = {0};
    VexValue *current_list = NULL;

    while (*line) {

        const char *eol = strchr(line, '\n');
        size_t llen = eol ? (size_t)(eol - line) : strlen(line);

        size_t indent = 0;
        while (indent < llen && (line[indent] == ' ' || line[indent] == '\t')) indent++;

        if (indent == llen || line[indent] == '#') {
            line = eol ? eol + 1 : line + llen;
            continue;
        }

        if (line[indent] == '-' && indent + 1 < llen && line[indent + 1] == ' ') {
            const char *val = line + indent + 2;
            size_t vlen = llen - indent - 2;

            while (vlen > 0 && (val[vlen-1] == ' ' || val[vlen-1] == '\r')) vlen--;

            if (!current_list) {
                current_list = vval_list();
            }
            char *vbuf = strndup(val, vlen);

            char *endp;
            long lv = strtol(vbuf, &endp, 10);
            if (*endp == '\0' && endp != vbuf) {
                vval_list_push(current_list, vval_int(lv));
            } else {
                double dv = strtod(vbuf, &endp);
                if (*endp == '\0' && endp != vbuf) {
                    vval_list_push(current_list, vval_float(dv));
                } else if (strcmp(vbuf, "true") == 0) {
                    vval_list_push(current_list, vval_bool(true));
                } else if (strcmp(vbuf, "false") == 0) {
                    vval_list_push(current_list, vval_bool(false));
                } else if (strcmp(vbuf, "null") == 0 || strcmp(vbuf, "~") == 0) {
                    vval_list_push(current_list, vval_null());
                } else {
                    vval_list_push(current_list, vval_string_cstr(vbuf));
                }
            }
            free(vbuf);
            line = eol ? eol + 1 : line + llen;
            continue;
        }

        if (current_list && current_key[0]) {
            vval_record_set(rec, current_key, current_list);
            vval_release(current_list);
            current_list = NULL;
            current_key[0] = '\0';
        }

        const char *colon = memchr(line + indent, ':', llen - indent);
        if (colon) {
            size_t klen = (size_t)(colon - (line + indent));
            if (klen >= sizeof(current_key)) klen = sizeof(current_key) - 1;
            memcpy(current_key, line + indent, klen);
            current_key[klen] = '\0';

            while (klen > 0 && current_key[klen-1] == ' ') current_key[--klen] = '\0';

            const char *val = colon + 1;
            while (*val == ' ') val++;
            size_t vlen = llen - (size_t)(val - line);
            while (vlen > 0 && (val[vlen-1] == ' ' || val[vlen-1] == '\r')) vlen--;

            if (vlen > 0) {
                char *vbuf = strndup(val, vlen);

                size_t vblen = strlen(vbuf);
                if (vblen >= 2 && ((vbuf[0] == '"' && vbuf[vblen-1] == '"') ||
                                   (vbuf[0] == '\'' && vbuf[vblen-1] == '\''))) {
                    memmove(vbuf, vbuf + 1, vblen - 2);
                    vbuf[vblen - 2] = '\0';
                    vval_record_set(rec, current_key, vval_string_cstr(vbuf));
                } else {

                    char *endp;
                    long lv = strtol(vbuf, &endp, 10);
                    if (*endp == '\0' && endp != vbuf) {
                        vval_record_set(rec, current_key, vval_int(lv));
                    } else {
                        double dv = strtod(vbuf, &endp);
                        if (*endp == '\0' && endp != vbuf) {
                            vval_record_set(rec, current_key, vval_float(dv));
                        } else if (strcmp(vbuf, "true") == 0) {
                            vval_record_set(rec, current_key, vval_bool(true));
                        } else if (strcmp(vbuf, "false") == 0) {
                            vval_record_set(rec, current_key, vval_bool(false));
                        } else if (strcmp(vbuf, "null") == 0 || strcmp(vbuf, "~") == 0) {
                            vval_record_set(rec, current_key, vval_null());
                        } else {
                            vval_record_set(rec, current_key, vval_string_cstr(vbuf));
                        }
                    }
                }
                free(vbuf);
                current_key[0] = '\0';
            }

        }

        line = eol ? eol + 1 : line + llen;
    }

    if (current_list && current_key[0]) {
        vval_record_set(rec, current_key, current_list);
        vval_release(current_list);
    } else if (current_list) {

        vval_release(current_list);

    }

    return rec;
}

VexValue *builtin_detect_columns(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING)
        return vval_error("detect-columns: expected string input");

    const char *s = vstr_data(&input->string);
    VexValue *result = vval_list();

    const char *line = s;
    const char *eol = strchr(line, '\n');
    if (!eol) return vval_string_cstr(s);

    size_t hlen = (size_t)(eol - line);
    char *header = strndup(line, hlen);

    size_t col_count = 0;
    char *col_names[64];

    size_t i = 0;
    while (i < hlen) {
        while (i < hlen && (header[i] == ' ' || header[i] == '\t')) i++;
        if (i >= hlen) break;
        size_t start = i;
        while (i < hlen && header[i] != ' ' && header[i] != '\t') i++;
        col_names[col_count] = strndup(header + start, i - start);
        col_count++;
        if (col_count >= 64) break;
    }
    free(header);

    line = eol + 1;
    while (*line) {
        eol = strchr(line, '\n');
        size_t llen = eol ? (size_t)(eol - line) : strlen(line);
        if (llen == 0) { line = eol ? eol + 1 : line + llen; continue; }

        VexValue *rec = vval_record();

        size_t ci = 0;
        size_t pos = 0;
        while (pos < llen && ci < col_count) {
            while (pos < llen && (line[pos] == ' ' || line[pos] == '\t')) pos++;
            if (pos >= llen) break;
            size_t start = pos;

            if (ci == col_count - 1) {
                char *val = strndup(line + start, llen - start);

                size_t vl = strlen(val);
                while (vl > 0 && (val[vl-1] == ' ' || val[vl-1] == '\r')) val[--vl] = '\0';
                vval_record_set(rec, col_names[ci], vval_string_cstr(val));
                free(val);
                ci++;
            } else {
                while (pos < llen && line[pos] != ' ' && line[pos] != '\t') pos++;
                char *val = strndup(line + start, pos - start);
                vval_record_set(rec, col_names[ci], vval_string_cstr(val));
                free(val);
                ci++;
            }
        }
        vval_list_push(result, rec);
        vval_release(rec);
        line = eol ? eol + 1 : line + llen;
    }

    for (size_t c = 0; c < col_count; c++) free(col_names[c]);
    return result;
}

extern char **environ;

VexValue *builtin_env_keys(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    VexValue *result = vval_list();
    for (char **e = environ; *e; e++) {
        const char *eq = strchr(*e, '=');
        if (eq) {
            char *key = strndup(*e, (size_t)(eq - *e));
            vval_list_push(result, vval_string_cstr(key));
            free(key);
        }
    }
    return result;
}

VexValue *builtin_sys(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    VexValue *rec = vval_record();

    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        vval_record_set(rec, "hostname", vval_string_cstr(hostname));
    }

    struct utsname uts;
    if (uname(&uts) == 0) {
        vval_record_set(rec, "kernel", vval_string_cstr(uts.release));
        vval_record_set(rec, "arch", vval_string_cstr(uts.machine));
        vval_record_set(rec, "os", vval_string_cstr(uts.sysname));
    }

    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu > 0) vval_record_set(rec, "cpus", vval_int(ncpu));

#ifdef __APPLE__
    {
        int64_t memsize = 0;
        size_t mlen = sizeof(memsize);
        sysctlbyname("hw.memsize", &memsize, &mlen, NULL, 0);
        VexValue *mem = vval_record();
        vval_record_set(mem, "total", vval_int(memsize));

        mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
        vm_statistics64_data_t vmstat;
        if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                              (host_info64_t)&vmstat, &count) == KERN_SUCCESS) {
            int64_t page = (int64_t)vm_kernel_page_size;
            vval_record_set(mem, "free", vval_int((int64_t)vmstat.free_count * page));
            vval_record_set(mem, "available", vval_int((int64_t)(vmstat.free_count + vmstat.inactive_count) * page));
        }
        vval_record_set(rec, "memory", mem);
        vval_release(mem);

        struct timeval boottime;
        size_t bt_len = sizeof(boottime);
        int mib2[2] = { CTL_KERN, KERN_BOOTTIME };
        if (sysctl(mib2, 2, &boottime, &bt_len, NULL, 0) == 0)
            vval_record_set(rec, "uptime", vval_int((int64_t)(time(NULL) - boottime.tv_sec)));

        double loadavg[3];
        if (getloadavg(loadavg, 3) == 3) {
            vval_record_set(rec, "load_avg_1m", vval_float(loadavg[0]));
            vval_record_set(rec, "load_avg_5m", vval_float(loadavg[1]));
            vval_record_set(rec, "load_avg_15m", vval_float(loadavg[2]));
        }
    }
#else
    {
        struct sysinfo si;
        if (sysinfo(&si) == 0) {
            VexValue *mem = vval_record();
            vval_record_set(mem, "total", vval_int((int64_t)(si.totalram * si.mem_unit)));
            vval_record_set(mem, "free", vval_int((int64_t)(si.freeram * si.mem_unit)));
            vval_record_set(mem, "available", vval_int((int64_t)((si.freeram + si.bufferram) * si.mem_unit)));
            vval_record_set(mem, "swap_total", vval_int((int64_t)(si.totalswap * si.mem_unit)));
            vval_record_set(mem, "swap_free", vval_int((int64_t)(si.freeswap * si.mem_unit)));
            vval_record_set(rec, "memory", mem);
            vval_release(mem);

            vval_record_set(rec, "uptime", vval_int((int64_t)si.uptime));
            vval_record_set(rec, "load_avg_1m", vval_float(si.loads[0] / 65536.0));
            vval_record_set(rec, "load_avg_5m", vval_float(si.loads[1] / 65536.0));
            vval_record_set(rec, "load_avg_15m", vval_float(si.loads[2] / 65536.0));
        }
    }
#endif

    vval_record_set(rec, "pid", vval_int(getpid()));

    return rec;
}

VexValue *builtin_input_list(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    VexValue *list = NULL;
    const char *prompt_str = "Select: ";

    if (input && input->type == VEX_VAL_LIST && vval_list_len(input) > 0) {
        list = input;
    } else if (argc > 0 && args[0]->type == VEX_VAL_LIST) {
        list = args[0];
    }

    for (size_t i = 0; i < argc; i++) {
        if (args[i]->type == VEX_VAL_STRING &&
            strcmp(vstr_data(&args[i]->string), "-p") == 0 && i + 1 < argc) {
            prompt_str = vstr_data(&args[i + 1]->string);
            break;
        }
    }

    if (!list) {
        vex_err("input-list: expected a list");
        return vval_error("expected a list");
    }

    size_t count = vval_list_len(list);

    fprintf(stderr, "%s\n", prompt_str);
    for (size_t i = 0; i < count; i++) {
        VexValue *item = vval_list_get(list, i);
        VexStr s = vval_to_str(item);
        fprintf(stderr, "  %zu) %s\n", i + 1, vstr_data(&s));
        vstr_free(&s);
    }
    fprintf(stderr, "> ");
    fflush(stderr);

    char buf[64];
    if (!fgets(buf, sizeof(buf), stdin)) return vval_null();
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';

    char *endp;
    long choice = strtol(buf, &endp, 10);
    if (endp == buf || choice < 1 || (size_t)choice > count) return vval_null();

    return vval_retain(vval_list_get(list, (size_t)(choice - 1)));
}

VexValue *builtin_str_title_case(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return input ? vval_retain(input) : vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    char *buf = malloc(len + 1);
    bool word_start = true;
    for (size_t i = 0; i < len; i++) {
        if (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '-' || s[i] == '_') {
            buf[i] = s[i];
            word_start = true;
        } else if (word_start) {
            buf[i] = (char)toupper((unsigned char)s[i]);
            word_start = false;
        } else {
            buf[i] = (char)tolower((unsigned char)s[i]);
            word_start = false;
        }
    }
    buf[len] = '\0';
    VexValue *result = vval_string_cstr(buf);
    free(buf);
    return result;
}

VexValue *builtin_str_distance(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_STRING)
        return vval_error("str-distance: expected two strings");

    const char *a = vstr_data(&input->string);
    const char *b = vstr_data(&args[0]->string);
    size_t la = strlen(a), lb = strlen(b);

    size_t *prev = calloc(lb + 1, sizeof(size_t));
    size_t *curr = calloc(lb + 1, sizeof(size_t));

    for (size_t j = 0; j <= lb; j++) prev[j] = j;

    for (size_t i = 1; i <= la; i++) {
        curr[0] = i;
        for (size_t j = 1; j <= lb; j++) {
            size_t cost = (a[i-1] == b[j-1]) ? 0 : 1;
            size_t del = prev[j] + 1;
            size_t ins = curr[j-1] + 1;
            size_t sub = prev[j-1] + cost;
            curr[j] = del < ins ? (del < sub ? del : sub) : (ins < sub ? ins : sub);
        }
        size_t *tmp = prev;
        prev = curr;
        curr = tmp;
    }
    int64_t dist = (int64_t)prev[lb];
    free(prev);
    free(curr);
    return vval_int(dist);
}

VexValue *builtin_split_row(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING)
        return input ? vval_retain(input) : vval_null();

    const char *sep = "\n";
    if (argc > 0 && args[0]->type == VEX_VAL_STRING) {
        sep = vstr_data(&args[0]->string);
    }

    const char *s = vstr_data(&input->string);
    size_t sep_len = strlen(sep);
    VexValue *result = vval_list();

    if (sep_len == 0) {

        for (size_t i = 0; s[i]; i++) {
            char c[2] = { s[i], '\0' };
            vval_list_push(result, vval_string_cstr(c));
        }
        return result;
    }

    const char *start = s;
    const char *found;
    while ((found = strstr(start, sep)) != NULL) {
        char *part = strndup(start, (size_t)(found - start));
        vval_list_push(result, vval_string_cstr(part));
        free(part);
        start = found + sep_len;
    }
    vval_list_push(result, vval_string_cstr(start));
    return result;
}

VexValue *builtin_seq_date(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;

    if (argc < 2 || args[0]->type != VEX_VAL_STRING || args[1]->type != VEX_VAL_STRING) {
        vex_err("seq-date: usage: seq-date <start> <end> [step-days]");
        return vval_error("missing arguments");
    }

    int step_days = 1;
    if (argc > 2 && args[2]->type == VEX_VAL_INT) step_days = (int)args[2]->integer;
    if (step_days == 0) step_days = 1;

    struct tm start_tm = {0}, end_tm = {0};
    const char *s1 = vstr_data(&args[0]->string);
    const char *s2 = vstr_data(&args[1]->string);

    if (sscanf(s1, "%d-%d-%d", &start_tm.tm_year, &start_tm.tm_mon, &start_tm.tm_mday) != 3 ||
        sscanf(s2, "%d-%d-%d", &end_tm.tm_year, &end_tm.tm_mon, &end_tm.tm_mday) != 3) {
        return vval_error("seq-date: expected YYYY-MM-DD format");
    }
    start_tm.tm_year -= 1900; start_tm.tm_mon -= 1;
    end_tm.tm_year -= 1900; end_tm.tm_mon -= 1;

    time_t start_t = mktime(&start_tm);
    time_t end_t = mktime(&end_tm);

    VexValue *result = vval_list();
    time_t cur = start_t;
    int direction = step_days > 0 ? 1 : -1;

    while ((direction > 0 && cur <= end_t) || (direction < 0 && cur >= end_t)) {
        struct tm *tm = localtime(&cur);
        char buf[16];
        strftime(buf, sizeof(buf), "%Y-%m-%d", tm);
        vval_list_push(result, vval_string_cstr(buf));
        cur += (time_t)(step_days * 86400);

        if (vval_list_len(result) >= 10000) break;
    }
    return result;
}

VexValue *builtin_math_mod(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || argc < 1) return vval_error("math-mod: expected value | math-mod <divisor>");
    if (input->type == VEX_VAL_INT && args[0]->type == VEX_VAL_INT) {
        if (args[0]->integer == 0) return vval_error("math-mod: division by zero");
        return vval_int(input->integer % args[0]->integer);
    }
    double a, b;
    if (input->type == VEX_VAL_INT) a = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) a = input->floating;
    else return vval_error("math-mod: expected number");
    if (args[0]->type == VEX_VAL_INT) b = (double)args[0]->integer;
    else if (args[0]->type == VEX_VAL_FLOAT) b = args[0]->floating;
    else return vval_error("math-mod: divisor must be number");
    if (b == 0.0) return vval_error("math-mod: division by zero");
    return vval_float(fmod(a, b));
}

VexValue *builtin_math_exp(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    double v;
    if (input->type == VEX_VAL_INT) v = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) v = input->floating;
    else return vval_error("math-exp: expected number");
    return vval_float(exp(v));
}

VexValue *builtin_math_ln(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    double v;
    if (input->type == VEX_VAL_INT) v = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) v = input->floating;
    else return vval_error("math-ln: expected number");
    if (v <= 0) return vval_error("math-ln: non-positive input");
    return vval_float(log(v));
}

VexValue *builtin_str_starts_with_any(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_LIST)
        return vval_bool(false);
    const char *s = vstr_data(&input->string);
    for (size_t i = 0; i < args[0]->list.len; i++) {
        VexValue *prefix = args[0]->list.data[i];
        if (prefix->type == VEX_VAL_STRING) {
            const char *p = vstr_data(&prefix->string);
            if (strncmp(s, p, vstr_len(&prefix->string)) == 0)
                return vval_bool(true);
        }
    }
    return vval_bool(false);
}

VexValue *builtin_str_ends_with_any(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_LIST)
        return vval_bool(false);
    const char *s = vstr_data(&input->string);
    size_t slen = vstr_len(&input->string);
    for (size_t i = 0; i < args[0]->list.len; i++) {
        VexValue *suffix = args[0]->list.data[i];
        if (suffix->type == VEX_VAL_STRING) {
            size_t plen = vstr_len(&suffix->string);
            if (plen <= slen && memcmp(s + slen - plen, vstr_data(&suffix->string), plen) == 0)
                return vval_bool(true);
        }
    }
    return vval_bool(false);
}

VexValue *builtin_collect(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;

    if (input && input->type == VEX_VAL_LIST) {
        bool all_strings = true;
        for (size_t i = 0; i < vval_list_len(input); i++) {
            if (vval_list_get(input, i)->type != VEX_VAL_STRING) { all_strings = false; break; }
        }
        if (all_strings) {
            VexStr out = vstr_new("");
            for (size_t i = 0; i < vval_list_len(input); i++) {
                if (i > 0) vstr_append_char(&out, '\n');
                vstr_append_str(&out, &vval_list_get(input, i)->string);
            }
            VexValue *result = vval_string_cstr(vstr_data(&out));
            vstr_free(&out);
            return result;
        }
        return vval_retain(input);
    }
    return input ? vval_retain(input) : vval_null();
}

VexValue *builtin_zip_with(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST || argc < 2 ||
        args[0]->type != VEX_VAL_LIST || args[1]->type != VEX_VAL_CLOSURE)
        return vval_error("zip-with: expected list | zip-with <list> <closure>");

    VexValue *other = args[0];
    size_t len = input->list.len < other->list.len ? input->list.len : other->list.len;
    VexValue *result = vval_list();

    for (size_t i = 0; i < len; i++) {
        VexValue *ca[2] = { input->list.data[i], other->list.data[i] };
        VexValue *v = eval_call_closure(ctx, args[1], ca, 2);
        vval_list_push(result, v);
        vval_release(v);
    }
    return result;
}

VexValue *builtin_from_xml(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING)
        return vval_error("from-xml: expected string input");

    const char *s = vstr_data(&input->string);
    VexValue *rec = vval_record();

    while (*s) {

        while (*s && (*s == ' ' || *s == '\n' || *s == '\r' || *s == '\t')) s++;
        if (!*s) break;

        if (strncmp(s, "<?", 2) == 0) {
            s = strstr(s, "?>");
            if (s) s += 2; else break;
            continue;
        }
        if (strncmp(s, "<!--", 4) == 0) {
            s = strstr(s, "-->");
            if (s) s += 3; else break;
            continue;
        }

        if (*s == '<' && s[1] != '/') {
            s++;
            const char *tag_start = s;
            while (*s && *s != '>' && *s != ' ' && *s != '/') s++;
            char *tag = strndup(tag_start, (size_t)(s - tag_start));

            while (*s && *s != '>' && *s != '/') s++;

            if (*s == '/') {
                s++;
                if (*s == '>') s++;
                vval_record_set(rec, tag, vval_null());
                free(tag);
                continue;
            }
            if (*s == '>') s++;

            char close_tag[512];
            snprintf(close_tag, sizeof(close_tag), "</%s>", tag);
            const char *close = strstr(s, close_tag);
            if (close) {

                const char *inner_tag = memchr(s, '<', (size_t)(close - s));
                if (inner_tag && inner_tag[1] != '/') {

                    char *inner = strndup(s, (size_t)(close - s));
                    VexValue *inner_str = vval_string_cstr(inner);
                    free(inner);
                    VexValue *child_args[1] = { inner_str };
                    (void)child_args;
                    VexValue *child = builtin_from_xml(ctx, inner_str, NULL, 0);
                    vval_record_set(rec, tag, child);
                    vval_release(child);
                    vval_release(inner_str);
                } else {

                    char *val = strndup(s, (size_t)(close - s));

                    size_t vlen = strlen(val);
                    while (vlen > 0 && (val[vlen-1] == ' ' || val[vlen-1] == '\n' || val[vlen-1] == '\r')) val[--vlen] = '\0';
                    const char *vstart = val;
                    while (*vstart == ' ' || *vstart == '\n' || *vstart == '\r') vstart++;

                    char *endp;
                    long lv = strtol(vstart, &endp, 10);
                    if (*endp == '\0' && endp != vstart) {
                        vval_record_set(rec, tag, vval_int(lv));
                    } else {
                        vval_record_set(rec, tag, vval_string_cstr(vstart));
                    }
                    free(val);
                }
                s = close + strlen(close_tag);
            }
            free(tag);
        } else {
            s++;
        }
    }
    return rec;
}

static void xml_escape(VexStr *out, const char *s) {
    for (; *s; s++) {
        switch (*s) {
        case '<': vstr_append_cstr(out, "&lt;"); break;
        case '>': vstr_append_cstr(out, "&gt;"); break;
        case '&': vstr_append_cstr(out, "&amp;"); break;
        case '"': vstr_append_cstr(out, "&quot;"); break;
        default: vstr_append_char(out, *s); break;
        }
    }
}

static void xml_serialize_value(VexStr *out, const char *tag, VexValue *val, int indent) {
    for (int i = 0; i < indent; i++) vstr_append_cstr(out, "  ");

    if (!val || val->type == VEX_VAL_NULL) {
        vstr_append_cstr(out, "<");
        vstr_append_cstr(out, tag);
        vstr_append_cstr(out, "/>\n");
        return;
    }

    vstr_append_cstr(out, "<");
    vstr_append_cstr(out, tag);
    vstr_append_cstr(out, ">");

    if (val->type == VEX_VAL_RECORD) {
        vstr_append_char(out, '\n');
        VexMapIter it = vmap_iter(&val->record);
        const char *k;
        void *v;
        while (vmap_next(&it, &k, &v)) {
            xml_serialize_value(out, k, (VexValue *)v, indent + 1);
        }
        for (int i = 0; i < indent; i++) vstr_append_cstr(out, "  ");
    } else if (val->type == VEX_VAL_LIST) {
        vstr_append_char(out, '\n');
        for (size_t i = 0; i < val->list.len; i++) {
            xml_serialize_value(out, "item", val->list.data[i], indent + 1);
        }
        for (int i = 0; i < indent; i++) vstr_append_cstr(out, "  ");
    } else {
        VexStr s = vval_to_str(val);
        xml_escape(out, vstr_data(&s));
        vstr_free(&s);
    }

    vstr_append_cstr(out, "</");
    vstr_append_cstr(out, tag);
    vstr_append_cstr(out, ">\n");
}

VexValue *builtin_to_xml(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();

    VexStr out = vstr_new("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");

    if (input->type == VEX_VAL_RECORD) {
        vstr_append_cstr(&out, "<root>\n");
        VexMapIter it = vmap_iter(&input->record);
        const char *k;
        void *v;
        while (vmap_next(&it, &k, &v)) {
            xml_serialize_value(&out, k, (VexValue *)v, 1);
        }
        vstr_append_cstr(&out, "</root>\n");
    } else {
        xml_serialize_value(&out, "root", input, 0);
    }

    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_path_exists(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    const char *path = NULL;
    if (argc > 0 && args[0]->type == VEX_VAL_STRING) {
        path = vstr_data(&args[0]->string);
    } else if (input && input->type == VEX_VAL_STRING) {
        path = vstr_data(&input->string);
    }
    if (!path) return vval_bool(false);
    struct stat st;
    return vval_bool(stat(path, &st) == 0);
}

VexValue *builtin_path_type(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    const char *path = NULL;
    if (argc > 0 && args[0]->type == VEX_VAL_STRING) {
        path = vstr_data(&args[0]->string);
    } else if (input && input->type == VEX_VAL_STRING) {
        path = vstr_data(&input->string);
    }
    if (!path) return vval_null();

    struct stat st;
    if (lstat(path, &st) != 0) return vval_null();

    if (S_ISREG(st.st_mode)) return vval_string_cstr("file");
    if (S_ISDIR(st.st_mode)) return vval_string_cstr("dir");
    if (S_ISLNK(st.st_mode)) return vval_string_cstr("symlink");
    if (S_ISFIFO(st.st_mode)) return vval_string_cstr("fifo");
    if (S_ISSOCK(st.st_mode)) return vval_string_cstr("socket");
    if (S_ISBLK(st.st_mode)) return vval_string_cstr("block");
    if (S_ISCHR(st.st_mode)) return vval_string_cstr("char");
    return vval_string_cstr("unknown");
}

VexValue *builtin_generate(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;

    if (argc < 2 || args[1]->type != VEX_VAL_CLOSURE) {
        vex_err("generate: usage: generate <initial> <closure>");
        return vval_error("missing arguments");
    }

    VexValue *result = vval_list();
    VexValue *state = vval_retain(args[0]);

    for (size_t limit = 0; limit < 100000; limit++) {
        VexValue *ca[1] = { state };
        VexValue *step = eval_call_closure(ctx, args[1], ca, 1);

        if (!step || step->type == VEX_VAL_NULL) {
            if (step) vval_release(step);
            break;
        }

        if (step->type == VEX_VAL_RECORD) {
            VexValue *out = vval_record_get(step, "out");
            VexValue *next = vval_record_get(step, "next");
            if (out) vval_list_push(result, out);
            vval_release(state);
            state = next ? vval_retain(next) : vval_null();
            vval_release(step);
            if (!next) break;
        } else {

            vval_list_push(result, step);
            vval_release(state);
            state = vval_retain(step);
            vval_release(step);
        }
    }
    vval_release(state);
    return result;
}

VexValue *builtin_math_asin(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    double v;
    if (input->type == VEX_VAL_INT) v = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) v = input->floating;
    else return vval_error("math-asin: expected number");
    if (v < -1.0 || v > 1.0) return vval_error("math-asin: out of range [-1, 1]");
    return vval_float(asin(v));
}

VexValue *builtin_math_acos(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    double v;
    if (input->type == VEX_VAL_INT) v = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) v = input->floating;
    else return vval_error("math-acos: expected number");
    if (v < -1.0 || v > 1.0) return vval_error("math-acos: out of range [-1, 1]");
    return vval_float(acos(v));
}

VexValue *builtin_math_atan(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    double v;
    if (input->type == VEX_VAL_INT) v = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) v = input->floating;
    else return vval_error("math-atan: expected number");
    return vval_float(atan(v));
}

VexValue *builtin_math_atan2(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || argc < 1) return vval_error("math-atan2: expected y | math-atan2 <x>");
    double y, x;
    if (input->type == VEX_VAL_INT) y = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) y = input->floating;
    else return vval_error("math-atan2: y must be number");
    if (args[0]->type == VEX_VAL_INT) x = (double)args[0]->integer;
    else if (args[0]->type == VEX_VAL_FLOAT) x = args[0]->floating;
    else return vval_error("math-atan2: x must be number");
    return vval_float(atan2(y, x));
}

VexValue *builtin_str_center(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_INT)
        return input ? vval_retain(input) : vval_null();

    int64_t width = args[0]->integer;
    char fill = ' ';
    if (argc > 1 && args[1]->type == VEX_VAL_STRING && vstr_len(&args[1]->string) > 0)
        fill = vstr_data(&args[1]->string)[0];

    size_t len = vstr_len(&input->string);
    if ((int64_t)len >= width) return vval_retain(input);

    int64_t total_pad = width - (int64_t)len;
    int64_t left_pad = total_pad / 2;
    int64_t right_pad = total_pad - left_pad;

    VexStr out = vstr_new("");
    for (int64_t i = 0; i < left_pad; i++) vstr_append_char(&out, fill);
    vstr_append_str(&out, &input->string);
    for (int64_t i = 0; i < right_pad; i++) vstr_append_char(&out, fill);

    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_str_remove(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_STRING)
        return input ? vval_retain(input) : vval_null();

    const char *s = vstr_data(&input->string);
    const char *needle = vstr_data(&args[0]->string);
    size_t nlen = vstr_len(&args[0]->string);
    if (nlen == 0) return vval_retain(input);

    VexStr out = vstr_new("");
    const char *p = s;
    const char *found;
    while ((found = strstr(p, needle)) != NULL) {

        for (const char *c = p; c < found; c++) vstr_append_char(&out, *c);
        p = found + nlen;
    }
    vstr_append_cstr(&out, p);

    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_group_by_fn(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST || argc < 1 || args[0]->type != VEX_VAL_CLOSURE)
        return vval_error("group-by-fn: expected list | group-by-fn <closure>");

    VexValue *rec = vval_record();

    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *item = vval_list_get(input, i);
        VexValue *ca[1] = { item };
        VexValue *key = eval_call_closure(ctx, args[0], ca, 1);
        VexStr ks = vval_to_str(key);

        VexValue *group = vval_record_get(rec, vstr_data(&ks));
        if (!group) {
            group = vval_list();
            vval_list_push(group, item);
            vval_record_set(rec, vstr_data(&ks), group);
            vval_release(group);
        } else {
            vval_list_push(group, item);
        }

        vstr_free(&ks);
        vval_release(key);
    }
    return rec;
}

VexValue *builtin_scan(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST || argc < 2 || args[1]->type != VEX_VAL_CLOSURE)
        return vval_error("scan: expected list | scan <init> <closure>");

    VexValue *result = vval_list();
    VexValue *acc = vval_retain(args[0]);
    vval_list_push(result, acc);

    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *ca[2] = { acc, vval_list_get(input, i) };
        VexValue *next = eval_call_closure(ctx, args[1], ca, 2);
        vval_list_push(result, next);
        vval_release(acc);
        acc = next;
    }
    vval_release(acc);
    return result;
}

VexValue *builtin_chunks_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST || argc < 1 || args[0]->type != VEX_VAL_CLOSURE)
        return vval_error("chunks-by: expected list | chunks-by <closure>");

    VexValue *result = vval_list();
    VexValue *current_chunk = vval_list();

    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *item = vval_list_get(input, i);

        if (i > 0) {
            VexValue *prev = vval_list_get(input, i - 1);
            VexValue *ca[2] = { prev, item };
            VexValue *same = eval_call_closure(ctx, args[0], ca, 2);
            bool group = vval_truthy(same);
            vval_release(same);

            if (!group) {
                vval_list_push(result, current_chunk);
                vval_release(current_chunk);
                current_chunk = vval_list();
            }
        }
        vval_list_push(current_chunk, item);
    }

    if (vval_list_len(current_chunk) > 0) {
        vval_list_push(result, current_chunk);
    }
    vval_release(current_chunk);
    return result;
}

VexValue *builtin_path_dirname(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    const char *path = NULL;
    if (input && input->type == VEX_VAL_STRING) path = vstr_data(&input->string);
    else if (argc > 0 && args[0]->type == VEX_VAL_STRING) path = vstr_data(&args[0]->string);
    if (!path) return vval_null();

    char *tmp = strdup(path);
    char *dir = dirname(tmp);
    VexValue *result = vval_string_cstr(dir);
    free(tmp);
    return result;
}

VexValue *builtin_path_basename_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    const char *path = NULL;
    if (input && input->type == VEX_VAL_STRING) path = vstr_data(&input->string);
    else if (argc > 0 && args[0]->type == VEX_VAL_STRING) path = vstr_data(&args[0]->string);
    if (!path) return vval_null();

    char *tmp = strdup(path);
    char *base = basename(tmp);
    VexValue *result = vval_string_cstr(base);
    free(tmp);
    return result;
}

VexValue *builtin_path_ext(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    const char *path = NULL;
    if (input && input->type == VEX_VAL_STRING) path = vstr_data(&input->string);
    else if (argc > 0 && args[0]->type == VEX_VAL_STRING) path = vstr_data(&args[0]->string);
    if (!path) return vval_null();

    const char *dot = strrchr(path, '.');
    const char *slash = strrchr(path, '/');
    if (dot && (!slash || dot > slash)) {
        return vval_string_cstr(dot + 1);
    }
    return vval_string_cstr("");
}

static void html_escape(VexStr *out, const char *s) {
    for (; *s; s++) {
        switch (*s) {
        case '<': vstr_append_cstr(out, "&lt;"); break;
        case '>': vstr_append_cstr(out, "&gt;"); break;
        case '&': vstr_append_cstr(out, "&amp;"); break;
        case '"': vstr_append_cstr(out, "&quot;"); break;
        default: vstr_append_char(out, *s); break;
        }
    }
}

VexValue *builtin_to_html(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();

    VexStr out = vstr_new("");

    if (input->type == VEX_VAL_LIST && vval_list_len(input) > 0 &&
        vval_list_get(input, 0)->type == VEX_VAL_RECORD) {

        vstr_append_cstr(&out, "<table>\n<thead>\n<tr>\n");

        VexValue *first = vval_list_get(input, 0);
        VexMapIter it = vmap_iter(&first->record);
        const char *k;
        void *v;

        const char *keys[128];
        size_t nkeys = 0;
        while (vmap_next(&it, &k, &v) && nkeys < 128) {
            keys[nkeys++] = k;
            vstr_append_cstr(&out, "  <th>");
            html_escape(&out, k);
            vstr_append_cstr(&out, "</th>\n");
        }
        vstr_append_cstr(&out, "</tr>\n</thead>\n<tbody>\n");

        for (size_t i = 0; i < vval_list_len(input); i++) {
            VexValue *row = vval_list_get(input, i);
            vstr_append_cstr(&out, "<tr>\n");
            for (size_t j = 0; j < nkeys; j++) {
                VexValue *cell = (row->type == VEX_VAL_RECORD) ? vval_record_get(row, keys[j]) : NULL;
                vstr_append_cstr(&out, "  <td>");
                if (cell) {
                    VexStr cs = vval_to_str(cell);
                    html_escape(&out, vstr_data(&cs));
                    vstr_free(&cs);
                }
                vstr_append_cstr(&out, "</td>\n");
            }
            vstr_append_cstr(&out, "</tr>\n");
        }
        vstr_append_cstr(&out, "</tbody>\n</table>");
    } else if (input->type == VEX_VAL_RECORD) {

        vstr_append_cstr(&out, "<dl>\n");
        VexMapIter it = vmap_iter(&input->record);
        const char *k2;
        void *v2;
        while (vmap_next(&it, &k2, &v2)) {
            vstr_append_cstr(&out, "  <dt>");
            html_escape(&out, k2);
            vstr_append_cstr(&out, "</dt>\n  <dd>");
            VexStr vs = vval_to_str((VexValue *)v2);
            html_escape(&out, vstr_data(&vs));
            vstr_free(&vs);
            vstr_append_cstr(&out, "</dd>\n");
        }
        vstr_append_cstr(&out, "</dl>");
    } else {
        VexStr vs = vval_to_str(input);
        html_escape(&out, vstr_data(&vs));
        vstr_free(&vs);
    }

    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_sleep_ms(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    int64_t ms = 0;
    if (argc > 0 && args[0]->type == VEX_VAL_INT) ms = args[0]->integer;
    else if (input && input->type == VEX_VAL_INT) ms = input->integer;
    if (ms <= 0) return vval_null();

    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
    return vval_null();
}

VexValue *builtin_is_admin(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    return vval_bool(geteuid() == 0);
}

static int64_t gcd(int64_t a, int64_t b) {
    if (a < 0) a = -a;
    if (b < 0) b = -b;
    while (b) { int64_t t = b; b = a % b; a = t; }
    return a;
}

VexValue *builtin_math_gcd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;

    if (input && input->type == VEX_VAL_LIST) {
        if (vval_list_len(input) == 0) return vval_int(0);
        VexValue *first = vval_list_get(input, 0);
        if (first->type != VEX_VAL_INT) return vval_error("math-gcd: expected integers");
        int64_t result = first->integer;
        for (size_t i = 1; i < vval_list_len(input); i++) {
            VexValue *v = vval_list_get(input, i);
            if (v->type != VEX_VAL_INT) return vval_error("math-gcd: expected integers");
            result = gcd(result, v->integer);
        }
        return vval_int(result);
    }
    if (input && input->type == VEX_VAL_INT && argc > 0 && args[0]->type == VEX_VAL_INT) {
        return vval_int(gcd(input->integer, args[0]->integer));
    }
    return vval_error("math-gcd: expected integers");
}

VexValue *builtin_math_lcm(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (input && input->type == VEX_VAL_LIST) {
        if (vval_list_len(input) == 0) return vval_int(0);
        VexValue *first = vval_list_get(input, 0);
        if (first->type != VEX_VAL_INT) return vval_error("math-lcm: expected integers");
        int64_t result = first->integer;
        for (size_t i = 1; i < vval_list_len(input); i++) {
            VexValue *v = vval_list_get(input, i);
            if (v->type != VEX_VAL_INT) return vval_error("math-lcm: expected integers");
            int64_t g = gcd(result, v->integer);
            if (g == 0) return vval_int(0);
            result = (result / g) * v->integer;
        }
        return vval_int(result < 0 ? -result : result);
    }
    if (input && input->type == VEX_VAL_INT && argc > 0 && args[0]->type == VEX_VAL_INT) {
        int64_t g = gcd(input->integer, args[0]->integer);
        if (g == 0) return vval_int(0);
        int64_t r = (input->integer / g) * args[0]->integer;
        return vval_int(r < 0 ? -r : r);
    }
    return vval_error("math-lcm: expected integers");
}

VexValue *builtin_math_clamp(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || argc < 2) return vval_error("math-clamp: expected value | math-clamp <min> <max>");

    double v, lo, hi;
    if (input->type == VEX_VAL_INT) v = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) v = input->floating;
    else return vval_error("math-clamp: expected number");

    if (args[0]->type == VEX_VAL_INT) lo = (double)args[0]->integer;
    else if (args[0]->type == VEX_VAL_FLOAT) lo = args[0]->floating;
    else return vval_error("math-clamp: min must be number");

    if (args[1]->type == VEX_VAL_INT) hi = (double)args[1]->integer;
    else if (args[1]->type == VEX_VAL_FLOAT) hi = args[1]->floating;
    else return vval_error("math-clamp: max must be number");

    double result = v < lo ? lo : (v > hi ? hi : v);
    if (input->type == VEX_VAL_INT && args[0]->type == VEX_VAL_INT && args[1]->type == VEX_VAL_INT)
        return vval_int((int64_t)result);
    return vval_float(result);
}

VexValue *builtin_str_wrap(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_INT)
        return input ? vval_retain(input) : vval_null();

    int64_t width = args[0]->integer;
    if (width <= 0) return vval_retain(input);

    const char *s = vstr_data(&input->string);
    VexStr out = vstr_new("");
    int64_t col = 0;
    const char *word_start = s;

    while (*s) {

        if (*s == ' ' || *s == '\t') {
            if (col > 0) { vstr_append_char(&out, ' '); col++; }
            s++;
            continue;
        }
        if (*s == '\n') {
            vstr_append_char(&out, '\n');
            col = 0;
            s++;
            continue;
        }

        word_start = s;
        while (*s && *s != ' ' && *s != '\t' && *s != '\n') s++;
        size_t wlen = (size_t)(s - word_start);

        if (col > 0 && col + (int64_t)wlen > width) {
            vstr_append_char(&out, '\n');
            col = 0;
        }
        for (size_t i = 0; i < wlen; i++) vstr_append_char(&out, word_start[i]);
        col += (int64_t)wlen;
    }

    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_str_similarity(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_STRING)
        return vval_error("str-similarity: expected two strings");

    const char *a = vstr_data(&input->string);
    const char *b = vstr_data(&args[0]->string);
    size_t la = strlen(a), lb = strlen(b);

    if (la == 0 && lb == 0) return vval_float(1.0);
    if (la == 0 || lb == 0) return vval_float(0.0);

    size_t *prev = calloc(lb + 1, sizeof(size_t));
    size_t *curr = calloc(lb + 1, sizeof(size_t));
    for (size_t j = 0; j <= lb; j++) prev[j] = j;
    for (size_t i = 1; i <= la; i++) {
        curr[0] = i;
        for (size_t j = 1; j <= lb; j++) {
            size_t cost = (a[i-1] == b[j-1]) ? 0 : 1;
            size_t del = prev[j] + 1;
            size_t ins = curr[j-1] + 1;
            size_t sub = prev[j-1] + cost;
            curr[j] = del < ins ? (del < sub ? del : sub) : (ins < sub ? ins : sub);
        }
        size_t *tmp = prev; prev = curr; curr = tmp;
    }
    size_t dist = prev[lb];
    free(prev); free(curr);

    size_t maxlen = la > lb ? la : lb;
    return vval_float(1.0 - (double)dist / (double)maxlen);
}

VexValue *builtin_pairwise(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST || vval_list_len(input) < 2)
        return vval_list();

    VexValue *result = vval_list();
    for (size_t i = 0; i + 1 < vval_list_len(input); i++) {
        VexValue *pair = vval_list();
        vval_list_push(pair, vval_list_get(input, i));
        vval_list_push(pair, vval_list_get(input, i + 1));
        vval_list_push(result, pair);
        vval_release(pair);
    }
    return result;
}

VexValue *builtin_cartesian(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST || argc < 1 || args[0]->type != VEX_VAL_LIST)
        return vval_error("cartesian: expected list | cartesian <list>");

    VexValue *result = vval_list();
    for (size_t i = 0; i < vval_list_len(input); i++) {
        for (size_t j = 0; j < vval_list_len(args[0]); j++) {
            VexValue *pair = vval_list();
            vval_list_push(pair, vval_list_get(input, i));
            vval_list_push(pair, vval_list_get(args[0], j));
            vval_list_push(result, pair);
            vval_release(pair);
        }
    }
    return result;
}

VexValue *builtin_from_ssv(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING)
        return vval_error("from-ssv: expected string input");

    return builtin_detect_columns(ctx, input, args, argc);
}

VexValue *builtin_to_text_table(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST || vval_list_len(input) == 0)
        return input ? vval_retain(input) : vval_null();

    VexValue *first = vval_list_get(input, 0);
    if (first->type != VEX_VAL_RECORD) return vval_retain(input);

    const char *cols[128];
    size_t ncols = 0;
    VexMapIter it = vmap_iter(&first->record);
    const char *k;
    void *v;
    while (vmap_next(&it, &k, &v) && ncols < 128) {
        cols[ncols++] = k;
    }

    size_t widths[128];
    for (size_t c = 0; c < ncols; c++) widths[c] = strlen(cols[c]);

    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *row = vval_list_get(input, i);
        if (row->type != VEX_VAL_RECORD) continue;
        for (size_t c = 0; c < ncols; c++) {
            VexValue *cell = vval_record_get(row, cols[c]);
            if (cell) {
                VexStr cs = vval_to_str(cell);
                size_t clen = vstr_len(&cs);
                if (clen > widths[c]) widths[c] = clen;
                vstr_free(&cs);
            }
        }
    }

    VexStr out = vstr_new("");

    for (size_t c = 0; c < ncols; c++) {
        if (c > 0) vstr_append_cstr(&out, "  ");
        size_t klen = strlen(cols[c]);
        vstr_append_cstr(&out, cols[c]);
        for (size_t p = klen; p < widths[c]; p++) vstr_append_char(&out, ' ');
    }
    vstr_append_char(&out, '\n');

    for (size_t c = 0; c < ncols; c++) {
        if (c > 0) vstr_append_cstr(&out, "  ");
        for (size_t p = 0; p < widths[c]; p++) vstr_append_char(&out, '-');
    }
    vstr_append_char(&out, '\n');

    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *row = vval_list_get(input, i);
        for (size_t c = 0; c < ncols; c++) {
            if (c > 0) vstr_append_cstr(&out, "  ");
            VexValue *cell = (row->type == VEX_VAL_RECORD) ? vval_record_get(row, cols[c]) : NULL;
            VexStr cs = cell ? vval_to_str(cell) : vstr_new("");
            size_t clen = vstr_len(&cs);
            vstr_append_str(&out, &cs);
            for (size_t p = clen; p < widths[c]; p++) vstr_append_char(&out, ' ');
            vstr_free(&cs);
        }
        vstr_append_char(&out, '\n');
    }

    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_path_stem(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    const char *path = NULL;
    if (input && input->type == VEX_VAL_STRING) path = vstr_data(&input->string);
    else if (argc > 0 && args[0]->type == VEX_VAL_STRING) path = vstr_data(&args[0]->string);
    if (!path) return vval_null();

    char *tmp = strdup(path);
    char *base = basename(tmp);

    char *dot = strrchr(base, '.');
    if (dot && dot != base) *dot = '\0';

    VexValue *result = vval_string_cstr(base);
    free(tmp);
    return result;
}

VexValue *builtin_path_rel(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_STRING)
        return input ? vval_retain(input) : vval_null();

    const char *path = vstr_data(&input->string);
    const char *base = vstr_data(&args[0]->string);

    size_t blen = strlen(base);
    if (strncmp(path, base, blen) == 0) {
        const char *rel = path + blen;
        while (*rel == '/') rel++;
        return vval_string_cstr(*rel ? rel : ".");
    }
    return vval_retain(input);
}

VexValue *builtin_count_by(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST || argc < 1 || args[0]->type != VEX_VAL_CLOSURE)
        return vval_int(0);

    int64_t count = 0;
    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *item = vval_list_get(input, i);
        VexValue *ca[1] = { item };
        VexValue *r = eval_call_closure(ctx, args[0], ca, 1);
        if (vval_truthy(r)) count++;
        vval_release(r);
    }
    return vval_int(count);
}

VexValue *builtin_repeat_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (argc < 1 || args[0]->type != VEX_VAL_INT)
        return vval_error("repeat: expected count");

    int64_t n = args[0]->integer;
    if (n <= 0) return vval_list();

    VexValue *val = (input && input->type != VEX_VAL_NULL) ? input : vval_null();
    VexValue *result = vval_list();
    for (int64_t i = 0; i < n && i < 1000000; i++) {
        vval_list_push(result, val);
    }
    return result;
}

VexValue *builtin_bits_and(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_INT || argc < 1 || args[0]->type != VEX_VAL_INT)
        return vval_error("bits-and: expected integers");
    return vval_int(input->integer & args[0]->integer);
}

VexValue *builtin_bits_or(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_INT || argc < 1 || args[0]->type != VEX_VAL_INT)
        return vval_error("bits-or: expected integers");
    return vval_int(input->integer | args[0]->integer);
}

VexValue *builtin_bits_xor(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_INT || argc < 1 || args[0]->type != VEX_VAL_INT)
        return vval_error("bits-xor: expected integers");
    return vval_int(input->integer ^ args[0]->integer);
}

VexValue *builtin_bits_not(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_INT)
        return vval_error("bits-not: expected integer");
    return vval_int(~input->integer);
}

VexValue *builtin_bits_shl(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_INT || argc < 1 || args[0]->type != VEX_VAL_INT)
        return vval_error("bits-shl: expected integers");
    int64_t shift = args[0]->integer;
    if (shift < 0 || shift > 63) return vval_error("bits-shl: shift out of range");
    return vval_int(input->integer << shift);
}

VexValue *builtin_bits_shr(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_INT || argc < 1 || args[0]->type != VEX_VAL_INT)
        return vval_error("bits-shr: expected integers");
    int64_t shift = args[0]->integer;
    if (shift < 0 || shift > 63) return vval_error("bits-shr: shift out of range");
    return vval_int((int64_t)((uint64_t)input->integer >> shift));
}

VexValue *builtin_into_filesize(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_INT)
        return vval_error("into-filesize: expected integer (bytes)");

    int64_t bytes = input->integer;
    char buf[64];
    double val;

    if (bytes < 0) {
        snprintf(buf, sizeof(buf), "%lld B", (long long)bytes);
    } else if (bytes < 1024) {
        snprintf(buf, sizeof(buf), "%lld B", (long long)bytes);
    } else if (bytes < 1024LL * 1024) {
        val = (double)bytes / 1024.0;
        snprintf(buf, sizeof(buf), "%.1f KiB", val);
    } else if (bytes < 1024LL * 1024 * 1024) {
        val = (double)bytes / (1024.0 * 1024.0);
        snprintf(buf, sizeof(buf), "%.1f MiB", val);
    } else if (bytes < 1024LL * 1024 * 1024 * 1024) {
        val = (double)bytes / (1024.0 * 1024.0 * 1024.0);
        snprintf(buf, sizeof(buf), "%.2f GiB", val);
    } else {
        val = (double)bytes / (1024.0 * 1024.0 * 1024.0 * 1024.0);
        snprintf(buf, sizeof(buf), "%.2f TiB", val);
    }
    return vval_string_cstr(buf);
}

VexValue *builtin_into_duration(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING)
        return vval_error("into-duration: expected string like '2h30m'");

    const char *s = vstr_data(&input->string);
    int64_t total_secs = 0;
    int64_t num = 0;
    bool has_num = false;

    while (*s) {
        if (*s >= '0' && *s <= '9') {
            num = num * 10 + (*s - '0');
            has_num = true;
        } else if (has_num) {
            switch (*s) {
            case 'd': total_secs += num * 86400; break;
            case 'h': total_secs += num * 3600; break;
            case 'm':
                if (s[1] == 's') { total_secs += num / 1000; s++; }
                else total_secs += num * 60;
                break;
            case 's': total_secs += num; break;
            default: break;
            }
            num = 0;
            has_num = false;
        } else {
            s++;
            continue;
        }
        s++;
    }

    if (has_num) total_secs += num;

    return vval_int(total_secs);
}

VexValue *builtin_format_duration(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();

    int64_t secs;
    if (input->type == VEX_VAL_INT) secs = input->integer;
    else if (input->type == VEX_VAL_FLOAT) secs = (int64_t)input->floating;
    else return vval_error("format-duration: expected number (seconds)");

    bool neg = secs < 0;
    if (neg) secs = -secs;

    int64_t days = secs / 86400;
    int64_t hours = (secs % 86400) / 3600;
    int64_t mins = (secs % 3600) / 60;
    int64_t rem = secs % 60;

    VexStr out = vstr_new("");
    if (neg) vstr_append_char(&out, '-');

    if (days > 0) {
        char tmp[32]; snprintf(tmp, sizeof(tmp), "%lldd ", (long long)days);
        vstr_append_cstr(&out, tmp);
    }
    if (hours > 0 || days > 0) {
        char tmp[32]; snprintf(tmp, sizeof(tmp), "%lldh ", (long long)hours);
        vstr_append_cstr(&out, tmp);
    }
    if (mins > 0 || hours > 0 || days > 0) {
        char tmp[32]; snprintf(tmp, sizeof(tmp), "%lldm ", (long long)mins);
        vstr_append_cstr(&out, tmp);
    }
    char tmp[32]; snprintf(tmp, sizeof(tmp), "%llds", (long long)rem);
    vstr_append_cstr(&out, tmp);

    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_loop_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 2 || args[0]->type != VEX_VAL_INT || args[1]->type != VEX_VAL_CLOSURE)
        return vval_error("loop: expected loop <n> <closure>");

    int64_t n = args[0]->integer;
    VexValue *result = vval_list();

    for (int64_t i = 0; i < n; i++) {
        VexValue *idx = vval_int(i);
        VexValue *ca[1] = { idx };
        VexValue *r = eval_call_closure(ctx, args[1], ca, 1);
        if (r && r->type != VEX_VAL_NULL) {
            vval_list_push(result, r);
        }
        vval_release(r);
        vval_release(idx);

        if (ctx->flow == FLOW_BREAK) { ctx->flow = FLOW_NONE; break; }
        if (ctx->flow == FLOW_CONTINUE) { ctx->flow = FLOW_NONE; }
    }
    return result;
}

VexValue *builtin_cmp(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || argc < 1) return vval_error("cmp: expected value | cmp <other>");

    VexValue *a = input, *b = args[0];

    if (a->type == VEX_VAL_INT && b->type == VEX_VAL_INT) {
        return vval_int(a->integer < b->integer ? -1 : (a->integer > b->integer ? 1 : 0));
    }
    if ((a->type == VEX_VAL_INT || a->type == VEX_VAL_FLOAT) &&
        (b->type == VEX_VAL_INT || b->type == VEX_VAL_FLOAT)) {
        double da = a->type == VEX_VAL_INT ? (double)a->integer : a->floating;
        double db = b->type == VEX_VAL_INT ? (double)b->integer : b->floating;
        return vval_int(da < db ? -1 : (da > db ? 1 : 0));
    }
    if (a->type == VEX_VAL_STRING && b->type == VEX_VAL_STRING) {
        int r = strcmp(vstr_data(&a->string), vstr_data(&b->string));
        return vval_int(r < 0 ? -1 : (r > 0 ? 1 : 0));
    }

    VexStr sa = vval_to_str(a), sb = vval_to_str(b);
    int r = strcmp(vstr_data(&sa), vstr_data(&sb));
    vstr_free(&sa); vstr_free(&sb);
    return vval_int(r < 0 ? -1 : (r > 0 ? 1 : 0));
}

VexValue *builtin_sort_by_fn(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST || argc < 1 || args[0]->type != VEX_VAL_CLOSURE)
        return input ? vval_retain(input) : vval_null();

    size_t n = vval_list_len(input);
    if (n <= 1) return vval_retain(input);

    VexValue **items = malloc(n * sizeof(VexValue *));
    for (size_t i = 0; i < n; i++) items[i] = vval_list_get(input, i);

    VexStr *keys = malloc(n * sizeof(VexStr));
    for (size_t i = 0; i < n; i++) {
        VexValue *ca[1] = { items[i] };
        VexValue *k = eval_call_closure(ctx, args[0], ca, 1);
        keys[i] = vval_to_str(k);
        vval_release(k);
    }

    for (size_t i = 1; i < n; i++) {
        VexValue *item = items[i];
        VexStr key = keys[i];
        size_t j = i;
        while (j > 0 && strcmp(vstr_data(&keys[j-1]), vstr_data(&key)) > 0) {
            items[j] = items[j-1];
            keys[j] = keys[j-1];
            j--;
        }
        items[j] = item;
        keys[j] = key;
    }

    VexValue *result = vval_list();
    for (size_t i = 0; i < n; i++) {
        vval_list_push(result, items[i]);
        vstr_free(&keys[i]);
    }
    free(items);
    free(keys);
    return result;
}

VexValue *builtin_index_of(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST || argc < 1)
        return vval_int(-1);

    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *item = vval_list_get(input, i);
        VexStr a = vval_to_str(item);
        VexStr b = vval_to_str(args[0]);
        bool eq = (vstr_len(&a) == vstr_len(&b) && strcmp(vstr_data(&a), vstr_data(&b)) == 0);
        vstr_free(&a); vstr_free(&b);
        if (eq) return vval_int((int64_t)i);
    }
    return vval_int(-1);
}

VexValue *builtin_flat(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST) return input ? vval_retain(input) : vval_null();

    int64_t depth = 1;
    if (argc > 0 && args[0]->type == VEX_VAL_INT) depth = args[0]->integer;
    if (depth <= 0) return vval_retain(input);

    VexValue *result = vval_list();
    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *item = vval_list_get(input, i);
        if (item->type == VEX_VAL_LIST && depth > 0) {

            VexValue *depth_arg = vval_int(depth - 1);
            VexValue *sub_args[1] = { depth_arg };
            VexValue *sub = builtin_flat(ctx, item, sub_args, 1);
            for (size_t j = 0; j < vval_list_len(sub); j++) {
                vval_list_push(result, vval_list_get(sub, j));
            }
            vval_release(sub);
            vval_release(depth_arg);
        } else {
            vval_list_push(result, item);
        }
    }
    return result;
}

VexValue *builtin_from_lines(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return input ? vval_retain(input) : vval_null();

    const char *s = vstr_data(&input->string);
    VexValue *result = vval_list();
    const char *start = s;

    while (*s) {
        if (*s == '\n') {
            char *line = strndup(start, (size_t)(s - start));

            size_t ll = strlen(line);
            if (ll > 0 && line[ll-1] == '\r') line[ll-1] = '\0';
            vval_list_push(result, vval_string_cstr(line));
            free(line);
            start = s + 1;
        }
        s++;
    }

    if (start < s) {
        char *line = strndup(start, (size_t)(s - start));
        size_t ll = strlen(line);
        if (ll > 0 && line[ll-1] == '\r') line[ll-1] = '\0';
        vval_list_push(result, vval_string_cstr(line));
        free(line);
    }
    return result;
}

VexValue *builtin_to_lines(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST) return input ? vval_retain(input) : vval_null();

    VexStr out = vstr_new("");
    for (size_t i = 0; i < vval_list_len(input); i++) {
        if (i > 0) vstr_append_char(&out, '\n');
        VexStr s = vval_to_str(vval_list_get(input, i));
        vstr_append_str(&out, &s);
        vstr_free(&s);
    }
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

static void md5_hash(const uint8_t *data, size_t len, uint8_t out[16]) {
    uint32_t a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
    static const uint32_t K[] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };
    static const uint32_t s[] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
    };

    size_t padded_len = ((len + 8) / 64 + 1) * 64;
    uint8_t *msg = calloc(padded_len, 1);
    memcpy(msg, data, len);
    msg[len] = 0x80;
    uint64_t bit_len = (uint64_t)len * 8;
    memcpy(msg + padded_len - 8, &bit_len, 8);

    for (size_t offset = 0; offset < padded_len; offset += 64) {
        uint32_t *M = (uint32_t *)(msg + offset);
        uint32_t A = a0, B = b0, C = c0, D = d0;
        for (uint32_t i = 0; i < 64; i++) {
            uint32_t F, g;
            if (i < 16) { F = (B & C) | (~B & D); g = i; }
            else if (i < 32) { F = (D & B) | (~D & C); g = (5*i+1) % 16; }
            else if (i < 48) { F = B ^ C ^ D; g = (3*i+5) % 16; }
            else { F = C ^ (B | ~D); g = (7*i) % 16; }
            F += A + K[i] + M[g];
            A = D; D = C; C = B;
            B += (F << s[i]) | (F >> (32 - s[i]));
        }
        a0 += A; b0 += B; c0 += C; d0 += D;
    }
    free(msg);
    memcpy(out, &a0, 4); memcpy(out+4, &b0, 4);
    memcpy(out+8, &c0, 4); memcpy(out+12, &d0, 4);
}

VexValue *builtin_hash_md5(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING)
        return vval_error("hash-md5: expected string");
    const char *s = vstr_data(&input->string);
    uint8_t hash[16];
    md5_hash((const uint8_t *)s, strlen(s), hash);
    char hex[33];
    for (int i = 0; i < 16; i++) sprintf(hex + i*2, "%02x", hash[i]);
    return vval_string_cstr(hex);
}

static void sha256_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    static const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    #define RR(x,n) (((x)>>(n))|((x)<<(32-(n))))
    #define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
    #define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
    #define EP0(x) (RR(x,2)^RR(x,13)^RR(x,22))
    #define EP1(x) (RR(x,6)^RR(x,11)^RR(x,25))
    #define SIG0(x) (RR(x,7)^RR(x,18)^((x)>>3))
    #define SIG1(x) (RR(x,17)^RR(x,19)^((x)>>10))

    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

    size_t padded_len = ((len + 8) / 64 + 1) * 64;
    uint8_t *msg = calloc(padded_len, 1);
    memcpy(msg, data, len);
    msg[len] = 0x80;
    uint64_t bit_len = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) msg[padded_len - 1 - i] = (uint8_t)(bit_len >> (i*8));

    for (size_t offset = 0; offset < padded_len; offset += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = ((uint32_t)msg[offset+i*4]<<24)|((uint32_t)msg[offset+i*4+1]<<16)|
                   ((uint32_t)msg[offset+i*4+2]<<8)|msg[offset+i*4+3];
        for (int i = 16; i < 64; i++)
            w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];

        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + EP1(e) + CH(e,f,g) + k[i] + w[i];
            uint32_t t2 = EP0(a) + MAJ(a,b,c);
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    free(msg);
    for (int i = 0; i < 8; i++) {
        out[i*4]=(uint8_t)(h[i]>>24); out[i*4+1]=(uint8_t)(h[i]>>16);
        out[i*4+2]=(uint8_t)(h[i]>>8); out[i*4+3]=(uint8_t)h[i];
    }
    #undef RR
    #undef CH
    #undef MAJ
    #undef EP0
    #undef EP1
    #undef SIG0
    #undef SIG1
}

VexValue *builtin_hash_sha256(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING)
        return vval_error("hash-sha256: expected string");
    const char *s = vstr_data(&input->string);
    uint8_t hash[32];
    sha256_hash((const uint8_t *)s, strlen(s), hash);
    char hex[65];
    for (int i = 0; i < 32; i++) sprintf(hex + i*2, "%02x", hash[i]);
    return vval_string_cstr(hex);
}

VexValue *builtin_hash_crc32(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING)
        return vval_error("hash-crc32: expected string");
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint8_t)s[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
    }
    crc ^= 0xFFFFFFFF;
    char hex[9];
    sprintf(hex, "%08x", crc);
    return vval_string_cstr(hex);
}

#include <sys/statvfs.h>

VexValue *builtin_df_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (has_flag_args(args, argc))
        return fallback_external(ctx, "df", args, argc);
    (void)input;
    const char *path = "/";
    if (argc > 0 && args[0]->type == VEX_VAL_STRING) {
        const char *arg = vstr_data(&args[0]->string);
        if (arg[0] == '-') return fallback_external(ctx, "df", args, argc);
        path = arg;
    }

    struct statvfs st;
    if (statvfs(path, &st) != 0) {
        vex_err("df: %s: %s", path, strerror(errno));
        return vval_error("df: failed to stat filesystem");
    }

    VexValue *rec = vval_record();
    vval_record_set(rec, "path", vval_string_cstr(path));
    vval_record_set(rec, "total", vval_int((int64_t)(st.f_blocks * st.f_frsize)));
    vval_record_set(rec, "free", vval_int((int64_t)(st.f_bfree * st.f_frsize)));
    vval_record_set(rec, "available", vval_int((int64_t)(st.f_bavail * st.f_frsize)));
    vval_record_set(rec, "used", vval_int((int64_t)((st.f_blocks - st.f_bfree) * st.f_frsize)));

    double pct = 100.0 * (double)(st.f_blocks - st.f_bfree) / (double)st.f_blocks;
    vval_record_set(rec, "use_percent", vval_float(pct));

    return rec;
}

VexValue *builtin_free_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (has_flag_args(args, argc))
        return fallback_external(ctx, "free", args, argc);
    (void)input; (void)args; (void)argc;
    VexValue *rec = vval_record();

#ifdef __APPLE__
    int64_t memsize = 0;
    size_t mlen = sizeof(memsize);
    sysctlbyname("hw.memsize", &memsize, &mlen, NULL, 0);

    VexValue *mem = vval_record();
    vval_record_set(mem, "total", vval_int(memsize));

    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    vm_statistics64_data_t vmstat;
    if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                          (host_info64_t)&vmstat, &count) == KERN_SUCCESS) {
        int64_t page = (int64_t)vm_kernel_page_size;
        int64_t free_mem = (int64_t)vmstat.free_count * page;
        vval_record_set(mem, "free", vval_int(free_mem));
        vval_record_set(mem, "used", vval_int(memsize - free_mem));
    }
    vval_record_set(rec, "memory", mem);
    vval_release(mem);

    struct xsw_usage sw;
    size_t sw_len = sizeof(sw);
    VexValue *swap = vval_record();
    if (sysctlbyname("vm.swapusage", &sw, &sw_len, NULL, 0) == 0) {
        vval_record_set(swap, "total", vval_int((int64_t)sw.xsu_total));
        vval_record_set(swap, "free", vval_int((int64_t)sw.xsu_avail));
        vval_record_set(swap, "used", vval_int((int64_t)sw.xsu_used));
    }
    vval_record_set(rec, "swap", swap);
    vval_release(swap);
#else
    struct sysinfo si;
    if (sysinfo(&si) < 0) return vval_error("free: sysinfo failed");

    unsigned long unit = si.mem_unit;

    VexValue *mem = vval_record();
    vval_record_set(mem, "total", vval_int((int64_t)(si.totalram * unit)));
    vval_record_set(mem, "free", vval_int((int64_t)(si.freeram * unit)));
    vval_record_set(mem, "buffers", vval_int((int64_t)(si.bufferram * unit)));
    vval_record_set(mem, "used", vval_int((int64_t)((si.totalram - si.freeram) * unit)));
    vval_record_set(rec, "memory", mem);
    vval_release(mem);

    VexValue *swap = vval_record();
    vval_record_set(swap, "total", vval_int((int64_t)(si.totalswap * unit)));
    vval_record_set(swap, "free", vval_int((int64_t)(si.freeswap * unit)));
    vval_record_set(swap, "used", vval_int((int64_t)((si.totalswap - si.freeswap) * unit)));
    vval_record_set(rec, "swap", swap);
    vval_release(swap);
#endif

    return rec;
}

#include <pwd.h>
#include <grp.h>

VexValue *builtin_id_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (has_flag_args(args, argc))
        return fallback_external(ctx, "id", args, argc);
    (void)ctx; (void)input; (void)args; (void)argc;
    VexValue *rec = vval_record();

    uid_t uid = getuid();
    gid_t gid = getgid();
    uid_t euid = geteuid();
    gid_t egid = getegid();

    vval_record_set(rec, "uid", vval_int(uid));
    vval_record_set(rec, "gid", vval_int(gid));
    vval_record_set(rec, "euid", vval_int(euid));
    vval_record_set(rec, "egid", vval_int(egid));

    struct passwd *pw = getpwuid(uid);
    if (pw) vval_record_set(rec, "user", vval_string_cstr(pw->pw_name));

    struct group *gr = getgrgid(gid);
    if (gr) vval_record_set(rec, "group", vval_string_cstr(gr->gr_name));

    gid_t groups[128];
    int ngroups = 128;
    if (getgroups(ngroups, groups) >= 0) {
        ngroups = getgroups(0, NULL);
        if (ngroups > 128) ngroups = 128;
        getgroups(ngroups, groups);
        VexValue *glist = vval_list();
        for (int i = 0; i < ngroups; i++) {
            struct group *g = getgrgid(groups[i]);
            if (g) vval_list_push(glist, vval_string_cstr(g->gr_name));
            else {
                char buf[16]; snprintf(buf, sizeof(buf), "%d", groups[i]);
                vval_list_push(glist, vval_string_cstr(buf));
            }
        }
        vval_record_set(rec, "groups", glist);
        vval_release(glist);
    }

    return rec;
}

VexValue *builtin_groups_cmd(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    gid_t groups[128];
    int ngroups = getgroups(128, groups);
    if (ngroups < 0) return vval_error("groups: getgroups failed");

    VexValue *result = vval_list();
    for (int i = 0; i < ngroups; i++) {
        struct group *g = getgrgid(groups[i]);
        if (g) vval_list_push(result, vval_string_cstr(g->gr_name));
        else {
            char buf[16]; snprintf(buf, sizeof(buf), "%d", groups[i]);
            vval_list_push(result, vval_string_cstr(buf));
        }
    }
    return result;
}

VexValue *builtin_date_add(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || argc < 1) return vval_error("date-add: expected epoch | date-add <seconds>");

    time_t epoch;
    if (input->type == VEX_VAL_INT) epoch = (time_t)input->integer;
    else if (input->type == VEX_VAL_RECORD) {
        VexValue *ep = vval_record_get(input, "epoch");
        if (!ep || ep->type != VEX_VAL_INT) return vval_error("date-add: record needs epoch");
        epoch = (time_t)ep->integer;
    } else return vval_error("date-add: expected int or date record");

    int64_t delta;
    if (args[0]->type == VEX_VAL_INT) delta = args[0]->integer;
    else if (args[0]->type == VEX_VAL_STRING) {

        VexValue *dur_args[1] = { args[0] };
        VexValue *parsed = builtin_into_duration(ctx, args[0], dur_args, 0);
        if (parsed->type != VEX_VAL_INT) { vval_release(parsed); return vval_error("date-add: bad duration"); }
        delta = parsed->integer;
        vval_release(parsed);
    } else return vval_error("date-add: expected seconds or duration string");

    return vval_int((int64_t)(epoch + delta));
}

VexValue *builtin_date_diff(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || argc < 1) return vval_error("date-diff: expected epoch | date-diff <epoch>");

    time_t a, b;
    if (input->type == VEX_VAL_INT) a = (time_t)input->integer;
    else if (input->type == VEX_VAL_RECORD) {
        VexValue *ep = vval_record_get(input, "epoch");
        if (!ep || ep->type != VEX_VAL_INT) return vval_error("date-diff: record needs epoch");
        a = (time_t)ep->integer;
    } else return vval_error("date-diff: expected int or date record");

    if (args[0]->type == VEX_VAL_INT) b = (time_t)args[0]->integer;
    else if (args[0]->type == VEX_VAL_RECORD) {
        VexValue *ep = vval_record_get(args[0], "epoch");
        if (!ep || ep->type != VEX_VAL_INT) return vval_error("date-diff: arg needs epoch");
        b = (time_t)ep->integer;
    } else return vval_error("date-diff: expected int or date record");

    return vval_int((int64_t)(a - b));
}

extern char *strptime(const char *s, const char *format, struct tm *tm);

VexValue *builtin_date_parse(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING)
        return vval_error("date-parse: expected date string");

    const char *s = vstr_data(&input->string);
    const char *fmt = "%Y-%m-%d";
    if (argc > 0 && args[0]->type == VEX_VAL_STRING)
        fmt = vstr_data(&args[0]->string);

    struct tm tm = {0};
    if (!strptime(s, fmt, &tm))
        return vval_error("date-parse: failed to parse date");

    tm.tm_isdst = -1;
    time_t epoch = mktime(&tm);
    return vval_int((int64_t)epoch);
}

VexValue *builtin_date_to_epoch(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_RECORD)
        return vval_error("date-to-epoch: expected date record");

    VexValue *ep = vval_record_get(input, "epoch");
    if (ep && ep->type == VEX_VAL_INT) return vval_int(ep->integer);

    struct tm tm = {0};
    VexValue *v;
    v = vval_record_get(input, "year");   if (v && v->type == VEX_VAL_INT) tm.tm_year = (int)v->integer - 1900;
    v = vval_record_get(input, "month");  if (v && v->type == VEX_VAL_INT) tm.tm_mon = (int)v->integer - 1;
    v = vval_record_get(input, "day");    if (v && v->type == VEX_VAL_INT) tm.tm_mday = (int)v->integer;
    v = vval_record_get(input, "hour");   if (v && v->type == VEX_VAL_INT) tm.tm_hour = (int)v->integer;
    v = vval_record_get(input, "minute"); if (v && v->type == VEX_VAL_INT) tm.tm_min = (int)v->integer;
    v = vval_record_get(input, "second"); if (v && v->type == VEX_VAL_INT) tm.tm_sec = (int)v->integer;
    tm.tm_isdst = -1;

    return vval_int((int64_t)mktime(&tm));
}

VexValue *builtin_math_sign(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    if (input->type == VEX_VAL_INT)
        return vval_int(input->integer < 0 ? -1 : (input->integer > 0 ? 1 : 0));
    if (input->type == VEX_VAL_FLOAT)
        return vval_int(input->floating < 0 ? -1 : (input->floating > 0 ? 1 : 0));
    return vval_error("math-sign: expected number");
}

VexValue *builtin_math_hypot(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || argc < 1) return vval_error("math-hypot: expected a | math-hypot <b>");
    double a, b;
    if (input->type == VEX_VAL_INT) a = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) a = input->floating;
    else return vval_error("math-hypot: expected number");
    if (args[0]->type == VEX_VAL_INT) b = (double)args[0]->integer;
    else if (args[0]->type == VEX_VAL_FLOAT) b = args[0]->floating;
    else return vval_error("math-hypot: expected number");
    return vval_float(hypot(a, b));
}

VexValue *builtin_math_log2(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    double v;
    if (input->type == VEX_VAL_INT) v = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) v = input->floating;
    else return vval_error("math-log2: expected number");
    if (v <= 0) return vval_error("math-log2: non-positive input");
    return vval_float(log2(v));
}

VexValue *builtin_math_log10(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    double v;
    if (input->type == VEX_VAL_INT) v = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) v = input->floating;
    else return vval_error("math-log10: expected number");
    if (v <= 0) return vval_error("math-log10: non-positive input");
    return vval_float(log10(v));
}

VexValue *builtin_regex_find(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_STRING)
        return vval_error("regex-find: expected string | regex-find <pattern>");

    const char *s = vstr_data(&input->string);
    const char *pattern = vstr_data(&args[0]->string);

    regex_t re;
    if (regcomp(&re, pattern, REG_EXTENDED) != 0)
        return vval_error("regex-find: invalid pattern");

    VexValue *result = vval_list();
    regmatch_t match;
    const char *p = s;

    while (regexec(&re, p, 1, &match, 0) == 0) {
        size_t mlen = (size_t)(match.rm_eo - match.rm_so);
        char *m = strndup(p + match.rm_so, mlen);
        vval_list_push(result, vval_string_cstr(m));
        free(m);
        p += match.rm_eo;
        if (match.rm_eo == 0) p++;
    }
    regfree(&re);
    return result;
}

VexValue *builtin_regex_split(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_STRING)
        return vval_error("regex-split: expected string | regex-split <pattern>");

    const char *s = vstr_data(&input->string);
    const char *pattern = vstr_data(&args[0]->string);

    regex_t re;
    if (regcomp(&re, pattern, REG_EXTENDED) != 0)
        return vval_error("regex-split: invalid pattern");

    VexValue *result = vval_list();
    regmatch_t match;
    const char *p = s;

    while (regexec(&re, p, 1, &match, 0) == 0) {
        char *part = strndup(p, (size_t)match.rm_so);
        vval_list_push(result, vval_string_cstr(part));
        free(part);
        p += match.rm_eo;
        if (match.rm_eo == 0) { p++; }
    }
    vval_list_push(result, vval_string_cstr(p));
    regfree(&re);
    return result;
}

VexValue *builtin_bytes_length(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_int(0);
    return vval_int((int64_t)vstr_len(&input->string));
}

VexValue *builtin_bytes_at(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_INT)
        return vval_null();
    int64_t idx = args[0]->integer;
    size_t len = vstr_len(&input->string);
    if (idx < 0) idx += (int64_t)len;
    if (idx < 0 || (size_t)idx >= len) return vval_null();
    return vval_int((int64_t)(unsigned char)vstr_data(&input->string)[idx]);
}

VexValue *builtin_bytes_slice(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_INT)
        return input ? vval_retain(input) : vval_null();

    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    int64_t start = args[0]->integer;
    int64_t end = (int64_t)len;
    if (argc > 1 && args[1]->type == VEX_VAL_INT) end = args[1]->integer;

    if (start < 0) start += (int64_t)len;
    if (end < 0) end += (int64_t)len;
    if (start < 0) start = 0;
    if (end > (int64_t)len) end = (int64_t)len;
    if (start >= end) return vval_string_cstr("");

    char *buf = strndup(s + start, (size_t)(end - start));
    VexValue *result = vval_string_cstr(buf);
    free(buf);
    return result;
}

VexValue *builtin_str_scan(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_STRING)
        return vval_error("str-scan: expected string | str-scan <substr>");

    const char *s = vstr_data(&input->string);
    const char *needle = vstr_data(&args[0]->string);
    size_t nlen = vstr_len(&args[0]->string);
    if (nlen == 0) return vval_list();

    VexValue *result = vval_list();
    const char *p = s;
    const char *found;
    while ((found = strstr(p, needle)) != NULL) {
        VexValue *rec = vval_record();
        vval_record_set(rec, "start", vval_int((int64_t)(found - s)));
        vval_record_set(rec, "end", vval_int((int64_t)(found - s + (int64_t)nlen)));
        vval_record_set(rec, "match", vval_string_cstr(needle));
        vval_list_push(result, rec);
        vval_release(rec);
        p = found + nlen;
    }
    return result;
}

VexValue *builtin_str_escape(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return input ? vval_retain(input) : vval_null();

    const char *s = vstr_data(&input->string);
    VexStr out = vstr_new("");
    for (; *s; s++) {
        switch (*s) {
        case '\n': vstr_append_cstr(&out, "\\n"); break;
        case '\t': vstr_append_cstr(&out, "\\t"); break;
        case '\r': vstr_append_cstr(&out, "\\r"); break;
        case '\0': vstr_append_cstr(&out, "\\0"); break;
        case '\\': vstr_append_cstr(&out, "\\\\"); break;
        case '"':  vstr_append_cstr(&out, "\\\""); break;
        default:
            if ((unsigned char)*s < 32) {
                char esc[5];
                snprintf(esc, sizeof(esc), "\\x%02x", (unsigned char)*s);
                vstr_append_cstr(&out, esc);
            } else {
                vstr_append_char(&out, *s);
            }
        }
    }
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_str_unescape(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return input ? vval_retain(input) : vval_null();

    const char *s = vstr_data(&input->string);
    VexStr out = vstr_new("");
    for (; *s; s++) {
        if (*s == '\\' && s[1]) {
            s++;
            switch (*s) {
            case 'n': vstr_append_char(&out, '\n'); break;
            case 't': vstr_append_char(&out, '\t'); break;
            case 'r': vstr_append_char(&out, '\r'); break;
            case '0': vstr_append_char(&out, '\0'); break;
            case '\\': vstr_append_char(&out, '\\'); break;
            case '"': vstr_append_char(&out, '"'); break;
            case 'x':
                if (s[1] && s[2]) {
                    int hi = hex_digit(s[1]), lo = hex_digit(s[2]);
                    if (hi >= 0 && lo >= 0) {
                        vstr_append_char(&out, (char)(hi * 16 + lo));
                        s += 2;
                        break;
                    }
                }
                vstr_append_char(&out, 'x');
                break;
            default: vstr_append_char(&out, '\\'); vstr_append_char(&out, *s); break;
            }
        } else {
            vstr_append_char(&out, *s);
        }
    }
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_headers(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST || vval_list_len(input) < 2)
        return input ? vval_retain(input) : vval_null();

    VexValue *header_row = vval_list_get(input, 0);
    if (header_row->type != VEX_VAL_LIST) return vval_retain(input);

    size_t ncols = vval_list_len(header_row);
    const char *cols[128];
    for (size_t i = 0; i < ncols && i < 128; i++) {
        VexValue *h = vval_list_get(header_row, i);
        if (h->type == VEX_VAL_STRING) cols[i] = vstr_data(&h->string);
        else cols[i] = "?";
    }

    VexValue *result = vval_list();
    for (size_t r = 1; r < vval_list_len(input); r++) {
        VexValue *row = vval_list_get(input, r);
        VexValue *rec = vval_record();
        if (row->type == VEX_VAL_LIST) {
            for (size_t c = 0; c < ncols && c < vval_list_len(row); c++) {
                vval_record_set(rec, cols[c], vval_list_get(row, c));
            }
        }
        vval_list_push(result, rec);
        vval_release(rec);
    }
    return result;
}

VexValue *builtin_move_col(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_RECORD || argc < 1 || args[0]->type != VEX_VAL_STRING)
        return input ? vval_retain(input) : vval_null();

    const char *col = vstr_data(&args[0]->string);
    const char *position = "first";
    if (argc > 1 && args[1]->type == VEX_VAL_STRING)
        position = vstr_data(&args[1]->string);

    VexValue *moved = vval_record_get(input, col);
    if (!moved) return vval_retain(input);

    VexValue *rec = vval_record();

    if (strcmp(position, "first") == 0 || strcmp(position, "before") == 0) {

        vval_record_set(rec, col, moved);
        VexMapIter it = vmap_iter(&input->record);
        const char *k;
        void *v;
        while (vmap_next(&it, &k, &v)) {
            if (strcmp(k, col) != 0) vval_record_set(rec, k, (VexValue *)v);
        }
    } else {

        VexMapIter it = vmap_iter(&input->record);
        const char *k;
        void *v;
        while (vmap_next(&it, &k, &v)) {
            if (strcmp(k, col) != 0) vval_record_set(rec, k, (VexValue *)v);
        }
        vval_record_set(rec, col, moved);
    }

    return rec;
}

VexValue *builtin_into_datetime(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_INT)
        return vval_error("into-datetime: expected epoch integer");

    time_t epoch = (time_t)input->integer;
    struct tm *tm = localtime(&epoch);

    VexValue *rec = vval_record();
    vval_record_set(rec, "year", vval_int(tm->tm_year + 1900));
    vval_record_set(rec, "month", vval_int(tm->tm_mon + 1));
    vval_record_set(rec, "day", vval_int(tm->tm_mday));
    vval_record_set(rec, "hour", vval_int(tm->tm_hour));
    vval_record_set(rec, "minute", vval_int(tm->tm_min));
    vval_record_set(rec, "second", vval_int(tm->tm_sec));
    vval_record_set(rec, "weekday", vval_int(tm->tm_wday));
    vval_record_set(rec, "yearday", vval_int(tm->tm_yday + 1));
    vval_record_set(rec, "epoch", vval_int(input->integer));

    static const char *wday_names[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    vval_record_set(rec, "weekday_name", vval_string_cstr(wday_names[tm->tm_wday]));

    char iso[32];
    strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%S", tm);
    vval_record_set(rec, "iso", vval_string_cstr(iso));

    return rec;
}

VexValue *builtin_each_with_index(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (!input || input->type != VEX_VAL_LIST || argc < 1 || args[0]->type != VEX_VAL_CLOSURE)
        return input ? vval_retain(input) : vval_null();

    VexValue *result = vval_list();
    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *idx = vval_int((int64_t)i);
        VexValue *ca[2] = { vval_list_get(input, i), idx };
        VexValue *r = eval_call_closure(ctx, args[0], ca, 2);
        vval_list_push(result, r);
        vval_release(r);
        vval_release(idx);
    }
    return result;
}

static const char *type_name(VexType t) {
    switch (t) {
    case VEX_VAL_NULL: return "null";
    case VEX_VAL_BOOL: return "bool";
    case VEX_VAL_INT: return "int";
    case VEX_VAL_FLOAT: return "float";
    case VEX_VAL_STRING: return "string";
    case VEX_VAL_LIST: return "list";
    case VEX_VAL_RECORD: return "record";
    case VEX_VAL_CLOSURE: return "closure";
    case VEX_VAL_ERROR: return "error";
    case VEX_VAL_STREAM: return "stream";
    case VEX_VAL_BYTES: return "bytes";
    case VEX_VAL_RANGE: return "range";
    default: return "unknown";
    }
}

VexValue *builtin_debug(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_string_cstr("null (no input)");

    VexValue *rec = vval_record();
    vval_record_set(rec, "type", vval_string_cstr(type_name(input->type)));

    VexStr s = vval_to_str(input);
    vval_record_set(rec, "value", vval_string_cstr(vstr_data(&s)));
    vstr_free(&s);

    if (input->type == VEX_VAL_STRING) {
        vval_record_set(rec, "length", vval_int((int64_t)vstr_len(&input->string)));
        vval_record_set(rec, "bytes", vval_int((int64_t)vstr_len(&input->string)));
    } else if (input->type == VEX_VAL_LIST) {
        vval_record_set(rec, "length", vval_int((int64_t)vval_list_len(input)));
        if (vval_list_len(input) > 0) {
            vval_record_set(rec, "item_type", vval_string_cstr(type_name(vval_list_get(input, 0)->type)));
        }
    } else if (input->type == VEX_VAL_RECORD) {
        VexValue *keys = vval_list();
        VexMapIter it = vmap_iter(&input->record);
        const char *k; void *v;
        while (vmap_next(&it, &k, &v)) {
            vval_list_push(keys, vval_string_cstr(k));
        }
        vval_record_set(rec, "fields", keys);
        vval_release(keys);
    } else if (input->type == VEX_VAL_CLOSURE) {
        vval_record_set(rec, "params", vval_int((int64_t)input->closure.param_count));
    }

    return rec;
}

VexValue *builtin_profile(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    if (argc < 1 || args[0]->type != VEX_VAL_CLOSURE)
        return vval_error("profile: expected closure");

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    VexValue *ca[1] = { input ? input : vval_null() };
    VexValue *result = eval_call_closure(ctx, args[0], ca, input ? 0 : 1);

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (double)(end.tv_sec - start.tv_sec) +
                     (double)(end.tv_nsec - start.tv_nsec) / 1e9;

    VexValue *rec = vval_record();
    vval_record_set(rec, "result", result);
    vval_record_set(rec, "elapsed_ms", vval_float(elapsed * 1000.0));

    char buf[64];
    if (elapsed < 0.001)
        snprintf(buf, sizeof(buf), "%.1f µs", elapsed * 1e6);
    else if (elapsed < 1.0)
        snprintf(buf, sizeof(buf), "%.2f ms", elapsed * 1000.0);
    else
        snprintf(buf, sizeof(buf), "%.3f s", elapsed);
    vval_record_set(rec, "elapsed", vval_string_cstr(buf));

    vval_release(result);
    return rec;
}

VexValue *builtin_table_flip(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST || vval_list_len(input) == 0)
        return input ? vval_retain(input) : vval_null();

    VexValue *first = vval_list_get(input, 0);
    if (first->type != VEX_VAL_RECORD) return vval_retain(input);

    const char *cols[128];
    size_t ncols = 0;
    VexMapIter it = vmap_iter(&first->record);
    const char *k; void *v;
    while (vmap_next(&it, &k, &v) && ncols < 128) cols[ncols++] = k;

    VexValue *result = vval_record();
    for (size_t c = 0; c < ncols; c++) {
        VexValue *col_vals = vval_list();
        for (size_t r = 0; r < vval_list_len(input); r++) {
            VexValue *row = vval_list_get(input, r);
            VexValue *cell = (row->type == VEX_VAL_RECORD) ? vval_record_get(row, cols[c]) : NULL;
            vval_list_push(col_vals, cell ? cell : vval_null());
        }
        vval_record_set(result, cols[c], col_vals);
        vval_release(col_vals);
    }
    return result;
}

VexValue *builtin_cross_join(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST || argc < 1 || args[0]->type != VEX_VAL_LIST)
        return vval_error("cross-join: expected list | cross-join <list>");

    VexValue *result = vval_list();
    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *a = vval_list_get(input, i);
        for (size_t j = 0; j < vval_list_len(args[0]); j++) {
            VexValue *b = vval_list_get(args[0], j);

            VexValue *merged = vval_record();
            if (a->type == VEX_VAL_RECORD) {
                VexMapIter it = vmap_iter(&a->record);
                const char *k; void *v;
                while (vmap_next(&it, &k, &v)) vval_record_set(merged, k, (VexValue *)v);
            }
            if (b->type == VEX_VAL_RECORD) {
                VexMapIter it = vmap_iter(&b->record);
                const char *k; void *v;
                while (vmap_next(&it, &k, &v)) vval_record_set(merged, k, (VexValue *)v);
            }
            vval_list_push(result, merged);
            vval_release(merged);
        }
    }
    return result;
}

VexValue *builtin_left_join(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST || argc < 2 ||
        args[0]->type != VEX_VAL_LIST || args[1]->type != VEX_VAL_STRING)
        return vval_error("left-join: expected list | left-join <right> <key>");

    const char *key = vstr_data(&args[1]->string);
    VexValue *right = args[0];

    VexValue *result = vval_list();
    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *left_row = vval_list_get(input, i);
        if (left_row->type != VEX_VAL_RECORD) continue;
        VexValue *lkey = vval_record_get(left_row, key);
        if (!lkey) continue;

        VexStr lks = vval_to_str(lkey);
        bool matched = false;

        for (size_t j = 0; j < vval_list_len(right); j++) {
            VexValue *right_row = vval_list_get(right, j);
            if (right_row->type != VEX_VAL_RECORD) continue;
            VexValue *rkey = vval_record_get(right_row, key);
            if (!rkey) continue;

            VexStr rks = vval_to_str(rkey);
            if (strcmp(vstr_data(&lks), vstr_data(&rks)) == 0) {

                VexValue *merged = vval_record();
                VexMapIter it = vmap_iter(&left_row->record);
                const char *k; void *v;
                while (vmap_next(&it, &k, &v)) vval_record_set(merged, k, (VexValue *)v);
                it = vmap_iter(&right_row->record);
                while (vmap_next(&it, &k, &v)) {
                    if (strcmp(k, key) != 0) vval_record_set(merged, k, (VexValue *)v);
                }
                vval_list_push(result, merged);
                vval_release(merged);
                matched = true;
            }
            vstr_free(&rks);
        }
        if (!matched) {
            vval_list_push(result, left_row);
        }
        vstr_free(&lks);
    }
    return result;
}

VexValue *builtin_str_hex(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return input ? vval_retain(input) : vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    char *hex = malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) sprintf(hex + i*2, "%02x", (unsigned char)s[i]);
    hex[len * 2] = '\0';
    VexValue *result = vval_string_cstr(hex);
    free(hex);
    return result;
}

VexValue *builtin_from_hex(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return input ? vval_retain(input) : vval_null();
    const char *s = vstr_data(&input->string);
    size_t len = vstr_len(&input->string);
    if (len % 2 != 0) return vval_error("from-hex: odd length");

    size_t out_len = len / 2;
    char *buf = malloc(out_len + 1);
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_digit(s[i*2]), lo = hex_digit(s[i*2+1]);
        if (hi < 0 || lo < 0) { free(buf); return vval_error("from-hex: invalid hex"); }
        buf[i] = (char)(hi * 16 + lo);
    }
    buf[out_len] = '\0';
    VexValue *result = vval_string_cstr(buf);
    free(buf);
    return result;
}

VexValue *builtin_math_factorial(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_INT) return vval_error("math-factorial: expected integer");
    int64_t n = input->integer;
    if (n < 0) return vval_error("math-factorial: negative input");
    if (n > 20) return vval_error("math-factorial: too large (max 20)");
    int64_t result = 1;
    for (int64_t i = 2; i <= n; i++) result *= i;
    return vval_int(result);
}

VexValue *builtin_math_is_prime(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_INT) return vval_bool(false);
    int64_t n = input->integer;
    if (n < 2) return vval_bool(false);
    if (n < 4) return vval_bool(true);
    if (n % 2 == 0 || n % 3 == 0) return vval_bool(false);
    for (int64_t i = 5; i * i <= n; i += 6) {
        if (n % i == 0 || n % (i + 2) == 0) return vval_bool(false);
    }
    return vval_bool(true);
}

VexValue *builtin_math_fibonacci(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_INT) return vval_error("math-fibonacci: expected integer");
    int64_t n = input->integer;
    if (n < 0) return vval_error("math-fibonacci: negative input");
    if (n > 92) return vval_error("math-fibonacci: too large (max 92 for int64)");
    if (n == 0) return vval_int(0);
    int64_t a = 0, b = 1;
    for (int64_t i = 2; i <= n; i++) { int64_t t = a + b; a = b; b = t; }
    return vval_int(b);
}

VexValue *builtin_env_get(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_STRING)
        return vval_error("env-get: expected variable name");
    const char *name = vstr_data(&args[0]->string);
    const char *val = getenv(name);
    if (val) return vval_string_cstr(val);

    if (argc > 1) return vval_retain(args[1]);
    return vval_null();
}

VexValue *builtin_env_set(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 2 || args[0]->type != VEX_VAL_STRING || args[1]->type != VEX_VAL_STRING) {
        vex_err("env-set: expected env-set <name> <value>");
        return vval_null();
    }
    setenv(vstr_data(&args[0]->string), vstr_data(&args[1]->string), 1);
    return vval_null();
}

static VexValue *shell_capture(const char *cmd) {
    int pipefd[2];
    if (pipe(pipefd) < 0) return vval_error("pipe failed");
    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execlp("sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    VexStr buf = vstr_new("");
    char chunk[4096];
    ssize_t n;
    while ((n = read(pipefd[0], chunk, sizeof(chunk) - 1)) > 0) {
        chunk[n] = '\0';
        vstr_append_cstr(&buf, chunk);
    }
    close(pipefd[0]);
    int status;
    waitpid(pid, &status, 0);
    VexValue *result = vval_string_cstr(vstr_data(&buf));
    vstr_free(&buf);
    return result;
}

VexValue *builtin_gzip(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (argc > 0 && args[0]->type == VEX_VAL_STRING) {

        const char *file = vstr_data(&args[0]->string);
        char cmd[4200];
        snprintf(cmd, sizeof(cmd), "gzip '%s'", file);
        int r = system(cmd);
        return vval_int(WIFEXITED(r) ? WEXITSTATUS(r) : 1);
    }
    if (input && input->type == VEX_VAL_STRING) {

        char cmd[64] = "gzip | base64";
        int pipefd_in[2], pipefd_out[2];
        if (pipe(pipefd_in) < 0 || pipe(pipefd_out) < 0)
            return vval_error("gzip: pipe failed");
        pid_t pid = fork();
        if (pid == 0) {
            close(pipefd_in[1]); close(pipefd_out[0]);
            dup2(pipefd_in[0], STDIN_FILENO);
            dup2(pipefd_out[1], STDOUT_FILENO);
            close(pipefd_in[0]); close(pipefd_out[1]);
            execlp("sh", "sh", "-c", cmd, (char *)NULL);
            _exit(127);
        }
        close(pipefd_in[0]); close(pipefd_out[1]);
        const char *data = vstr_data(&input->string);
        write(pipefd_in[1], data, vstr_len(&input->string));
        close(pipefd_in[1]);
        VexStr buf = vstr_new("");
        char chunk[4096];
        ssize_t n;
        while ((n = read(pipefd_out[0], chunk, sizeof(chunk) - 1)) > 0) {
            chunk[n] = '\0'; vstr_append_cstr(&buf, chunk);
        }
        close(pipefd_out[0]);
        waitpid(pid, NULL, 0);
        VexValue *result = vval_string_cstr(vstr_data(&buf));
        vstr_free(&buf);
        return result;
    }
    return vval_error("gzip: expected file path or string input");
}

VexValue *builtin_gunzip(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (argc > 0 && args[0]->type == VEX_VAL_STRING) {
        const char *file = vstr_data(&args[0]->string);
        char cmd[4200];
        snprintf(cmd, sizeof(cmd), "gunzip '%s'", file);
        int r = system(cmd);
        return vval_int(WIFEXITED(r) ? WEXITSTATUS(r) : 1);
    }
    (void)input;
    return vval_error("gunzip: expected file path");
}

VexValue *builtin_tar_list(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_STRING)
        return vval_error("tar-list: expected archive path");

    const char *path = vstr_data(&args[0]->string);
    char cmd[4200];
    snprintf(cmd, sizeof(cmd), "tar -tf '%s' 2>/dev/null", path);
    VexValue *output = shell_capture(cmd);

    if (output->type != VEX_VAL_STRING) return output;
    const char *s = vstr_data(&output->string);
    VexValue *result = vval_list();
    const char *start = s;
    while (*s) {
        if (*s == '\n') {
            if (s > start) {
                char *line = strndup(start, (size_t)(s - start));
                vval_list_push(result, vval_string_cstr(line));
                free(line);
            }
            start = s + 1;
        }
        s++;
    }
    if (*start) vval_list_push(result, vval_string_cstr(start));
    vval_release(output);
    return result;
}

VexValue *builtin_path_is_absolute(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    const char *path = NULL;
    if (input && input->type == VEX_VAL_STRING) path = vstr_data(&input->string);
    else if (argc > 0 && args[0]->type == VEX_VAL_STRING) path = vstr_data(&args[0]->string);
    if (!path) return vval_bool(false);
    return vval_bool(path[0] == '/');
}

VexValue *builtin_path_normalize(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    const char *path = NULL;
    if (input && input->type == VEX_VAL_STRING) path = vstr_data(&input->string);
    else if (argc > 0 && args[0]->type == VEX_VAL_STRING) path = vstr_data(&args[0]->string);
    if (!path) return vval_null();

    char *parts[256];
    int nparts = 0;
    bool absolute = (path[0] == '/');

    char *tmp = strdup(path);
    char *tok = strtok(tmp, "/");
    while (tok) {
        if (strcmp(tok, ".") == 0) {  }
        else if (strcmp(tok, "..") == 0) {
            if (nparts > 0 && strcmp(parts[nparts-1], "..") != 0) {
                free(parts[--nparts]);
            } else if (!absolute) {
                parts[nparts++] = strdup("..");
            }
        } else {
            parts[nparts++] = strdup(tok);
        }
        tok = strtok(NULL, "/");
    }
    free(tmp);

    VexStr out = vstr_new("");
    if (absolute) vstr_append_char(&out, '/');
    for (int i = 0; i < nparts; i++) {
        if (i > 0) vstr_append_char(&out, '/');
        vstr_append_cstr(&out, parts[i]);
        free(parts[i]);
    }
    if (nparts == 0 && !absolute) vstr_append_char(&out, '.');

    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_path_with_ext(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_STRING)
        return input ? vval_retain(input) : vval_null();

    const char *path = vstr_data(&input->string);
    const char *new_ext = vstr_data(&args[0]->string);
    const char *dot = strrchr(path, '.');
    const char *slash = strrchr(path, '/');

    VexStr out = vstr_new("");
    if (dot && (!slash || dot > slash)) {

        for (const char *p = path; p < dot; p++) vstr_append_char(&out, *p);
    } else {
        vstr_append_cstr(&out, path);
    }
    if (new_ext[0] != '.') vstr_append_char(&out, '.');
    vstr_append_cstr(&out, new_ext);

    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_str_ljust(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    return builtin_str_pad_right(ctx, input, args, argc);
}

VexValue *builtin_str_rjust(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    return builtin_str_pad_left(ctx, input, args, argc);
}

VexValue *builtin_split_column(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1)
        return input ? vval_retain(input) : vval_null();

    const char *sep = " ";
    if (args[0]->type == VEX_VAL_STRING) sep = vstr_data(&args[0]->string);

    const char *s = vstr_data(&input->string);
    size_t sep_len = strlen(sep);
    VexValue *rec = vval_record();

    size_t col_idx = 0;
    const char *start = s;
    const char *found;

    while ((found = sep_len > 0 ? strstr(start, sep) : NULL) != NULL) {
        char *part = strndup(start, (size_t)(found - start));
        char col_name[32];
        if (col_idx + 1 < argc && args[col_idx + 1]->type == VEX_VAL_STRING) {
            snprintf(col_name, sizeof(col_name), "%s", vstr_data(&args[col_idx + 1]->string));
        } else {
            snprintf(col_name, sizeof(col_name), "column%zu", col_idx);
        }
        vval_record_set(rec, col_name, vval_string_cstr(part));
        free(part);
        start = found + sep_len;
        col_idx++;
    }

    char col_name[32];
    if (col_idx + 1 < argc && args[col_idx + 1]->type == VEX_VAL_STRING) {
        snprintf(col_name, sizeof(col_name), "%s", vstr_data(&args[col_idx + 1]->string));
    } else {
        snprintf(col_name, sizeof(col_name), "column%zu", col_idx);
    }
    vval_record_set(rec, col_name, vval_string_cstr(start));

    return rec;
}

VexValue *builtin_fill_null(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || argc < 1) return input ? vval_retain(input) : vval_null();
    VexValue *fill = args[0];

    if (input->type == VEX_VAL_NULL) return vval_retain(fill);

    if (input->type == VEX_VAL_LIST) {
        VexValue *result = vval_list();
        for (size_t i = 0; i < vval_list_len(input); i++) {
            VexValue *item = vval_list_get(input, i);
            vval_list_push(result, (item->type == VEX_VAL_NULL) ? fill : item);
        }
        return result;
    }
    if (input->type == VEX_VAL_RECORD) {
        VexValue *rec = vval_record();
        VexMapIter it = vmap_iter(&input->record);
        const char *k; void *v;
        while (vmap_next(&it, &k, &v)) {
            VexValue *val = (VexValue *)v;
            vval_record_set(rec, k, (val->type == VEX_VAL_NULL) ? fill : val);
        }
        return rec;
    }
    return vval_retain(input);
}

VexValue *builtin_math_variance(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST || vval_list_len(input) == 0)
        return vval_error("math-variance: expected non-empty list");

    size_t n = vval_list_len(input);
    double sum = 0;
    for (size_t i = 0; i < n; i++) {
        VexValue *v = vval_list_get(input, i);
        if (v->type == VEX_VAL_INT) sum += (double)v->integer;
        else if (v->type == VEX_VAL_FLOAT) sum += v->floating;
        else return vval_error("math-variance: non-numeric item");
    }
    double mean = sum / (double)n;
    double var = 0;
    for (size_t i = 0; i < n; i++) {
        VexValue *v = vval_list_get(input, i);
        double d = (v->type == VEX_VAL_INT ? (double)v->integer : v->floating) - mean;
        var += d * d;
    }
    return vval_float(var / (double)n);
}

VexValue *builtin_compact_record(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_RECORD) return input ? vval_retain(input) : vval_null();

    VexValue *rec = vval_record();
    VexMapIter it = vmap_iter(&input->record);
    const char *k; void *v;
    while (vmap_next(&it, &k, &v)) {
        VexValue *val = (VexValue *)v;
        if (val->type != VEX_VAL_NULL) vval_record_set(rec, k, val);
    }
    return rec;
}

VexValue *builtin_to_base(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_INT || argc < 1 || args[0]->type != VEX_VAL_INT)
        return vval_error("to-base: expected int | to-base <base>");
    int64_t num = input->integer;
    int64_t base = args[0]->integer;
    if (base < 2 || base > 36) return vval_error("to-base: base must be 2-36");

    bool neg = num < 0;
    if (neg) num = -num;

    static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char buf[66];
    int pos = 65;
    buf[pos] = '\0';

    if (num == 0) {
        buf[--pos] = '0';
    } else {
        while (num > 0) {
            buf[--pos] = digits[num % base];
            num /= base;
        }
    }
    if (neg) buf[--pos] = '-';

    return vval_string_cstr(buf + pos);
}

VexValue *builtin_from_base(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_STRING || argc < 1 || args[0]->type != VEX_VAL_INT)
        return vval_error("from-base: expected string | from-base <base>");
    int64_t base = args[0]->integer;
    if (base < 2 || base > 36) return vval_error("from-base: base must be 2-36");

    const char *s = vstr_data(&input->string);
    char *endp;
    long long val = strtoll(s, &endp, (int)base);
    if (endp == s) return vval_error("from-base: invalid number");
    return vval_int((int64_t)val);
}

VexValue *builtin_builtins(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    VexValue *list = vval_list();
    for (size_t i = 0; i < builtin_count(); i++) {
        const char *name = builtin_name(i);
        if (name) {
            const BuiltinCmd *cmd = builtin_lookup(name);
            VexValue *rec = vval_record();
            vval_record_set(rec, "name", vval_string_cstr(name));
            vval_record_set(rec, "usage", vval_string_cstr(cmd->usage));
            vval_record_set(rec, "description", vval_string_cstr(cmd->description));
            vval_list_push(list, rec);
            vval_release(rec);
        }
    }
    return list;
}

VexValue *builtin_vars(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input; (void)args; (void)argc;
    VexValue *list = vval_list();
    Scope *s = ctx->current;
    while (s) {
        VexMapIter it = vmap_iter(&s->bindings);
        const char *k; void *v;
        while (vmap_next(&it, &k, &v)) {
            VexValue *val = (VexValue *)v;
            VexValue *rec = vval_record();
            vval_record_set(rec, "name", vval_string_cstr(k));
            VexStr ts = vval_to_str(val);
            vval_record_set(rec, "type", vval_string_cstr(type_name(val->type)));
            vval_record_set(rec, "value", vval_string_cstr(vstr_data(&ts)));
            vstr_free(&ts);
            vval_list_push(list, rec);
            vval_release(rec);
        }
        s = s->parent;
    }
    return list;
}

#include <sys/resource.h>

VexValue *builtin_ulimit(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc == 0) {

        VexValue *rec = vval_record();
        struct { const char *name; int res; } limits[] = {
            {"open-files", RLIMIT_NOFILE},
            {"stack-size", RLIMIT_STACK},
            {"max-procs", RLIMIT_NPROC},
            {"file-size", RLIMIT_FSIZE},
            {"core-size", RLIMIT_CORE},
            {"data-size", RLIMIT_DATA},
            {"cpu-time", RLIMIT_CPU},
            {"virtual-memory", RLIMIT_AS},
        };
        for (size_t i = 0; i < sizeof(limits)/sizeof(limits[0]); i++) {
            struct rlimit rl;
            if (getrlimit(limits[i].res, &rl) == 0) {
                VexValue *lrec = vval_record();
                vval_record_set(lrec, "soft",
                    rl.rlim_cur == RLIM_INFINITY ? vval_string_cstr("unlimited") : vval_int((int64_t)rl.rlim_cur));
                vval_record_set(lrec, "hard",
                    rl.rlim_max == RLIM_INFINITY ? vval_string_cstr("unlimited") : vval_int((int64_t)rl.rlim_max));
                vval_record_set(rec, limits[i].name, lrec);
                vval_release(lrec);
            }
        }
        return rec;
    }

    if (argc >= 1 && args[0]->type == VEX_VAL_STRING) {
        const char *name = vstr_data(&args[0]->string);
        int res = -1;
        if (strcmp(name, "-n") == 0 || strcmp(name, "open-files") == 0) res = RLIMIT_NOFILE;
        else if (strcmp(name, "-s") == 0 || strcmp(name, "stack-size") == 0) res = RLIMIT_STACK;
        else if (strcmp(name, "-u") == 0 || strcmp(name, "max-procs") == 0) res = RLIMIT_NPROC;
        else if (strcmp(name, "-f") == 0 || strcmp(name, "file-size") == 0) res = RLIMIT_FSIZE;
        else if (strcmp(name, "-c") == 0 || strcmp(name, "core-size") == 0) res = RLIMIT_CORE;
        else if (strcmp(name, "-v") == 0 || strcmp(name, "virtual-memory") == 0) res = RLIMIT_AS;
        if (res < 0) return vval_error("ulimit: unknown resource");

        if (argc >= 2 && args[1]->type == VEX_VAL_INT) {
            struct rlimit rl;
            getrlimit(res, &rl);
            rl.rlim_cur = (rlim_t)args[1]->integer;
            if (setrlimit(res, &rl) < 0)
                return vval_error("ulimit: failed to set limit");
            return vval_null();
        }
        struct rlimit rl;
        getrlimit(res, &rl);
        return rl.rlim_cur == RLIM_INFINITY ? vval_string_cstr("unlimited") : vval_int((int64_t)rl.rlim_cur);
    }
    return vval_error("ulimit: expected resource name");
}

VexValue *builtin_ansi_strip(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return input ? vval_retain(input) : vval_null();
    const char *s = vstr_data(&input->string);
    VexStr out = vstr_new("");
    while (*s) {
        if (*s == '\033' && *(s+1) == '[') {
            s += 2;
            while (*s && !(*s >= 'A' && *s <= 'Z') && *s != 'm' && !(*s >= 'a' && *s <= 'z'))
                s++;
            if (*s) s++;
        } else {
            vstr_append_char(&out, *s++);
        }
    }
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_str_is_numeric(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_bool(false);
    const char *s = vstr_data(&input->string);
    if (*s == '\0') return vval_bool(false);
    char *endp;
    strtod(s, &endp);

    while (*endp && isspace((unsigned char)*endp)) endp++;
    return vval_bool(*endp == '\0');
}

VexValue *builtin_inner_join(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_LIST || argc < 2 ||
        args[0]->type != VEX_VAL_LIST || args[1]->type != VEX_VAL_STRING)
        return vval_error("inner-join: expected table | inner-join <table> <key>");

    const char *key = vstr_data(&args[1]->string);
    VexValue *right = args[0];
    VexValue *result = vval_list();

    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *lrow = vval_list_get(input, i);
        if (lrow->type != VEX_VAL_RECORD) continue;
        VexValue *lkey = vval_record_get(lrow, key);
        if (!lkey) continue;

        for (size_t j = 0; j < vval_list_len(right); j++) {
            VexValue *rrow = vval_list_get(right, j);
            if (rrow->type != VEX_VAL_RECORD) continue;
            VexValue *rkey = vval_record_get(rrow, key);
            if (!rkey) continue;

            VexStr ls = vval_to_str(lkey);
            VexStr rs = vval_to_str(rkey);
            bool match = (strcmp(vstr_data(&ls), vstr_data(&rs)) == 0);
            vstr_free(&ls); vstr_free(&rs);

            if (match) {
                VexValue *merged = vval_record();

                VexMapIter it = vmap_iter(&lrow->record);
                const char *k; void *v;
                while (vmap_next(&it, &k, &v))
                    vval_record_set(merged, k, (VexValue *)v);

                it = vmap_iter(&rrow->record);
                while (vmap_next(&it, &k, &v))
                    vval_record_set(merged, k, (VexValue *)v);
                vval_list_push(result, merged);
                vval_release(merged);
            }
        }
    }
    return result;
}

VexValue *builtin_from_jsonl(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING)
        return vval_error("from-jsonl: expected string input");

    const char *s = vstr_data(&input->string);
    VexValue *result = vval_list();
    const char *start = s;

    while (*s) {
        if (*s == '\n' || *(s+1) == '\0') {
            const char *end = (*s == '\n') ? s : s + 1;
            size_t len = (size_t)(end - start);
            if (len > 0) {
                char *line = strndup(start, len);
                VexValue *line_val = vval_string_cstr(line);

                VexValue *parsed_args[] = { line_val };
                VexValue *parsed = builtin_from_json(ctx, line_val, parsed_args, 0);
                if (parsed && parsed->type != VEX_VAL_ERROR) {
                    vval_list_push(result, parsed);
                }
                vval_release(parsed);
                vval_release(line_val);
                free(line);
            }
            start = s + 1;
        }
        s++;
    }
    return result;
}

VexValue *builtin_to_jsonl(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("to-jsonl: expected list input");

    VexStr out = vstr_new("");
    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *item = vval_list_get(input, i);
        VexValue *json = builtin_to_json(ctx, item, NULL, 0);
        if (json && json->type == VEX_VAL_STRING) {
            vstr_append_cstr(&out, vstr_data(&json->string));
            vstr_append_char(&out, '\n');
        }
        vval_release(json);
    }
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_url_build(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_RECORD)
        return vval_error("url-build: expected record with scheme, host, path, etc.");

    VexStr url = vstr_new("");
    VexValue *scheme = vval_record_get(input, "scheme");
    VexValue *host = vval_record_get(input, "host");
    VexValue *port = vval_record_get(input, "port");
    VexValue *path = vval_record_get(input, "path");
    VexValue *query = vval_record_get(input, "query");
    VexValue *fragment = vval_record_get(input, "fragment");
    VexValue *user = vval_record_get(input, "user");

    if (scheme && scheme->type == VEX_VAL_STRING) {
        vstr_append_cstr(&url, vstr_data(&scheme->string));
        vstr_append_cstr(&url, "://");
    }
    if (user && user->type == VEX_VAL_STRING) {
        vstr_append_cstr(&url, vstr_data(&user->string));
        vstr_append_char(&url, '@');
    }
    if (host && host->type == VEX_VAL_STRING)
        vstr_append_cstr(&url, vstr_data(&host->string));
    if (port && port->type == VEX_VAL_INT) {
        char pbuf[16];
        snprintf(pbuf, sizeof(pbuf), ":%lld", (long long)port->integer);
        vstr_append_cstr(&url, pbuf);
    } else if (port && port->type == VEX_VAL_STRING) {
        vstr_append_char(&url, ':');
        vstr_append_cstr(&url, vstr_data(&port->string));
    }
    if (path && path->type == VEX_VAL_STRING) {
        const char *p = vstr_data(&path->string);
        if (*p != '/') vstr_append_char(&url, '/');
        vstr_append_cstr(&url, p);
    }
    if (query && query->type == VEX_VAL_STRING) {
        vstr_append_char(&url, '?');
        vstr_append_cstr(&url, vstr_data(&query->string));
    }
    if (fragment && fragment->type == VEX_VAL_STRING) {
        vstr_append_char(&url, '#');
        vstr_append_cstr(&url, vstr_data(&fragment->string));
    }

    VexValue *result = vval_string_cstr(vstr_data(&url));
    vstr_free(&url);
    return result;
}

VexValue *builtin_tar_extract(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_STRING)
        return vval_error("tar-extract: expected archive path");

    const char *archive = vstr_data(&args[0]->string);
    const char *dest = ".";
    if (argc >= 2 && args[1]->type == VEX_VAL_STRING)
        dest = vstr_data(&args[1]->string);

    char cmd[8400];
    snprintf(cmd, sizeof(cmd), "tar -xf '%s' -C '%s'", archive, dest);
    int r = system(cmd);
    return vval_int(WIFEXITED(r) ? WEXITSTATUS(r) : 1);
}

VexValue *builtin_tar_create(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 2 || args[0]->type != VEX_VAL_STRING)
        return vval_error("tar-create: expected archive and files");

    const char *archive = vstr_data(&args[0]->string);
    VexStr cmd = vstr_new("tar -cf '");
    vstr_append_cstr(&cmd, archive);
    vstr_append_char(&cmd, '\'');

    for (size_t i = 1; i < argc; i++) {
        if (args[i]->type == VEX_VAL_STRING) {
            vstr_append_cstr(&cmd, " '");
            vstr_append_cstr(&cmd, vstr_data(&args[i]->string));
            vstr_append_char(&cmd, '\'');
        }
    }

    int r = system(vstr_data(&cmd));
    vstr_free(&cmd);
    return vval_int(WIFEXITED(r) ? WEXITSTATUS(r) : 1);
}

VexValue *builtin_path_home(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input; (void)args; (void)argc;
    const char *home = getenv("HOME");
    return home ? vval_string_cstr(home) : vval_null();
}

VexValue *builtin_env_remove(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_STRING)
        return vval_error("env-remove: expected variable name");
    const char *name = vstr_data(&args[0]->string);
    if (unsetenv(name) < 0) return vval_error("env-remove: failed");
    return vval_null();
}

VexValue *builtin_command_type(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 1 || args[0]->type != VEX_VAL_STRING)
        return vval_error("command-type: expected command name");
    const char *name = vstr_data(&args[0]->string);

    const char *alias_exp = alias_lookup(name);
    if (alias_exp) {
        VexValue *rec = vval_record();
        vval_record_set(rec, "name", vval_string_cstr(name));
        vval_record_set(rec, "type", vval_string_cstr("alias"));
        vval_record_set(rec, "value", vval_string_cstr(alias_exp));
        return rec;
    }

    if (builtin_exists(name)) {
        VexValue *rec = vval_record();
        vval_record_set(rec, "name", vval_string_cstr(name));
        vval_record_set(rec, "type", vval_string_cstr("builtin"));
        return rec;
    }

    VexValue *val = scope_get(ctx->current, name);
    if (val && val->type == VEX_VAL_CLOSURE) {
        VexValue *rec = vval_record();
        vval_record_set(rec, "name", vval_string_cstr(name));
        vval_record_set(rec, "type", vval_string_cstr("function"));
        return rec;
    }

    char *pathenv = getenv("PATH");
    if (pathenv) {
        char *paths = strdup(pathenv);
        char *dir = strtok(paths, ":");
        while (dir) {
            char full[4200];
            snprintf(full, sizeof(full), "%s/%s", dir, name);
            if (access(full, X_OK) == 0) {
                free(paths);
                VexValue *rec = vval_record();
                vval_record_set(rec, "name", vval_string_cstr(name));
                vval_record_set(rec, "type", vval_string_cstr("external"));
                vval_record_set(rec, "path", vval_string_cstr(full));
                return rec;
            }
            dir = strtok(NULL, ":");
        }
        free(paths);
    }

    return vval_null();
}

VexValue *builtin_pivot(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();

    if (input->type == VEX_VAL_RECORD) {
        VexValue *result = vval_list();
        VexMapIter it = vmap_iter(&input->record);
        const char *k; void *v;
        while (vmap_next(&it, &k, &v)) {
            VexValue *row = vval_record();
            vval_record_set(row, "column", vval_string_cstr(k));
            vval_record_set(row, "value", (VexValue *)v);
            vval_list_push(result, row);
            vval_release(row);
        }
        return result;
    }

    if (input->type != VEX_VAL_LIST) return vval_retain(input);
    if (vval_list_len(input) == 0) return vval_list();

    VexValue *first = vval_list_get(input, 0);
    if (first->type == VEX_VAL_RECORD) {
        VexValue *result = vval_list();
        VexMapIter it = vmap_iter(&first->record);
        const char *k; void *v;
        while (vmap_next(&it, &k, &v)) {
            VexValue *row = vval_record();
            vval_record_set(row, "column", vval_string_cstr(k));
            vval_record_set(row, "value", (VexValue *)v);
            vval_list_push(result, row);
            vval_release(row);
        }
        return result;
    }
    return vval_retain(input);
}

VexValue *builtin_merge_deep(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || input->type != VEX_VAL_RECORD || argc < 1 || args[0]->type != VEX_VAL_RECORD)
        return input ? vval_retain(input) : vval_null();

    VexValue *result = vval_record();

    VexMapIter it = vmap_iter(&input->record);
    const char *k; void *v;
    while (vmap_next(&it, &k, &v))
        vval_record_set(result, k, (VexValue *)v);

    it = vmap_iter(&args[0]->record);
    while (vmap_next(&it, &k, &v)) {
        VexValue *existing = vval_record_get(result, k);
        VexValue *incoming = (VexValue *)v;
        if (existing && existing->type == VEX_VAL_RECORD && incoming->type == VEX_VAL_RECORD) {
            VexValue *merge_args[] = { incoming };
            VexValue *merged = builtin_merge_deep(ctx, existing, merge_args, 1);
            vval_record_set(result, k, merged);
            vval_release(merged);
        } else {
            vval_record_set(result, k, incoming);
        }
    }
    return result;
}

VexValue *builtin_from_nuon(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING)
        return vval_error("from-nuon: expected string input");

    const char *src = vstr_data(&input->string);
    Parser p = parser_init(src, ctx->arena);
    ASTNode *node = parser_parse_line(&p);
    if (!node || p.had_error) return vval_error("from-nuon: parse error");
    return eval(ctx, node);
}

VexValue *builtin_split_words(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_STRING) return vval_list();
    const char *s = vstr_data(&input->string);
    VexValue *result = vval_list();
    const char *start = NULL;
    while (*s) {
        bool is_word = isalnum((unsigned char)*s) || *s == '_' || *s == '\'';
        if (is_word && !start) {
            start = s;
        } else if (!is_word && start) {
            char *word = strndup(start, (size_t)(s - start));
            vval_list_push(result, vval_string_cstr(word));
            free(word);
            start = NULL;
        }
        s++;
    }
    if (start) {
        vval_list_push(result, vval_string_cstr(start));
    }
    return result;
}

VexValue *builtin_math_deg_to_rad(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    double deg = 0;
    if (input->type == VEX_VAL_INT) deg = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) deg = input->floating;
    else return vval_error("math-deg-to-rad: expected number");
    return vval_float(deg * 3.14159265358979323846 / 180.0);
}

VexValue *builtin_math_rad_to_deg(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    double rad = 0;
    if (input->type == VEX_VAL_INT) rad = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) rad = input->floating;
    else return vval_error("math-rad-to-deg: expected number");
    return vval_float(rad * 180.0 / 3.14159265358979323846);
}

VexValue *builtin_into_binary(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input) return vval_null();
    if (input->type == VEX_VAL_INT) {
        int64_t n = input->integer;
        VexValue *result = vval_list();
        for (int i = 7; i >= 0; i--) {
            vval_list_push(result, vval_int((n >> (i * 8)) & 0xFF));
        }
        return result;
    }
    if (input->type == VEX_VAL_STRING) {
        const char *s = vstr_data(&input->string);
        size_t len = vstr_len(&input->string);
        VexValue *result = vval_list();
        for (size_t i = 0; i < len; i++) {
            vval_list_push(result, vval_int((unsigned char)s[i]));
        }
        return result;
    }
    return vval_error("into-binary: expected int or string");
}

VexValue *builtin_from_binary(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_LIST)
        return vval_error("from-binary: expected list of byte values");
    VexStr out = vstr_new("");
    for (size_t i = 0; i < vval_list_len(input); i++) {
        VexValue *b = vval_list_get(input, i);
        if (b->type == VEX_VAL_INT) {
            char c = (char)(b->integer & 0xFF);
            vstr_append_char(&out, c);
        }
    }
    VexValue *result = vval_string_cstr(vstr_data(&out));
    vstr_free(&out);
    return result;
}

VexValue *builtin_math_lerp(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || argc < 2) return vval_error("math-lerp: expected number | math-lerp <a> <b>");
    double t = 0;
    if (input->type == VEX_VAL_INT) t = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) t = input->floating;
    else return vval_error("math-lerp: expected number");
    double a = 0, b = 0;
    if (args[0]->type == VEX_VAL_INT) a = (double)args[0]->integer;
    else if (args[0]->type == VEX_VAL_FLOAT) a = args[0]->floating;
    if (args[1]->type == VEX_VAL_INT) b = (double)args[1]->integer;
    else if (args[1]->type == VEX_VAL_FLOAT) b = args[1]->floating;
    return vval_float(a + t * (b - a));
}

VexValue *builtin_math_map_range(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx;
    if (!input || argc < 4) return vval_error("math-map-range: expected num | math-map-range <in_min> <in_max> <out_min> <out_max>");
    double val = 0;
    if (input->type == VEX_VAL_INT) val = (double)input->integer;
    else if (input->type == VEX_VAL_FLOAT) val = input->floating;
    double in_min = 0, in_max = 0, out_min = 0, out_max = 0;
    for (int i = 0; i < 4; i++) {
        double *target = (i == 0) ? &in_min : (i == 1) ? &in_max : (i == 2) ? &out_min : &out_max;
        if (args[i]->type == VEX_VAL_INT) *target = (double)args[i]->integer;
        else if (args[i]->type == VEX_VAL_FLOAT) *target = args[i]->floating;
    }
    double ratio = (val - in_min) / (in_max - in_min);
    return vval_float(out_min + ratio * (out_max - out_min));
}

VexValue *builtin_record_to_list(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_RECORD)
        return vval_error("record-to-list: expected record input");
    VexValue *result = vval_list();
    VexMapIter it = vmap_iter(&input->record);
    const char *k; void *v;
    while (vmap_next(&it, &k, &v)) {
        VexValue *pair = vval_list();
        vval_list_push(pair, vval_string_cstr(k));
        vval_list_push(pair, (VexValue *)v);
        vval_list_push(result, pair);
        vval_release(pair);
    }
    return result;
}

VexValue *builtin_record_keys(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_RECORD) return vval_list();
    VexValue *result = vval_list();
    VexMapIter it = vmap_iter(&input->record);
    const char *k; void *v;
    while (vmap_next(&it, &k, &v)) {
        vval_list_push(result, vval_string_cstr(k));
    }
    return result;
}

VexValue *builtin_record_values(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)args; (void)argc;
    if (!input || input->type != VEX_VAL_RECORD) return vval_list();
    VexValue *result = vval_list();
    VexMapIter it = vmap_iter(&input->record);
    const char *k; void *v;
    while (vmap_next(&it, &k, &v)) {
        vval_list_push(result, (VexValue *)v);
    }
    return result;
}

VexValue *builtin_assert(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1) {
        vex_err("assert: expected condition");
        ctx->had_error = true;
        return vval_error("assert: expected condition");
    }
    if (!vval_truthy(args[0])) {
        const char *msg = "assertion failed";
        if (argc >= 2 && args[1]->type == VEX_VAL_STRING)
            msg = vstr_data(&args[1]->string);
        vex_err("assert: %s", msg);
        ctx->had_error = true;
        return vval_error("assertion failed");
    }
    return vval_null();
}

VexValue *builtin_shift(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    int n = 1;
    if (argc > 0 && args[0]->type == VEX_VAL_INT)
        n = (int)args[0]->integer;
    if (n < 1) return vval_null();

    VexValue *argv = scope_get(ctx->current, "argv");
    if (!argv) argv = scope_get(ctx->global, "argv");
    if (!argv || argv->type != VEX_VAL_LIST) return vval_null();

    VexValue *new_argv = vval_list();
    for (size_t i = (size_t)n; i < argv->list.len; i++)
        vval_list_push(new_argv, argv->list.data[i]);

    VexValue *new_argc = vval_int((int64_t)new_argv->list.len);
    scope_set(ctx->global, "argc", new_argc);
    vval_release(new_argc);

    for (size_t i = 0; i < new_argv->list.len && i < 20; i++) {
        char name[8];
        snprintf(name, sizeof(name), "%zu", i + 1);
        scope_set(ctx->global, name, new_argv->list.data[i]);
    }

    scope_set(ctx->global, "argv", new_argv);
    vval_release(new_argv);

    return vval_null();
}

VexValue *builtin_argparse(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)ctx; (void)input;
    if (argc < 2 || args[0]->type != VEX_VAL_RECORD || args[1]->type != VEX_VAL_LIST) {
        return vval_error("argparse: usage: argparse {name: type, ...} $argv");
    }

    VexValue *spec = args[0];
    VexValue *argv_list = args[1];
    VexValue *parsed = vval_record();
    VexValue *rest = vval_list();

    VexMapIter it = vmap_iter(&spec->record);
    const char *k; void *v;
    while (vmap_next(&it, &k, &v)) {
        VexValue *type_val = (VexValue *)v;
        if (type_val->type == VEX_VAL_STRING &&
            strcmp(vstr_data(&type_val->string), "bool") == 0) {
            VexValue *f = vval_bool(false);
            vval_record_set(parsed, k, f);
            vval_release(f);
        }
    }

    for (size_t i = 0; i < argv_list->list.len; i++) {
        VexValue *arg = argv_list->list.data[i];
        if (arg->type != VEX_VAL_STRING) {
            vval_list_push(rest, arg);
            continue;
        }
        const char *s = vstr_data(&arg->string);

        if (s[0] == '-' && s[1] == '-' && s[2] != '\0') {
            const char *name = s + 2;

            VexValue *type_val = vval_record_get(spec, name);
            if (!type_val) {
                vval_list_push(rest, arg);
                continue;
            }
            if (type_val->type == VEX_VAL_STRING &&
                strcmp(vstr_data(&type_val->string), "bool") == 0) {
                VexValue *t = vval_bool(true);
                vval_record_set(parsed, name, t);
                vval_release(t);
            } else if (i + 1 < argv_list->list.len) {
                i++;
                VexValue *val = argv_list->list.data[i];
                if (type_val->type == VEX_VAL_STRING &&
                    strcmp(vstr_data(&type_val->string), "int") == 0 &&
                    val->type == VEX_VAL_STRING) {
                    VexValue *iv = vval_int(strtol(vstr_data(&val->string), NULL, 10));
                    vval_record_set(parsed, name, iv);
                    vval_release(iv);
                } else {
                    vval_record_set(parsed, name, val);
                }
            }
        } else if (s[0] == '-' && s[1] != '-' && s[1] != '\0') {

            for (int j = 1; s[j]; j++) {
                char short_name[2] = { s[j], '\0' };
                VexValue *type_val = vval_record_get(spec, short_name);
                if (type_val) {
                    VexValue *t = vval_bool(true);
                    vval_record_set(parsed, short_name, t);
                    vval_release(t);
                }
            }
        } else {
            vval_list_push(rest, arg);
        }
    }

    VexValue *result = vval_record();
    vval_record_set(result, "args", parsed);
    vval_record_set(result, "rest", rest);
    vval_release(parsed);
    vval_release(rest);
    return result;
}

VexValue *builtin_ssh_exec(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 2) {
        return vval_error("ssh-exec: usage: ssh-exec <host> <command...>");
    }

    char **argv = malloc((argc + 2) * sizeof(char *));
    argv[0] = "ssh";
    for (size_t i = 0; i < argc; i++) {
        if (args[i]->type == VEX_VAL_STRING)
            argv[i + 1] = (char *)vstr_data(&args[i]->string);
        else
            argv[i + 1] = "";
    }
    argv[argc + 1] = NULL;

    VexValue *result = exec_external_capture("ssh", argv, STDIN_FILENO);
    free(argv);
    ctx->last_exit_code = 0;
    return result;
}

VexValue *builtin_scp_get(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1) {
        return vval_error("scp-get: usage: scp-get <host:path> [local-path]");
    }

    size_t n = 0;
    char *argv[8];
    argv[n++] = "scp";
    argv[n++] = "-r";
    if (args[0]->type == VEX_VAL_STRING)
        argv[n++] = (char *)vstr_data(&args[0]->string);
    if (argc > 1 && args[1]->type == VEX_VAL_STRING)
        argv[n++] = (char *)vstr_data(&args[1]->string);
    else
        argv[n++] = ".";
    argv[n] = NULL;

    int status = exec_external("scp", argv, -1, -1);
    ctx->last_exit_code = status;
    if (status != 0) return vval_error("scp-get: transfer failed");
    return vval_null();
}

VexValue *builtin_scp_put(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 2) {
        return vval_error("scp-put: usage: scp-put <local-path> <host:path>");
    }
    size_t n = 0;
    char *argv[8];
    argv[n++] = "scp";
    argv[n++] = "-r";
    if (args[0]->type == VEX_VAL_STRING)
        argv[n++] = (char *)vstr_data(&args[0]->string);
    if (args[1]->type == VEX_VAL_STRING)
        argv[n++] = (char *)vstr_data(&args[1]->string);
    argv[n] = NULL;

    int status = exec_external("scp", argv, -1, -1);
    ctx->last_exit_code = status;
    if (status != 0) return vval_error("scp-put: transfer failed");
    return vval_null();
}

VexValue *builtin_ssh_shell(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1) {
        return vval_error("ssh: usage: ssh <host> [command...]");
    }

    char **argv = malloc((argc + 2) * sizeof(char *));
    argv[0] = "ssh";
    for (size_t i = 0; i < argc; i++) {
        if (args[i]->type == VEX_VAL_STRING)
            argv[i + 1] = (char *)vstr_data(&args[i]->string);
        else
            argv[i + 1] = "";
    }
    argv[argc + 1] = NULL;

    int status = exec_external("ssh", argv, -1, -1);
    ctx->last_exit_code = status;
    free(argv);
    return vval_int(status);
}

static const char *pkg_dir(void) {
    static char path[PATH_MAX];
    const char *home = getenv("HOME");
    if (!home) return NULL;
    snprintf(path, sizeof(path), "%s/.local/share/vex/packages", home);
    return path;
}

static void ensure_pkg_dir(void) {
    const char *dir = pkg_dir();
    if (!dir) return;
    const char *home = getenv("HOME");
    if (!home) return;
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s/.local", home);
    mkdir(tmp, 0755);
    snprintf(tmp, sizeof(tmp), "%s/.local/share", home);
    mkdir(tmp, 0755);
    snprintf(tmp, sizeof(tmp), "%s/.local/share/vex", home);
    mkdir(tmp, 0755);
    mkdir(dir, 0755);
}

static const char *pkg_name_from_url(const char *url) {
    const char *last_slash = strrchr(url, '/');
    if (last_slash) url = last_slash + 1;
    static char name[256];
    strncpy(name, url, sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';

    size_t len = strlen(name);
    if (len > 4 && strcmp(name + len - 4, ".git") == 0)
        name[len - 4] = '\0';
    return name;
}

VexValue *builtin_pkg(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;
    if (argc < 1) {
        fprintf(stderr, "pkg: usage: pkg <install|remove|list|update|init|enable|disable> [args...]\n");
        return vval_error("pkg: missing subcommand");
    }
    if (args[0]->type != VEX_VAL_STRING) return vval_error("pkg: expected string subcommand");
    const char *subcmd = vstr_data(&args[0]->string);

    if (strcmp(subcmd, "install") == 0) {
        if (argc < 2 || args[1]->type != VEX_VAL_STRING) {
            return vval_error("pkg install: expected git URL or name");
        }
        const char *url = vstr_data(&args[1]->string);
        char expanded_url[1024];
        if (!strstr(url, "://")) {
            const char *slash = strchr(url, '/');
            if (slash && !strchr(slash + 1, '/')) {
                snprintf(expanded_url, sizeof(expanded_url),
                         "https://github.com/%s", url);
            } else if (!slash) {
                snprintf(expanded_url, sizeof(expanded_url),
                         "https://github.com/vex-shell/%s", url);
            } else {
                snprintf(expanded_url, sizeof(expanded_url), "%s", url);
            }
            url = expanded_url;
        }
        const char *name = (argc >= 3 && args[2]->type == VEX_VAL_STRING)
                           ? vstr_data(&args[2]->string)
                           : pkg_name_from_url(url);
        ensure_pkg_dir();
        char dest[PATH_MAX];
        snprintf(dest, sizeof(dest), "%s/%s", pkg_dir(), name);

        struct stat st;
        if (stat(dest, &st) == 0) {
            fprintf(stderr, "pkg: '%s' is already installed\n", name);
            return vval_error("package already installed");
        }

        char *argv[] = { "git", "clone", "--depth", "1", (char *)url, dest, NULL };
        int status = exec_external("git", argv, -1, -1);
        ctx->last_exit_code = status;
        if (status != 0) return vval_error("pkg install: git clone failed");

        char init_path[PATH_MAX];
        snprintf(init_path, sizeof(init_path), "%s/init.vex", dest);
        if (stat(init_path, &st) == 0) {
            fprintf(stderr, "pkg: installed '%s' — sourcing init.vex\n", name);

            VexValue *path_arg = vval_string_cstr(init_path);
            VexValue *r = builtin_source(ctx, NULL, &path_arg, 1);
            vval_release(path_arg);
            vval_release(r);
        } else {
            fprintf(stderr, "pkg: installed '%s' (no init.vex found)\n", name);
        }
        return vval_string_cstr(name);

    } else if (strcmp(subcmd, "remove") == 0) {
        if (argc < 2 || args[1]->type != VEX_VAL_STRING) {
            return vval_error("pkg remove: expected package name");
        }
        const char *name = vstr_data(&args[1]->string);
        char dest[PATH_MAX];
        snprintf(dest, sizeof(dest), "%s/%s", pkg_dir(), name);

        struct stat st;
        if (stat(dest, &st) != 0) {
            return vval_error("pkg remove: package not found");
        }

        char *argv[] = { "rm", "-rf", dest, NULL };
        int status = exec_external("rm", argv, -1, -1);
        ctx->last_exit_code = status;
        if (status == 0) fprintf(stderr, "pkg: removed '%s'\n", name);
        return vval_null();

    } else if (strcmp(subcmd, "list") == 0) {
        const char *dir = pkg_dir();
        VexValue *list = vval_list();
        if (!dir) return list;

        DIR *d = opendir(dir);
        if (!d) return list;

        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char full[PATH_MAX];
            snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
            struct stat st;
            if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

            VexValue *rec = vval_record();
            vval_record_set(rec, "name", vval_string_cstr(ent->d_name));
            vval_record_set(rec, "path", vval_string_cstr(full));

            char init_path[PATH_MAX];
            snprintf(init_path, sizeof(init_path), "%s/init.vex", full);
            VexValue *has_init = vval_bool(stat(init_path, &st) == 0);
            vval_record_set(rec, "has_init", has_init);
            vval_release(has_init);

            char pkg_path[PATH_MAX];
            snprintf(pkg_path, sizeof(pkg_path), "%s/package.vex", full);
            FILE *pkg_fp = fopen(pkg_path, "r");
            if (pkg_fp) {
                char pkg_buf[4096];
                size_t pkg_len = fread(pkg_buf, 1, sizeof(pkg_buf) - 1, pkg_fp);
                fclose(pkg_fp);
                pkg_buf[pkg_len] = '\0';

                const char *keys[] = { "version", "description", "author" };
                for (int ki = 0; ki < 3; ki++) {
                    char needle[64];
                    snprintf(needle, sizeof(needle), "%s:", keys[ki]);
                    char *pos = strstr(pkg_buf, needle);
                    if (!pos) {
                        snprintf(needle, sizeof(needle), "%s :", keys[ki]);
                        pos = strstr(pkg_buf, needle);
                    }
                    if (pos) {
                        char *q1 = strchr(pos + strlen(needle), '"');
                        if (q1) {
                            char *q2 = strchr(q1 + 1, '"');
                            if (q2) {
                                size_t vlen = (size_t)(q2 - q1 - 1);
                                char val[512];
                                if (vlen >= sizeof(val)) vlen = sizeof(val) - 1;
                                memcpy(val, q1 + 1, vlen);
                                val[vlen] = '\0';
                                vval_record_set(rec, keys[ki], vval_string_cstr(val));
                            }
                        }
                    }
                }
            }

            vval_list_push(list, rec);
            vval_release(rec);
        }
        closedir(d);
        return list;

    } else if (strcmp(subcmd, "update") == 0) {
        const char *dir = pkg_dir();
        if (!dir) return vval_error("pkg: no package directory");

        if (argc >= 2 && args[1]->type == VEX_VAL_STRING) {

            const char *name = vstr_data(&args[1]->string);
            char dest[PATH_MAX];
            snprintf(dest, sizeof(dest), "%s/%s", dir, name);
            char cmd[PATH_MAX + 32];
            snprintf(cmd, sizeof(cmd), "cd '%s' && git pull", dest);
            int status = system(cmd);
            ctx->last_exit_code = WEXITSTATUS(status);
        } else {

            DIR *d = opendir(dir);
            if (!d) return vval_null();
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (ent->d_name[0] == '.') continue;
                char full[PATH_MAX];
                snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
                struct stat st;
                if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
                fprintf(stderr, "pkg: updating '%s'...\n", ent->d_name);
                char cmd[PATH_MAX + 32];
                snprintf(cmd, sizeof(cmd), "cd '%s' && git pull", full);
                system(cmd);
            }
            closedir(d);
        }
        return vval_null();

    } else if (strcmp(subcmd, "init") == 0) {

        char *cwd = getcwd(NULL, 0);
        if (!cwd) { fprintf(stderr, "pkg init: cannot get cwd\n"); return vval_null(); }
        const char *name = strrchr(cwd, '/');
        name = name ? name + 1 : cwd;

        FILE *f = fopen("init.vex", "w");
        if (f) {
            fprintf(f, "# %s — Vex package\n", name);
            fprintf(f, "# This file is sourced when the package is loaded.\n\n");
            fprintf(f, "# Define functions, aliases, completions, etc. here.\n");
            fclose(f);
        }

        f = fopen("package.vex", "w");
        if (f) {
            fprintf(f, "# Package metadata\n");
            fprintf(f, "let package = {\n");
            fprintf(f, "  name: \"%s\"\n", name);
            fprintf(f, "  version: \"0.1.0\"\n");
            fprintf(f, "  description: \"A Vex package\"\n");
            fprintf(f, "  author: \"\"\n");
            fprintf(f, "}\n");
            fclose(f);
        }

        free((void *)cwd);
        fprintf(stderr, "pkg: created init.vex and package.vex\n");
        return vval_null();

    } else if (strcmp(subcmd, "enable") == 0) {
        if (argc < 2 || args[1]->type != VEX_VAL_STRING)
            return vval_error("pkg enable: expected plugin name");
        const char *name = vstr_data(&args[1]->string);
        const char *home = getenv("HOME");
        if (!home) return vval_error("pkg enable: HOME not set");

        char conf_dir[PATH_MAX];
        snprintf(conf_dir, sizeof(conf_dir), "%s/.config/vex", home);
        mkdir(conf_dir, 0755);

        char conf_path[PATH_MAX];
        snprintf(conf_path, sizeof(conf_path), "%s/plugins.vex", conf_dir);

        FILE *f = fopen(conf_path, "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                size_t len = strlen(line);
                while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                    line[--len] = '\0';
                if (strcmp(line, name) == 0) {
                    fclose(f);
                    fprintf(stderr, "pkg: '%s' is already enabled\n", name);
                    return vval_null();
                }
            }
            fclose(f);
        }

        f = fopen(conf_path, "a");
        if (!f) return vval_error("pkg enable: cannot open plugins.vex");
        fprintf(f, "%s\n", name);
        fclose(f);
        fprintf(stderr, "pkg: enabled '%s'\n", name);
        return vval_null();

    } else if (strcmp(subcmd, "disable") == 0) {
        if (argc < 2 || args[1]->type != VEX_VAL_STRING)
            return vval_error("pkg disable: expected plugin name");
        const char *name = vstr_data(&args[1]->string);
        const char *home = getenv("HOME");
        if (!home) return vval_error("pkg disable: HOME not set");

        char conf_path[PATH_MAX];
        snprintf(conf_path, sizeof(conf_path), "%s/.config/vex/plugins.vex", home);

        FILE *f = fopen(conf_path, "r");
        if (!f) return vval_error("pkg disable: plugins.vex not found");

        char lines[256][256];
        int count = 0;
        bool found = false;
        char line[256];
        while (fgets(line, sizeof(line), f) && count < 256) {
            size_t len = strlen(line);
            while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                line[--len] = '\0';
            if (strcmp(line, name) == 0) {
                found = true;
                continue;
            }
            strncpy(lines[count], line, sizeof(lines[count]) - 1);
            lines[count][sizeof(lines[count]) - 1] = '\0';
            count++;
        }
        fclose(f);

        if (!found) {
            fprintf(stderr, "pkg: '%s' is not enabled\n", name);
            return vval_null();
        }

        f = fopen(conf_path, "w");
        if (!f) return vval_error("pkg disable: cannot write plugins.vex");
        for (int i = 0; i < count; i++) {
            fprintf(f, "%s\n", lines[i]);
        }
        fclose(f);
        fprintf(stderr, "pkg: disabled '%s'\n", name);
        return vval_null();
    }

    return vval_error("pkg: unknown subcommand (install|remove|list|update|init|enable|disable)");
}

void pkg_autoload(EvalCtx *ctx) {
    const char *home = getenv("HOME");
    if (!home) return;

    char plugins_dir[PATH_MAX];
    snprintf(plugins_dir, sizeof(plugins_dir), "%s/.config/vex/plugins", home);

    DIR *d = opendir(plugins_dir);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char init_path[PATH_MAX];
        snprintf(init_path, sizeof(init_path), "%s/%s/init.vex",
                 plugins_dir, ent->d_name);
        struct stat st;
        if (stat(init_path, &st) == 0) {
            VexValue *path_arg = vval_string_cstr(init_path);
            VexValue *r = builtin_source(ctx, NULL, &path_arg, 1);
            vval_release(path_arg);
            vval_release(r);
            ctx->had_error = false;
            continue;
        }

        snprintf(init_path, sizeof(init_path), "%s/%s",
                 plugins_dir, ent->d_name);
        size_t nlen = strlen(ent->d_name);
        if (nlen > 4 && strcmp(ent->d_name + nlen - 4, ".vex") == 0) {
            if (stat(init_path, &st) == 0) {
                VexValue *path_arg = vval_string_cstr(init_path);
                VexValue *r = builtin_source(ctx, NULL, &path_arg, 1);
                vval_release(path_arg);
                vval_release(r);
                ctx->had_error = false;
            }
        }
    }
    closedir(d);
}

static bool is_sh_file(const char *path) {
    size_t len = strlen(path);
    if (len > 3 && strcmp(path + len - 3, ".sh") == 0) return true;
    if (len > 5 && strcmp(path + len - 5, ".bash") == 0) return true;
    return false;
}

static bool has_sh_shebang(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char line[256];
    bool result = false;
    if (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "#!/bin/sh", 9) == 0 ||
            strncmp(line, "#!/bin/bash", 11) == 0 ||
            strncmp(line, "#!/usr/bin/env sh", 17) == 0 ||
            strncmp(line, "#!/usr/bin/env bash", 19) == 0)
            result = true;
    }
    fclose(f);
    return result;
}

VexValue *source_sh_file(EvalCtx *ctx, const char *path) {

    char cmd[PATH_MAX + 64];
    snprintf(cmd, sizeof(cmd), ". '%s' && env -0", path);
    char *argv[] = { "bash", "-c", cmd, NULL };

    VexValue *output = exec_external_capture("bash", argv, STDIN_FILENO);
    if (!output || output->type != VEX_VAL_STRING) {
        if (output) vval_release(output);

        char *argv2[] = { "bash", (char *)path, NULL };
        int status = exec_external("bash", argv2, -1, -1);
        ctx->last_exit_code = status;
        return vval_null();
    }

    const char *s = vstr_data(&output->string);
    size_t len = vstr_len(&output->string);
    const char *p = s;

    while (p < s + len) {
        const char *eq = strchr(p, '=');
        if (!eq) break;
        size_t key_len = (size_t)(eq - p);
        char *key = strndup(p, key_len);
        const char *val_start = eq + 1;

        const char *end = memchr(val_start, '\0', (size_t)((s + len) - val_start));
        if (!end) end = s + len;

        size_t val_len = (size_t)(end - val_start);
        char *val = strndup(val_start, val_len);
        setenv(key, val, 1);

        VexValue *v = vval_string_cstr(val);
        scope_set(ctx->global, key, v);
        vval_release(v);

        free(key);
        free(val);
        p = end + 1;
    }

    vval_release(output);
    return vval_null();
}

bool vex_is_sh_script(const char *path) {
    return is_sh_file(path) || has_sh_shebang(path);
}

int vex_run_sh_script(const char *path, int script_argc, char **script_argv) {
    char **argv = malloc(((size_t)script_argc + 3) * sizeof(char *));
    argv[0] = "bash";
    argv[1] = (char *)path;
    for (int i = 0; i < script_argc; i++)
        argv[i + 2] = script_argv[i];
    argv[script_argc + 2] = NULL;

    int status = exec_external("bash", argv, -1, -1);
    free(argv);
    return status;
}

static struct { const char *name; const char *desc; const char *prompt; const char *rprompt; } builtin_themes[] = {
    { "minimal",      "clean, no color, just arrows",
      "%D > ", "" },
    { "powerline",    "rich info: user@host, git, duration, jobs",
      "%{bold,green}%n%{reset}@%{cyan}%h%{reset} %{bold,blue}%d%{reset}"
      " %{purple}%g%{red}%G%{reset}"
      " %{dim}%E%{reset}"
      " %{yellow}%j%{reset}"
      "%{red}%e%{reset}\n%{bold}%#%{reset} ",
      "%{dim}%T%{reset}" },
    { "lambda",       "λ prompt with exit code coloring",
      "%{bold,blue}%d%{reset} %{purple}%g%{red}%G%{reset} %{bold,magenta}λ%{reset} ",
      "%{dim}%t%{reset}" },
    { "pure",         "clean two-line prompt (inspired by sindresorhus/pure)",
      "%{bold,blue}%d%{reset} %{dim}%g%{reset} %{red}%G%{reset} %{yellow}%E%{reset}\n%{magenta}❯%{reset} ",
      "" },
    { "robbyrussell", "classic oh-my-zsh default theme",
      "%{bold,green}➜%{reset} %{cyan}%D%{reset} %{red}(%g%G)%{reset} ",
      "" },
    { NULL, NULL, NULL, NULL }
};

static bool load_theme_file(EvalCtx *ctx, const char *name) {
    const char *home = getenv("HOME");
    if (!home) return false;

    char path[PATH_MAX];
    struct stat st;

    snprintf(path, sizeof(path), "%s/.config/vex/themes/%s.vex", home, name);
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        VexValue *arg = vval_string_cstr(path);
        VexValue *r = builtin_source(ctx, NULL, &arg, 1);
        vval_release(arg);
        vval_release(r);
        return true;
    }

    snprintf(path, sizeof(path), "%s/.local/share/vex/packages/%s/theme.vex", home, name);
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        VexValue *arg = vval_string_cstr(path);
        VexValue *r = builtin_source(ctx, NULL, &arg, 1);
        vval_release(arg);
        vval_release(r);
        return true;
    }

    snprintf(path, sizeof(path), "%s/.local/share/vex/packages/vex-%s/theme.vex", home, name);
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
        VexValue *arg = vval_string_cstr(path);
        VexValue *r = builtin_source(ctx, NULL, &arg, 1);
        vval_release(arg);
        vval_release(r);
        return true;
    }

    return false;
}

static VexValue *list_all_themes(void) {
    VexValue *list = vval_list();

    {
        VexValue *rec = vval_record();
        vval_record_set(rec, "name", vval_string_cstr("default"));
        vval_record_set(rec, "description", vval_string_cstr("blue path, purple git, yellow prompt"));
        vval_record_set(rec, "source", vval_string_cstr("builtin"));
        vval_list_push(list, rec);
        vval_release(rec);
    }

    for (int i = 0; builtin_themes[i].name; i++) {
        VexValue *rec = vval_record();
        vval_record_set(rec, "name", vval_string_cstr(builtin_themes[i].name));
        vval_record_set(rec, "description", vval_string_cstr(builtin_themes[i].desc));
        vval_record_set(rec, "source", vval_string_cstr("builtin"));
        vval_list_push(list, rec);
        vval_release(rec);
    }

    const char *home = getenv("HOME");
    if (!home) return list;

    char dir_path[PATH_MAX];
    snprintf(dir_path, sizeof(dir_path), "%s/.config/vex/themes", home);
    DIR *d = opendir(dir_path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            size_t nlen = strlen(ent->d_name);
            if (nlen > 4 && nlen - 4 < 256 &&
                strcmp(ent->d_name + nlen - 4, ".vex") == 0) {
                char tname[256];
                size_t stem = nlen - 4;
                memcpy(tname, ent->d_name, stem);
                tname[stem] = '\0';

                VexValue *rec = vval_record();
                vval_record_set(rec, "name", vval_string_cstr(tname));
                char full[PATH_MAX];
                snprintf(full, sizeof(full), "%s/%s", dir_path, ent->d_name);
                vval_record_set(rec, "description", vval_string_cstr(full));
                vval_record_set(rec, "source", vval_string_cstr("user"));
                vval_list_push(list, rec);
                vval_release(rec);
            }
        }
        closedir(d);
    }

    snprintf(dir_path, sizeof(dir_path), "%s/.local/share/vex/packages", home);
    d = opendir(dir_path);
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            char theme_path[PATH_MAX];
            snprintf(theme_path, sizeof(theme_path), "%s/%s/theme.vex", dir_path, ent->d_name);
            struct stat st;
            if (stat(theme_path, &st) == 0 && S_ISREG(st.st_mode)) {
                VexValue *rec = vval_record();
                vval_record_set(rec, "name", vval_string_cstr(ent->d_name));
                vval_record_set(rec, "description", vval_string_cstr(theme_path));
                vval_record_set(rec, "source", vval_string_cstr("package"));
                vval_list_push(list, rec);
                vval_release(rec);
            }
        }
        closedir(d);
    }

    return list;
}

static void print_theme_list(VexValue *list) {
    size_t len = vval_list_len(list);
    for (size_t i = 0; i < len; i++) {
        VexValue *rec = vval_list_get(list, i);
        VexValue *name = vval_record_get(rec, "name");
        VexValue *desc = vval_record_get(rec, "description");
        VexValue *src = vval_record_get(rec, "source");
        printf("  \033[1;36m%-16s\033[0m \033[90m%-8s\033[0m %s\n",
               name ? vstr_data(&name->string) : "?",
               src ? vstr_data(&src->string) : "",
               desc ? vstr_data(&desc->string) : "");
    }
}

VexValue *builtin_theme(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;

    if (argc < 1 || args[0]->type != VEX_VAL_STRING) {
        VexValue *list = list_all_themes();
        if (!ctx->in_pipeline) print_theme_list(list);
        return ctx->in_pipeline ? list : vval_null();
    }

    const char *name = vstr_data(&args[0]->string);

    if (strcmp(name, "list") == 0) {
        VexValue *list = list_all_themes();
        if (!ctx->in_pipeline) print_theme_list(list);
        return ctx->in_pipeline ? list : vval_null();
    }

    if (strcmp(name, "save") == 0) {
        if (argc < 2 || args[1]->type != VEX_VAL_STRING) {
            return vval_error("theme save: expected theme name");
        }
        const char *tname = vstr_data(&args[1]->string);
        const char *home = getenv("HOME");
        if (!home) return vval_error("theme save: $HOME not set");

        char dir_path[PATH_MAX];
        snprintf(dir_path, sizeof(dir_path), "%s/.config/vex", home);
        mkdir(dir_path, 0755);
        snprintf(dir_path, sizeof(dir_path), "%s/.config/vex/themes", home);
        mkdir(dir_path, 0755);

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s.vex", dir_path, tname);

        FILE *f = fopen(path, "w");
        if (!f) return vval_error("theme save: cannot create file");

        fprintf(f, "# Vex theme: %s\n\n", tname);

        const char *prompt = getenv("VEX_PROMPT");
        const char *rprompt = getenv("VEX_RPROMPT");
        if (prompt) fprintf(f, "export VEX_PROMPT \"%s\"\n", prompt);
        if (rprompt) fprintf(f, "export VEX_RPROMPT \"%s\"\n", rprompt);

        const char *color_vars[] = {
            "VEX_COLOR_KEYWORD", "VEX_COLOR_BUILTIN", "VEX_COLOR_STRING",
            "VEX_COLOR_NUMBER", "VEX_COLOR_OPERATOR", "VEX_COLOR_COMMENT",
            "VEX_COLOR_BOOL", "VEX_COLOR_PIPE", "VEX_COLOR_CARET",
            "VEX_COLOR_ERROR", NULL
        };
        for (int i = 0; color_vars[i]; i++) {
            const char *val = getenv(color_vars[i]);
            if (val) fprintf(f, "export %s \"%s\"\n", color_vars[i], val);
        }

        fclose(f);
        fprintf(stderr, "theme: saved to %s\n", path);
        return vval_string_cstr(path);
    }

    if (strcmp(name, "create") == 0) {
        if (argc < 2 || args[1]->type != VEX_VAL_STRING) {
            return vval_error("theme create: expected theme name");
        }
        const char *tname = vstr_data(&args[1]->string);
        const char *home = getenv("HOME");
        if (!home) return vval_error("theme create: $HOME not set");

        char dir_path[PATH_MAX];
        snprintf(dir_path, sizeof(dir_path), "%s/.config/vex", home);
        mkdir(dir_path, 0755);
        snprintf(dir_path, sizeof(dir_path), "%s/.config/vex/themes", home);
        mkdir(dir_path, 0755);

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s.vex", dir_path, tname);

        struct stat st;
        if (stat(path, &st) == 0) {
            fprintf(stderr, "theme: '%s' already exists at %s\n", tname, path);
            return vval_error("theme already exists");
        }

        FILE *f = fopen(path, "w");
        if (!f) return vval_error("theme create: cannot create file");

        fprintf(f, "# Vex theme: %s\n", tname);
        fprintf(f, "#\n");
        fprintf(f, "# Prompt format specifiers:\n");
        fprintf(f, "#   %%d — full path (~-collapsed)    %%D — directory basename\n");
        fprintf(f, "#   %%g — git branch                 %%G — git status (+*?)\n");
        fprintf(f, "#   %%n — username                   %%h — hostname\n");
        fprintf(f, "#   %%t — time HH:MM                 %%T — time HH:MM:SS\n");
        fprintf(f, "#   %%e — exit code (if non-zero)    %%E — command duration\n");
        fprintf(f, "#   %%j — background jobs count      %%# — $ or # (root)\n");
        fprintf(f, "#   %%%%  — literal %%\n");
        fprintf(f, "#\n");
        fprintf(f, "# Colors: %%{red}, %%{bold,blue}, %%{bg_green,white}, %%{reset}\n");
        fprintf(f, "#   Styles: bold dim italic underline reverse reset\n");
        fprintf(f, "#   Colors: black red green yellow blue magenta/purple cyan white\n");
        fprintf(f, "#   Bright: bright_red bright_green bright_yellow bright_blue ...\n");
        fprintf(f, "#   Backgrounds: bg_red bg_green bg_yellow bg_blue ...\n");
        fprintf(f, "#\n");
        fprintf(f, "# You can also use prompt-fn and rprompt-fn for dynamic prompts:\n");
        fprintf(f, "#   prompt-fn { || \"my prompt> \" }\n");
        fprintf(f, "#\n\n");
        fprintf(f, "export VEX_PROMPT \"%%{bold,blue}%%d%%{reset} %%{bold,yellow}vex%%{reset}> \"\n");
        fprintf(f, "export VEX_RPROMPT \"%%{dim}%%t%%{reset}\"\n");
        fprintf(f, "\n# Syntax highlighting (SGR codes, e.g. \"1;35\" = bold magenta)\n");
        fprintf(f, "# export VEX_COLOR_KEYWORD \"1;35\"\n");
        fprintf(f, "# export VEX_COLOR_BUILTIN \"1;36\"\n");
        fprintf(f, "# export VEX_COLOR_STRING \"0;32\"\n");
        fprintf(f, "# export VEX_COLOR_NUMBER \"0;33\"\n");
        fprintf(f, "# export VEX_COLOR_ERROR \"1;31\"\n");

        fclose(f);
        fprintf(stderr, "theme: created %s\n", path);
        fprintf(stderr, "Edit the file, then activate with: theme %s\n", tname);
        return vval_string_cstr(path);
    }

    if (strcmp(name, "default") == 0) {
        unsetenv("VEX_PROMPT");
        unsetenv("VEX_RPROMPT");
        return vval_null();
    }

    for (int i = 0; builtin_themes[i].name; i++) {
        if (strcmp(name, builtin_themes[i].name) == 0) {
            setenv("VEX_PROMPT", builtin_themes[i].prompt, 1);
            setenv("VEX_RPROMPT", builtin_themes[i].rprompt, 1);
            return vval_null();
        }
    }

    if (load_theme_file(ctx, name)) {
        return vval_null();
    }

    fprintf(stderr, "theme: '%s' not found\n", name);
    fprintf(stderr, "  Try: theme list           — see available themes\n");
    fprintf(stderr, "       theme create %s  — create a new theme\n", name);
    fprintf(stderr, "       pkg install <url>    — install a theme package\n");
    return vval_error("theme not found");
}

static VexValue *trash_items_to_list(TrashItem *items, size_t n) {
    VexValue *list = vval_list();
    for (size_t i = 0; i < n; i++) {
        VexValue *rec = vval_record();
        vval_record_set(rec, "name", vval_string_cstr(items[i].name));
        vval_record_set(rec, "path", vval_string_cstr(items[i].full_path));
        vval_record_set(rec, "deleted_at", vval_int(items[i].deleted_at));
        vval_record_set(rec, "size", vval_int(items[i].size));
        vval_record_set(rec, "is_dir", vval_bool(items[i].is_dir));
        vval_list_push(list, rec);
    }
    return list;
}

static void print_trash_list(TrashItem *items, size_t n) {
    if (n == 0) { printf("trash is empty\n"); return; }
    time_t now = time(NULL);
    for (size_t i = 0; i < n; i++) {
        long age = (long)(now - items[i].deleted_at);
        char age_buf[32];
        if (age < 60) snprintf(age_buf, sizeof(age_buf), "%lds ago", age);
        else if (age < 3600) snprintf(age_buf, sizeof(age_buf), "%ldm ago", age / 60);
        else if (age < 86400) snprintf(age_buf, sizeof(age_buf), "%ldh ago", age / 3600);
        else snprintf(age_buf, sizeof(age_buf), "%ldd ago", age / 86400);
        printf("  %s%s  %lld B  %s\n",
               items[i].name, items[i].is_dir ? "/" : "",
               (long long)items[i].size, age_buf);
    }
}

VexValue *builtin_trash(EvalCtx *ctx, VexValue *input, VexValue **args, size_t argc) {
    (void)input;

    const char *sub = "list";
    if (argc >= 1 && args[0]->type == VEX_VAL_STRING) {
        sub = vstr_data(&args[0]->string);
    }

    if (strcmp(sub, "list") == 0) {
        TrashItem *items = NULL;
        size_t n = undo_list_trash(&items);
        if (ctx->in_pipeline) {
            VexValue *out = trash_items_to_list(items, n);
            undo_free_trash_list(items, n);
            return out;
        }
        print_trash_list(items, n);
        undo_free_trash_list(items, n);
        return vval_null();
    }

    if (strcmp(sub, "empty") == 0) {
        size_t removed = undo_empty_trash();
        if (!ctx->in_pipeline) {
            printf("emptied trash (%zu item%s)\n", removed, removed == 1 ? "" : "s");
        }
        return vval_int((int64_t)removed);
    }

    if (strcmp(sub, "purge") == 0) {
        long days = 7;
        if (argc >= 2) {
            if (args[1]->type == VEX_VAL_INT) {
                days = (long)args[1]->integer;
            } else if (args[1]->type == VEX_VAL_STRING) {
                char *end = NULL;
                long parsed = strtol(vstr_data(&args[1]->string), &end, 10);
                if (end && *end == '\0') days = parsed;
            }
            if (days < 0) days = 0;
        }
        time_t cutoff = time(NULL) - days * 86400;
        size_t removed = undo_purge_trash(cutoff);
        if (!ctx->in_pipeline) {
            printf("purged %zu item%s older than %ld day%s\n",
                   removed, removed == 1 ? "" : "s",
                   days, days == 1 ? "" : "s");
        }
        return vval_int((int64_t)removed);
    }

    fprintf(stderr, "trash: unknown subcommand '%s'\n", sub);
    fprintf(stderr, "usage: trash [list|empty|purge [days]]\n");
    return vval_error("unknown trash subcommand");
}

void builtins_init(void) {
    register_builtin("echo",    builtin_echo,    "echo [args...]",       "Print arguments");
    register_builtin("cd",      builtin_cd,      "cd [dir]",             "Change directory");
    register_builtin("exit",    builtin_exit,     "exit [code]",          "Exit the shell");
    register_builtin("pwd",     builtin_pwd,      "pwd",                  "Print working directory");
    register_builtin("env",     builtin_env,      "env",                  "Show environment variables");
    register_builtin("ls",      builtin_ls,       "ls [path]",            "List directory contents (structured)");
    register_builtin("which",   builtin_which,    "which <name>",         "Find command location");
    register_builtin("type",    builtin_type_cmd, "type <value>",         "Show type of a value");
    register_builtin("where",   builtin_where,    "where <condition>",    "Filter list/table rows");
    register_builtin("first",   builtin_first,    "first [n]",            "Take first n items");
    register_builtin("last",    builtin_last,     "last [n]",             "Take last n items");
    register_builtin("get",     builtin_get,      "get <field>",          "Extract field/column");
    register_builtin("sort-by", builtin_sort_by,  "sort-by <field>",      "Sort by field");
    register_builtin("each",    builtin_each,     "each <closure>",       "Map over items");
    register_builtin("lines",   builtin_lines,    "lines",                "Split string into lines");
    register_builtin("select",  builtin_select,   "select <fields...>",   "Project specific columns");
    register_builtin("reject",  builtin_reject,   "reject <fields...>",   "Remove specific columns");
    register_builtin("length",  builtin_length,   "length",               "Length of list or string");
    register_builtin("reverse", builtin_reverse,  "reverse",              "Reverse a list");
    register_builtin("flatten", builtin_flatten,   "flatten",              "Flatten one level of nesting");
    register_builtin("uniq",    builtin_uniq,     "uniq",                 "Remove consecutive duplicates");
    register_builtin("enumerate", builtin_enumerate, "enumerate",         "Add index to each item");
    register_builtin("skip",    builtin_skip,     "skip [n]",             "Skip first n items");
    register_builtin("reduce",  builtin_reduce,   "reduce <init> <fn>",   "Fold list with closure");
    register_builtin("to-text", builtin_to_text,  "to-text",              "Convert to plain text");
    register_builtin("str-join", builtin_str_join, "str-join [sep]",      "Join list with separator");
    register_builtin("str-split", builtin_str_split, "str-split [sep]",   "Split string by separator");
    register_builtin("str-trim", builtin_str_trim, "str-trim",            "Trim whitespace");
    register_builtin("str-replace", builtin_str_replace, "str-replace <find> <repl>", "Replace in string");
    register_builtin("help",    builtin_help,     "help",                 "Show this help");

    register_builtin("from-json", builtin_from_json, "from-json",          "Parse JSON string");
    register_builtin("to-json",   builtin_to_json,   "to-json",            "Serialize to JSON");
    register_builtin("from-csv",  builtin_from_csv,  "from-csv",           "Parse CSV string");
    register_builtin("to-csv",    builtin_to_csv,    "to-csv",             "Serialize to CSV");
    register_builtin("from-toml", builtin_from_toml, "from-toml",          "Parse TOML string");
    register_builtin("to-toml",   builtin_to_toml,   "to-toml",            "Serialize to TOML");

    register_builtin("open",     builtin_open,     "open <path>",          "Open file (auto-detect format)");
    register_builtin("save",     builtin_save,     "save <path>",          "Save data to file");
    register_builtin("glob",     builtin_glob,     "glob <pattern>",       "Match file patterns");

    register_builtin("str-contains",   builtin_str_contains,   "str-contains <substr>",   "Check if string contains substring");
    register_builtin("str-length",     builtin_str_length,     "str-length",              "String length in characters");
    register_builtin("str-downcase",   builtin_str_downcase,   "str-downcase",            "Convert to lowercase");
    register_builtin("str-upcase",     builtin_str_upcase,     "str-upcase",              "Convert to uppercase");
    register_builtin("str-starts-with", builtin_str_starts_with, "str-starts-with <pre>", "Check prefix");
    register_builtin("str-ends-with",  builtin_str_ends_with,  "str-ends-with <suf>",     "Check suffix");

    register_builtin("math-sum",   builtin_math_sum,   "math-sum",         "Sum of list");
    register_builtin("math-avg",   builtin_math_avg,   "math-avg",         "Average of list");
    register_builtin("math-min",   builtin_math_min,   "math-min",         "Minimum of list");
    register_builtin("math-max",   builtin_math_max,   "math-max",         "Maximum of list");
    register_builtin("math-abs",   builtin_math_abs,   "math-abs",         "Absolute value");
    register_builtin("math-round", builtin_math_round, "math-round",       "Round to integer");

    register_builtin("j",   builtin_j,  "j <terms...>",                    "Frecency jump to directory");
    register_builtin("ji",  builtin_ji, "ji",                              "Interactive frecency jump");

    register_builtin("filter", builtin_filter, "filter [--multi]",         "Interactive fuzzy filter");

    register_builtin("jobs",   builtin_jobs,     "jobs",                    "List active jobs");
    register_builtin("fg",     builtin_fg,       "fg [job-id]",             "Bring job to foreground");
    register_builtin("bg",     builtin_bg,       "bg [job-id]",             "Continue job in background");
    register_builtin("kill",   builtin_kill,     "kill <job-id> [signal]",  "Send signal to job");
    register_builtin("wait",   builtin_wait_cmd, "wait [job-id]",           "Wait for background job(s)");

    register_builtin("ps",     builtin_ps,       "ps",                      "List processes (structured)");

    register_builtin("set",    builtin_set,      "set [-exuC] [-o opt] [vi|emacs]", "Set shell options");
    register_builtin("export", builtin_export,   "export <key> <value>",    "Set environment variable");
    register_builtin("source", builtin_source,   "source <path>",           "Execute a vex script file");
    register_builtin(".", builtin_source,        ". <path>",                "Execute a vex script file (alias for source)");
    register_builtin("alias",  builtin_alias,    "alias <name> <command>",  "Define a command alias");
    register_builtin("abbr",   builtin_abbr,     "abbr add|remove|list [name] [expansion]", "Manage abbreviations (add, remove, list)");
    register_builtin("complete", builtin_complete, "complete files|dirs|commands|words <words> <cmd>", "Define tab completions for a command");
    register_builtin("complete-fn", builtin_complete_fn, "complete-fn <command> <closure>", "Register a dynamic completion callback for a command");

    register_builtin("pushd",  builtin_pushd,  "pushd [dir]",  "Push directory onto stack and cd");
    register_builtin("popd",   builtin_popd,   "popd",         "Pop directory from stack and cd");
    register_builtin("dirs",   builtin_dirs,   "dirs",         "Show directory stack");

    register_builtin("trap",   builtin_trap,   "trap [cmd] [signal...]", "Set signal handlers");

    register_builtin("read",   builtin_read,   "read [-p prompt] [-s] <var...>", "Read line into variable(s)");

    register_builtin("time",   builtin_time,   "time <command>",          "Measure command execution time");

    register_builtin("hash",   builtin_hash,   "hash",                    "Show PATH lookup cache");
    register_builtin("rehash", builtin_rehash, "rehash",                  "Clear PATH lookup cache");

    register_builtin("history", builtin_history, "history [n|clear]",     "Show or clear command history");

    register_builtin("seq",      builtin_seq,      "seq [start] [step] <end>", "Generate number sequence");
    register_builtin("sleep",    builtin_sleep,    "sleep <seconds>",     "Pause for given duration");
    register_builtin("test",     builtin_test,     "test <expr>",         "Evaluate conditional expression");
    register_builtin("is-file",  builtin_is_file,  "is-file <path>",      "True if path is a regular file");
    register_builtin("is-dir",   builtin_is_dir,   "is-dir <path>",       "True if path is a directory");
    register_builtin("file-exists", builtin_file_exists, "file-exists <path>", "True if path exists");
    register_builtin("file-size",   builtin_file_size,   "file-size <path>",   "Get file size in bytes");
    register_builtin("basename", builtin_basename, "basename <path> [suffix]", "Extract filename from path");
    register_builtin("dirname",  builtin_dirname,  "dirname <path>",      "Extract directory from path");
    register_builtin("mkdir",    builtin_mkdir,    "mkdir [-p] <dir...>", "Create directories");
    register_builtin("rm",       builtin_rm,       "rm <file...>",        "Remove files");
    register_builtin("cp",       builtin_cp,       "cp <src> <dst>",      "Copy a file");
    register_builtin("mv",       builtin_mv,       "mv <src> <dst>",      "Move/rename a file");
    register_builtin("undo",     builtin_undo,     "undo",                "Undo last rm/mv/cp");
    register_builtin("undo-list", builtin_undo_list, "undo-list",         "List undoable operations");

    register_builtin("getopts",  builtin_getopts,  "getopts <optstring> <var> [args...]", "Parse script options");

    register_builtin("select-menu", builtin_select_menu, "select-menu [-p prompt]", "Interactive numbered menu selection");

    register_builtin("true",  builtin_true,      "true",  "Return success (exit 0)");
    register_builtin("false", builtin_false_cmd,  "false", "Return failure (exit 1)");

    register_builtin("clear", builtin_clear,     "clear",              "Clear the terminal screen");

    register_builtin("yes",   builtin_yes,       "yes [string]",       "Repeatedly output a string (default: y)");

    register_builtin("bindkey", builtin_bindkey,  "bindkey <key> <command>", "Bind a key to a shell command");

    register_builtin("printf", builtin_printf, "printf <fmt> [args...]", "Formatted output (like C printf)");

    register_builtin("exec", builtin_exec, "exec <cmd> [args...]", "Replace shell with command");

    register_builtin("eval", builtin_eval, "eval <string>", "Evaluate string as vex code");

    register_builtin("date", builtin_date, "date [+format]", "Current date/time (structured or formatted)");

    register_builtin("random", builtin_random, "random [max] or random <min> <max>", "Generate random number");

    register_builtin("unset",   builtin_unset,   "unset <var...>",      "Remove variables");
    register_builtin("unalias", builtin_unalias,  "unalias <name...>",   "Remove aliases");

    register_builtin("command", builtin_command,  "command <cmd> [args...]", "Run external command (bypass aliases)");

    register_builtin("wc",     builtin_wc,       "wc",                  "Word/line/byte count (structured)");

    register_builtin("zip",     builtin_zip,      "zip <list>",          "Combine two lists pairwise");
    register_builtin("group-by", builtin_group_by, "group-by <field>",   "Group records by field value");
    register_builtin("merge",   builtin_merge,    "merge <record>",      "Merge two records");
    register_builtin("append",  builtin_append,   "append <items...>",   "Add items to end of list");
    register_builtin("prepend", builtin_prepend,  "prepend <items...>",  "Add items to start of list");
    register_builtin("sort",    builtin_sort,     "sort [field]",        "Sort a list");
    register_builtin("compact", builtin_compact,  "compact",             "Remove null values from list");

    register_builtin("to-table", builtin_to_table, "to-table",          "Display as columnar table");

    register_builtin("columns", builtin_columns,  "columns",             "Get column/field names");
    register_builtin("values",  builtin_values,   "values",              "Get record values");

    register_builtin("update",  builtin_update,   "update <field> <val|closure>", "Update field in record(s)");
    register_builtin("insert",  builtin_insert,   "insert <field> <val>", "Add field to record(s) if missing");

    register_builtin("any",     builtin_any,      "any [closure]",       "True if any item matches");
    register_builtin("all",     builtin_all,      "all [closure]",       "True if all items match");

    register_builtin("find",    builtin_find,     "find <term|closure>", "Find matching items in list");

    register_builtin("into-int",    builtin_into_int,    "into-int",    "Convert to integer");
    register_builtin("into-float",  builtin_into_float,  "into-float",  "Convert to float");
    register_builtin("into-string", builtin_into_string, "into-string", "Convert to string");

    register_builtin("str-substring", builtin_str_substring, "str-substring <start> [len]", "Extract substring");

    register_builtin("chunks",  builtin_chunks,   "chunks <size>",       "Split list into chunks");
    register_builtin("window",  builtin_window,   "window <size>",       "Sliding window over list");

    register_builtin("input",   builtin_input,    "input [prompt]",      "Read line with optional prompt");

    register_builtin("default",  builtin_default,  "default <value>",     "Provide fallback for null");
    register_builtin("describe", builtin_describe, "describe",            "Show type and schema of value");
    register_builtin("wrap",     builtin_wrap,     "wrap <field>",        "Wrap value into a record field");
    register_builtin("do",       builtin_do,       "do <closure> [args]", "Execute a closure");
    register_builtin("is-empty",   builtin_is_empty, "is-empty",              "Check if value is empty");

    register_builtin("str-index-of",  builtin_str_index_of,  "str-index-of <substr>",          "Find position of substring");
    register_builtin("str-pad-left",  builtin_str_pad_left,  "str-pad-left <width> [fill]",     "Pad string on left");
    register_builtin("str-pad-right", builtin_str_pad_right, "str-pad-right <width> [fill]",    "Pad string on right");

    register_builtin("touch",    builtin_touch,    "touch <file...>",     "Create or update file timestamps");

    register_builtin("path-join",  builtin_path_join,  "path-join <parts...>", "Join path components");
    register_builtin("path-parse", builtin_path_parse, "path-parse",           "Parse path into components");
    register_builtin("path-expand", builtin_path_expand, "path-expand [path]",  "Expand ~ and resolve path");

    register_builtin("str-capitalize", builtin_str_capitalize, "str-capitalize", "Capitalize first letter");
    register_builtin("take-while", builtin_take_while, "take-while <closure>",   "Take items while predicate holds");
    register_builtin("skip-while", builtin_skip_while, "skip-while <closure>",   "Skip items while predicate holds");
    register_builtin("rotate",    builtin_rotate,    "rotate [n]",              "Rotate list by n positions");
    register_builtin("transpose", builtin_transpose, "transpose",               "Transpose table (records↔lists)");
    register_builtin("encode",    builtin_encode,    "encode [base64|hex]",     "Encode string");
    register_builtin("decode",    builtin_decode,    "decode [base64|hex]",     "Decode string");
    register_builtin("inspect",   builtin_inspect,   "inspect",                 "Debug print to stderr, pass through");
    register_builtin("tee",       builtin_tee_cmd,   "tee <closure>",           "Run side effect, pass input through");
    register_builtin("umask",     builtin_umask_cmd, "umask [mask]",            "Get/set file creation mask");
    register_builtin("cal",       builtin_cal,       "cal [month] [year]",      "Display calendar");

    register_builtin("str-reverse",  builtin_str_reverse,  "str-reverse",           "Reverse a string");
    register_builtin("str-repeat",   builtin_str_repeat,   "str-repeat <n>",        "Repeat string n times");
    register_builtin("str-chars",    builtin_str_chars,    "str-chars",             "Split into characters");
    register_builtin("str-words",    builtin_str_words,    "str-words",             "Split into words");
    register_builtin("range",        builtin_range,        "range [start] <end> [step]", "Generate number range");
    register_builtin("par-each",     builtin_par_each,     "par-each <closure>",    "Map over items (parallel)");
    register_builtin("which-all",    builtin_which_all,    "which-all <cmd>",       "Find all matches in PATH");
    register_builtin("has",          builtin_has,          "has <field|value>",     "Check if record has field or list has item");
    register_builtin("to-nuon",      builtin_to_nuon,      "to-nuon",              "Serialize to vex literal format");
    register_builtin("from-tsv",     builtin_from_tsv,     "from-tsv",             "Parse tab-separated values");
    register_builtin("to-tsv",       builtin_to_tsv,       "to-tsv",               "Serialize to tab-separated values");
    register_builtin("uname",        builtin_uname,        "uname",                "System info (structured)");

    register_builtin("ansi",         builtin_ansi,         "ansi <style>",          "ANSI escape code for color/style");
    register_builtin("char",         builtin_char_cmd,     "char <name>",           "Named character (newline, tab, etc)");
    register_builtin("term-size",    builtin_term_size,    "term-size",             "Get terminal dimensions");
    register_builtin("url-parse",    builtin_url_parse,    "url-parse",             "Parse URL into components");
    register_builtin("split-at",     builtin_split_at,     "split-at <index>",      "Split list at index");
    register_builtin("each-while",   builtin_each_while,   "each-while <closure>",  "Map while closure returns truthy");
    register_builtin("str-match",    builtin_str_match,    "str-match <pattern>",   "Regex match (POSIX extended)");
    register_builtin("fill",         builtin_fill,         "fill --width N --align left|right|center", "Pad/align value");
    register_builtin("error-make",   builtin_error_make,   "error-make <msg>",      "Create an error value");
    register_builtin("try",          builtin_try_cmd,      "try <body> [catch]",    "Try/catch error handling");

    register_builtin("whoami",       builtin_whoami,       "whoami",                "Current username");
    register_builtin("hostname",     builtin_hostname_cmd, "hostname",              "System hostname");
    register_builtin("du",           builtin_du,           "du [path]",             "Disk usage (structured)");
    register_builtin("str-regex-replace", builtin_str_regex_replace, "str-regex-replace <pattern> <repl> [-g]", "Regex replace");
    register_builtin("histogram",    builtin_histogram,    "histogram",             "Frequency count of list items");
    register_builtin("into-bool",    builtin_into_bool,    "into-bool",             "Convert to boolean");
    register_builtin("into-record",  builtin_into_record,  "into-record",           "List of pairs to record");
    register_builtin("into-list",    builtin_into_list,    "into-list",             "Record to list of key-value pairs");
    register_builtin("watch",        builtin_watch,        "watch <interval> { closure }", "Live-updating structured data view");
    register_builtin("config",       builtin_config_cmd,   "config [--edit]",       "Show/edit shell config paths");
    register_builtin("version",      builtin_version,      "version",               "Shell version info");

    register_builtin("str-camel-case", builtin_str_camel_case, "str-camel-case",      "Convert to camelCase");
    register_builtin("str-snake-case", builtin_str_snake_case, "str-snake-case",      "Convert to snake_case");
    register_builtin("str-kebab-case", builtin_str_kebab_case, "str-kebab-case",      "Convert to kebab-case");
    register_builtin("to-md",       builtin_to_md,        "to-md",                 "Convert table to markdown");
    register_builtin("flat-map",    builtin_flat_map,     "flat-map <closure>",    "Map then flatten");
    register_builtin("every",       builtin_every,        "every <n>",             "Take every Nth item");
    register_builtin("interleave",  builtin_interleave,   "interleave <list>",     "Interleave two lists");
    register_builtin("load-env",    builtin_load_env,     "load-env [path]",       "Load .env file into environment");
    register_builtin("format",      builtin_format_cmd,   "format <fmt> [args]",   "Format string with {} placeholders");
    register_builtin("bench",       builtin_bench,        "bench <closure> [n]",   "Benchmark closure execution");
    register_builtin("open-url",    builtin_open_url,     "open-url <url|path>",   "Open in default application");
    register_builtin("input-confirm", builtin_input_confirm, "input-confirm [prompt]", "Yes/no confirmation prompt");

    register_builtin("str-count",    builtin_str_count,    "str-count <substr>",    "Count substring occurrences");
    register_builtin("str-bytes",    builtin_str_bytes,    "str-bytes",             "String as byte values");
    register_builtin("take-until",   builtin_take_until,   "take-until <closure>",  "Take items until predicate matches");
    register_builtin("min-by",       builtin_min_by,       "min-by <field|closure>","Minimum by field or closure");
    register_builtin("max-by",       builtin_max_by,       "max-by <field|closure>","Maximum by field or closure");
    register_builtin("sum-by",       builtin_sum_by,       "sum-by <field|closure>","Sum by field or closure");
    register_builtin("frequencies",  builtin_frequencies,  "frequencies",           "Count item frequencies as table");
    register_builtin("to-yaml",      builtin_to_yaml,      "to-yaml",              "Serialize to YAML");
    register_builtin("from-ini",     builtin_from_ini,     "from-ini",             "Parse INI config");
    register_builtin("to-ini",       builtin_to_ini,       "to-ini",               "Serialize to INI format");
    register_builtin("mktemp",       builtin_mktemp_cmd,   "mktemp [-d] [prefix]", "Create temp file or directory");
    register_builtin("realpath",     builtin_realpath_cmd,  "realpath <path>",      "Resolve path to absolute");

    register_builtin("ln",          builtin_ln,           "ln [-s] <target> <link>", "Create link");
    register_builtin("readlink",    builtin_readlink,     "readlink <path>",       "Read symlink target");
    register_builtin("chmod",       builtin_chmod,        "chmod <mode> <file...>","Change file permissions");
    register_builtin("head",        builtin_head_text,    "head [n]",              "First n lines of string");
    register_builtin("tail",        builtin_tail_text,    "tail [n]",              "Last n lines of string");
    register_builtin("tac",         builtin_tac,          "tac",                   "Reverse lines");
    register_builtin("with-env",    builtin_with_env,     "with-env <rec> <closure>", "Run with modified env");
    register_builtin("retry",       builtin_retry,        "retry <closure> [n] [delay]", "Retry on failure");
    register_builtin("timeout",     builtin_timeout_cmd,  "timeout <secs> <closure>", "Run with timeout");
    register_builtin("defer",       builtin_defer,        "defer <command>",       "Run command at exit");
    register_builtin("parallel",    builtin_parallel,     "parallel <closures...>","Run closures in parallel");

    register_builtin("disown",      builtin_disown,       "disown [job-id]",       "Remove job from table (no SIGHUP)");
    register_builtin("math-sqrt",   builtin_math_sqrt,    "math-sqrt",             "Square root");
    register_builtin("math-pow",    builtin_math_pow,     "math-pow <exp>",        "Raise to power");
    register_builtin("math-log",    builtin_math_log,     "math-log [base]",       "Logarithm (natural or base N)");
    register_builtin("math-ceil",   builtin_math_ceil,    "math-ceil",             "Round up to integer");
    register_builtin("math-floor",  builtin_math_floor,   "math-floor",            "Round down to integer");
    register_builtin("math-sin",    builtin_math_sin,     "math-sin",              "Sine (radians)");
    register_builtin("math-cos",    builtin_math_cos,     "math-cos",              "Cosine (radians)");
    register_builtin("math-tan",    builtin_math_tan,     "math-tan",              "Tangent (radians)");
    register_builtin("http-get",    builtin_http_get,     "http-get <url>",        "HTTP GET (via curl)");
    register_builtin("http-post",   builtin_http_post,    "http-post <url> [body]","HTTP POST (via curl)");
    register_builtin("str-truncate",builtin_str_truncate, "str-truncate <width>",  "Truncate with ellipsis");
    register_builtin("uptime",      builtin_uptime,       "uptime",                "System uptime (structured)");

    register_builtin("http-put",    builtin_http_put,     "http-put <url> [body]", "HTTP PUT (via curl)");
    register_builtin("http-delete", builtin_http_delete,  "http-delete <url>",     "HTTP DELETE (via curl)");
    register_builtin("http-head",   builtin_http_head,    "http-head <url>",       "HTTP HEAD (headers as record)");
    register_builtin("math-pi",     builtin_math_pi,      "math-pi",              "Pi constant");
    register_builtin("math-e",      builtin_math_e,       "math-e",               "Euler's number");
    register_builtin("date-format", builtin_date_format,  "date-format <fmt>",    "Format epoch/date with strftime");
    register_builtin("date-humanize", builtin_date_humanize, "date-humanize",     "Human-readable time difference");
    register_builtin("uniq-by",     builtin_uniq_by,      "uniq-by <field|closure>", "Unique by field or key fn");
    register_builtin("rename",      builtin_rename,       "rename <old> <new>",   "Rename record field(s)");
    register_builtin("drop",        builtin_drop,         "drop [n]",             "Drop first/last N items");
    register_builtin("str-encode-uri", builtin_str_encode_uri, "str-encode-uri",  "Percent-encode for URL");
    register_builtin("str-decode-uri", builtin_str_decode_uri, "str-decode-uri",  "Decode percent-encoded string");

    register_builtin("math-median",  builtin_math_median,  "math-median",          "Median of list");
    register_builtin("math-stddev",  builtin_math_stddev,  "math-stddev",          "Standard deviation of list");
    register_builtin("math-product", builtin_math_product, "math-product",         "Product of list");
    register_builtin("from-yaml",    builtin_from_yaml,    "from-yaml",            "Parse YAML string");
    register_builtin("detect-columns", builtin_detect_columns, "detect-columns",   "Parse columnar text into table");
    register_builtin("env-keys",     builtin_env_keys,     "env-keys",             "List environment variable names");
    register_builtin("sys",          builtin_sys,          "sys",                   "System info (structured)");
    register_builtin("input-list",   builtin_input_list,   "input-list [list]",    "Interactive list selection");
    register_builtin("str-title-case", builtin_str_title_case, "str-title-case",   "Convert to Title Case");
    register_builtin("str-distance", builtin_str_distance, "str-distance <other>", "Levenshtein edit distance");
    register_builtin("split-row",    builtin_split_row,    "split-row [sep]",      "Split string into list by delimiter");
    register_builtin("seq-date",     builtin_seq_date,     "seq-date <start> <end> [step]", "Generate date sequence");

    register_builtin("math-mod",    builtin_math_mod,     "math-mod <divisor>",    "Modulo operation");
    register_builtin("math-exp",    builtin_math_exp,     "math-exp",              "e raised to power");
    register_builtin("math-ln",     builtin_math_ln,      "math-ln",               "Natural logarithm");
    register_builtin("str-starts-with-any", builtin_str_starts_with_any, "str-starts-with-any <list>", "Check multiple prefixes");
    register_builtin("str-ends-with-any", builtin_str_ends_with_any, "str-ends-with-any <list>", "Check multiple suffixes");
    register_builtin("collect",     builtin_collect,      "collect",               "Collect list of strings into one");
    register_builtin("zip-with",    builtin_zip_with,     "zip-with <list> <closure>", "Zip with combining function");
    register_builtin("from-xml",    builtin_from_xml,     "from-xml",              "Parse XML into record");
    register_builtin("to-xml",      builtin_to_xml,       "to-xml",                "Serialize to XML");
    register_builtin("path-exists", builtin_path_exists,  "path-exists [path]",    "Check if path exists");
    register_builtin("path-type",   builtin_path_type,    "path-type [path]",      "File type (file/dir/symlink/...)");
    register_builtin("generate",    builtin_generate,     "generate <init> <closure>", "Generate list from accumulator");

    register_builtin("math-asin",   builtin_math_asin,    "math-asin",             "Arcsine (radians)");
    register_builtin("math-acos",   builtin_math_acos,    "math-acos",             "Arccosine (radians)");
    register_builtin("math-atan",   builtin_math_atan,    "math-atan",             "Arctangent (radians)");
    register_builtin("math-atan2",  builtin_math_atan2,   "math-atan2 <x>",        "Two-arg arctangent");
    register_builtin("str-center",  builtin_str_center,   "str-center <width> [fill]", "Center-align string");
    register_builtin("str-remove",  builtin_str_remove,   "str-remove <substr>",   "Remove all occurrences");
    register_builtin("group-by-fn", builtin_group_by_fn,  "group-by-fn <closure>", "Group by closure result");
    register_builtin("scan",        builtin_scan,         "scan <init> <closure>",  "Reduce keeping intermediates");
    register_builtin("chunks-by",   builtin_chunks_by,    "chunks-by <closure>",   "Chunk by adjacency predicate");
    register_builtin("path-dirname", builtin_path_dirname, "path-dirname",          "Directory part of path");
    register_builtin("path-basename", builtin_path_basename_cmd, "path-basename",   "Filename part of path");
    register_builtin("path-ext",    builtin_path_ext,     "path-ext",              "File extension");
    register_builtin("to-html",     builtin_to_html,      "to-html",               "Convert to HTML table");
    register_builtin("sleep-ms",    builtin_sleep_ms,     "sleep-ms <ms>",         "Sleep for milliseconds");
    register_builtin("is-admin",    builtin_is_admin,     "is-admin",              "Check if running as root");

    register_builtin("math-gcd",    builtin_math_gcd,     "math-gcd <n>",          "Greatest common divisor");
    register_builtin("math-lcm",    builtin_math_lcm,     "math-lcm <n>",          "Least common multiple");
    register_builtin("math-clamp",  builtin_math_clamp,   "math-clamp <min> <max>","Clamp to range");
    register_builtin("str-wrap",    builtin_str_wrap,     "str-wrap <width>",      "Word-wrap text");
    register_builtin("str-similarity", builtin_str_similarity, "str-similarity <other>", "Normalized similarity 0..1");
    register_builtin("pairwise",    builtin_pairwise,     "pairwise",              "Sliding pairs from list");
    register_builtin("cartesian",   builtin_cartesian,    "cartesian <list>",      "Cartesian product");
    register_builtin("from-ssv",    builtin_from_ssv,     "from-ssv",              "Parse space-separated values");
    register_builtin("to-text-table", builtin_to_text_table, "to-text-table",      "Pretty-print aligned table");
    register_builtin("path-stem",   builtin_path_stem,    "path-stem",             "Filename without extension");
    register_builtin("path-rel",    builtin_path_rel,     "path-rel <base>",       "Make path relative to base");
    register_builtin("count-by",    builtin_count_by,     "count-by <closure>",    "Count items matching predicate");
    register_builtin("repeat",      builtin_repeat_cmd,   "repeat <n>",            "Repeat value into list");

    register_builtin("bits-and",    builtin_bits_and,     "bits-and <n>",          "Bitwise AND");
    register_builtin("bits-or",     builtin_bits_or,      "bits-or <n>",           "Bitwise OR");
    register_builtin("bits-xor",    builtin_bits_xor,     "bits-xor <n>",          "Bitwise XOR");
    register_builtin("bits-not",    builtin_bits_not,     "bits-not",              "Bitwise NOT");
    register_builtin("bits-shl",    builtin_bits_shl,     "bits-shl <n>",          "Bit shift left");
    register_builtin("bits-shr",    builtin_bits_shr,     "bits-shr <n>",          "Bit shift right");
    register_builtin("into-filesize", builtin_into_filesize, "into-filesize",      "Format bytes as human size");
    register_builtin("into-duration", builtin_into_duration, "into-duration",      "Parse duration string to seconds");
    register_builtin("format-duration", builtin_format_duration, "format-duration", "Format seconds as duration");
    register_builtin("times",       builtin_loop_cmd,     "times <n> <closure>",   "Run closure N times");
    register_builtin("cmp",         builtin_cmp,          "cmp <other>",           "Compare values (-1/0/1)");
    register_builtin("sort-by-fn",  builtin_sort_by_fn,   "sort-by-fn <closure>",  "Sort by key function");
    register_builtin("index-of",    builtin_index_of,     "index-of <item>",       "Find index in list (-1 if missing)");
    register_builtin("flat",        builtin_flat,         "flat [depth]",          "Flatten to depth");
    register_builtin("from-lines",  builtin_from_lines,   "from-lines",            "Split string into lines");
    register_builtin("to-lines",    builtin_to_lines,     "to-lines",              "Join list with newlines");

    register_builtin("hash-md5",    builtin_hash_md5,     "hash-md5",              "MD5 hash of string");
    register_builtin("hash-sha256", builtin_hash_sha256,  "hash-sha256",           "SHA-256 hash of string");
    register_builtin("hash-crc32",  builtin_hash_crc32,   "hash-crc32",            "CRC32 checksum");
    register_builtin("df",          builtin_df_cmd,       "df [path]",             "Disk free space (structured)");
    register_builtin("free",        builtin_free_cmd,     "free",                  "Memory usage (structured)");
    register_builtin("id",          builtin_id_cmd,       "id",                    "User/group info (structured)");
    register_builtin("groups",      builtin_groups_cmd,   "groups",                "List user groups");
    register_builtin("date-add",    builtin_date_add,     "date-add <secs|dur>",   "Add duration to epoch");
    register_builtin("date-diff",   builtin_date_diff,    "date-diff <epoch>",     "Difference between epochs");
    register_builtin("date-parse",  builtin_date_parse,   "date-parse [fmt]",      "Parse date string to epoch");
    register_builtin("date-to-epoch", builtin_date_to_epoch, "date-to-epoch",      "Date record to epoch");
    register_builtin("math-sign",   builtin_math_sign,    "math-sign",             "Sign of number (-1/0/1)");
    register_builtin("math-hypot",  builtin_math_hypot,   "math-hypot <b>",        "Hypotenuse sqrt(a²+b²)");
    register_builtin("math-log2",   builtin_math_log2,    "math-log2",             "Base-2 logarithm");
    register_builtin("math-log10",  builtin_math_log10,   "math-log10",            "Base-10 logarithm");

    register_builtin("regex-find",  builtin_regex_find,   "regex-find <pattern>",  "Find all regex matches");
    register_builtin("regex-split", builtin_regex_split,  "regex-split <pattern>", "Split by regex");
    register_builtin("bytes-length", builtin_bytes_length, "bytes-length",         "Byte length of string");
    register_builtin("bytes-at",    builtin_bytes_at,     "bytes-at <index>",      "Byte value at index");
    register_builtin("bytes-slice", builtin_bytes_slice,  "bytes-slice <start> [end]", "Slice bytes");
    register_builtin("str-scan",    builtin_str_scan,     "str-scan <substr>",     "Find all occurrences with positions");
    register_builtin("str-escape",  builtin_str_escape,   "str-escape",            "Escape special characters");
    register_builtin("str-unescape", builtin_str_unescape, "str-unescape",        "Unescape \\n \\t etc");
    register_builtin("headers",     builtin_headers,      "headers",               "Use first row as column names");
    register_builtin("move-col",    builtin_move_col,     "move-col <col> [first|last]", "Reorder columns");
    register_builtin("into-datetime", builtin_into_datetime, "into-datetime",      "Epoch to date record");
    register_builtin("each-with-index", builtin_each_with_index, "each-with-index <closure>", "Map with index");

    register_builtin("debug",       builtin_debug,        "debug",                 "Detailed type/value info");
    register_builtin("profile",     builtin_profile,      "profile <closure>",     "Time closure execution");
    register_builtin("table-flip",  builtin_table_flip,   "table-flip",            "Rows to columns");
    register_builtin("cross-join",  builtin_cross_join,   "cross-join <table>",    "Cartesian join of tables");
    register_builtin("left-join",   builtin_left_join,    "left-join <table> <key>", "Left join on key");
    register_builtin("str-hex",     builtin_str_hex,      "str-hex",               "String to hex");
    register_builtin("from-hex",    builtin_from_hex,     "from-hex",              "Hex string to bytes");
    register_builtin("math-factorial", builtin_math_factorial, "math-factorial",    "Factorial (max 20)");
    register_builtin("math-is-prime", builtin_math_is_prime, "math-is-prime",      "Primality test");
    register_builtin("math-fibonacci", builtin_math_fibonacci, "math-fibonacci",   "Nth Fibonacci number");
    register_builtin("env-get",     builtin_env_get,      "env-get <name> [default]", "Get environment variable");
    register_builtin("env-set",     builtin_env_set,      "env-set <name> <value>", "Set environment variable");

    register_builtin("gzip",        builtin_gzip,         "gzip [file]",           "Compress with gzip");
    register_builtin("gunzip",      builtin_gunzip,       "gunzip <file>",         "Decompress gzip file");
    register_builtin("tar-list",    builtin_tar_list,     "tar-list <archive>",    "List tar archive contents");
    register_builtin("path-is-absolute", builtin_path_is_absolute, "path-is-absolute", "Check if path is absolute");
    register_builtin("path-normalize", builtin_path_normalize, "path-normalize",   "Normalize path (resolve . and ..)");
    register_builtin("path-with-ext", builtin_path_with_ext, "path-with-ext <ext>", "Change file extension");
    register_builtin("str-ljust",   builtin_str_ljust,    "str-ljust <width> [fill]", "Left-justify (pad right)");
    register_builtin("str-rjust",   builtin_str_rjust,    "str-rjust <width> [fill]", "Right-justify (pad left)");
    register_builtin("split-column", builtin_split_column, "split-column <sep> [cols...]", "Split string into record columns");
    register_builtin("fill-null",   builtin_fill_null,    "fill-null <value>",     "Replace nulls with default");
    register_builtin("math-variance", builtin_math_variance, "math-variance",      "Variance of list");
    register_builtin("compact-record", builtin_compact_record, "compact-record",   "Remove null fields from record");
    register_builtin("to-base",     builtin_to_base,      "to-base <base>",        "Convert int to base 2-36");
    register_builtin("from-base",   builtin_from_base,    "from-base <base>",      "Parse string in base 2-36");

    register_builtin("builtins",    builtin_builtins,     "builtins",              "List all builtins (structured)");
    register_builtin("vars",        builtin_vars,         "vars",                  "List variables in scope");
    register_builtin("ulimit",      builtin_ulimit,       "ulimit [resource] [value]", "Get/set resource limits");
    register_builtin("ansi-strip",  builtin_ansi_strip,   "ansi-strip",            "Remove ANSI escape codes");
    register_builtin("str-is-numeric", builtin_str_is_numeric, "str-is-numeric",   "Check if string is a number");
    register_builtin("inner-join",  builtin_inner_join,   "inner-join <table> <key>", "Inner join on key");
    register_builtin("from-jsonl",  builtin_from_jsonl,   "from-jsonl",            "Parse JSON Lines");
    register_builtin("to-jsonl",    builtin_to_jsonl,     "to-jsonl",              "Serialize to JSON Lines");
    register_builtin("url-build",   builtin_url_build,    "url-build",             "Build URL from record");
    register_builtin("tar-extract", builtin_tar_extract,  "tar-extract <archive> [dest]", "Extract tar archive");
    register_builtin("tar-create",  builtin_tar_create,   "tar-create <archive> <files...>", "Create tar archive");
    register_builtin("path-home",   builtin_path_home,    "path-home",             "Home directory path");
    register_builtin("env-remove",  builtin_env_remove,   "env-remove <name>",     "Remove environment variable");
    register_builtin("command-type", builtin_command_type, "command-type <name>",  "Command type (builtin/external/alias)");

    register_builtin("pivot",       builtin_pivot,        "pivot",                 "Pivot record to key-value table");
    register_builtin("merge-deep",  builtin_merge_deep,   "merge-deep <record>",   "Deep merge records");
    register_builtin("from-nuon",   builtin_from_nuon,    "from-nuon",             "Parse NUON/Vex literal syntax");
    register_builtin("split-words", builtin_split_words,  "split-words",           "Split into words (word boundaries)");
    register_builtin("math-deg-to-rad", builtin_math_deg_to_rad, "math-deg-to-rad", "Degrees to radians");
    register_builtin("math-rad-to-deg", builtin_math_rad_to_deg, "math-rad-to-deg", "Radians to degrees");
    register_builtin("into-binary", builtin_into_binary,  "into-binary",           "Convert to byte list");
    register_builtin("from-binary", builtin_from_binary,  "from-binary",           "Byte list to string");
    register_builtin("math-lerp",   builtin_math_lerp,    "math-lerp <a> <b>",     "Linear interpolation");
    register_builtin("math-map-range", builtin_math_map_range, "math-map-range <in_min> <in_max> <out_min> <out_max>", "Map value between ranges");
    register_builtin("record-to-list", builtin_record_to_list, "record-to-list",    "Record to [[key, val], ...] list");
    register_builtin("record-keys", builtin_record_keys,  "record-keys",           "Get record field names");
    register_builtin("record-values", builtin_record_values, "record-values",      "Get record field values");

    register_builtin("hook-add",    builtin_hook_add,    "hook-add <event> <closure>",    "Register a hook (preexec, precmd, chpwd)");
    register_builtin("hook-remove", builtin_hook_remove, "hook-remove <event> [<index>]", "Remove hook(s) for an event");
    register_builtin("hook-list",   builtin_hook_list,   "hook-list",                     "List registered hooks");

    register_builtin("prompt-fn",  builtin_prompt_fn,  "prompt-fn <closure>",  "Set a closure as the prompt generator");
    register_builtin("rprompt-fn", builtin_rprompt_fn, "rprompt-fn <closure>", "Set a closure as the right prompt generator");

    register_builtin("assert",    builtin_assert,    "assert <cond> [msg]",      "Assert condition is true");
    register_builtin("shift",     builtin_shift,     "shift [n]",                "Shift positional arguments");
    register_builtin("argparse",  builtin_argparse,  "argparse <spec> <argv>",   "Parse command-line arguments");

    register_builtin("ssh-exec",  builtin_ssh_exec,  "ssh-exec <host> <cmd...>", "Execute command on remote host");
    register_builtin("scp-get",   builtin_scp_get,   "scp-get <host:path> [local]", "Download file via SCP");
    register_builtin("scp-put",   builtin_scp_put,   "scp-put <local> <host:path>", "Upload file via SCP");
    register_builtin("ssh",       builtin_ssh_shell,  "ssh <host> [cmd...]",     "SSH to remote host");

    register_builtin("pkg",       builtin_pkg,        "pkg <subcmd> [args...]",  "Package manager (install/remove/list/update/init)");

    register_builtin("theme",     builtin_theme,      "theme <name>",            "Switch prompt theme (default/minimal/powerline/lambda/pure/robbyrussell)");
    register_builtin("trash",     builtin_trash,      "trash [list|empty|purge [days]]", "List, empty, or age-purge the rm trash");
    register_builtin("def-cmd",   builtin_def_cmd,    "def-cmd <name> [usage] [desc] <closure>", "Register a script command");

    builtin_ht_build();
}

const BuiltinCmd *builtin_lookup(const char *name) {
    if (!builtin_ht_ready) builtin_ht_build();
    uint32_t slot = fnv1a(name) & (BUILTIN_HT_SIZE - 1);
    while (builtin_ht[slot].key) {
        if (strcmp(builtin_ht[slot].key, name) == 0)
            return &builtins_table[builtin_ht[slot].idx];
        slot = (slot + 1) & (BUILTIN_HT_SIZE - 1);
    }
    return NULL;
}

bool builtin_exists(const char *name) {
    return builtin_lookup(name) != NULL;
}

size_t builtin_count(void) {
    return builtins_count;
}

const char *builtin_name(size_t i) {
    return i < builtins_count ? builtins_table[i].name : NULL;
}
