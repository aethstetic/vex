#include "vex.h"
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <termios.h>
#include <fcntl.h>
#include <glob.h>
#include <dirent.h>
#include <fnmatch.h>
#include <ctype.h>
#include <regex.h>
#include <pwd.h>

static VexValue *vval_alloc_local(VexType type) {
    VexValue *v = calloc(1, sizeof(VexValue));
    v->type = type;
    v->refcount = 1;
    return v;
}

/* Initialize eval context with global scope, arena, and default flow state */
EvalCtx eval_ctx_new(void) {
    EvalCtx ctx = {0};
    ctx.global = scope_new(NULL);
    ctx.current = ctx.global;
    ctx.arena = arena_create();
    ctx.pipeline_input = NULL;
    ctx.had_error = false;
    ctx.last_exit_code = 0;
    ctx.flow = FLOW_NONE;
    ctx.flow_value = NULL;
    return ctx;
}

/* Tears down the entire eval context; scope tree and arena are owned by ctx */
void eval_ctx_free(EvalCtx *ctx) {
    scope_free(ctx->global);
    arena_destroy(ctx->arena);
}

#define PATH_CACHE_SIZE 64
static struct {
    char *name;
    char *path;
} path_cache[PATH_CACHE_SIZE];
static size_t path_cache_count = 0;
static char *cached_path_env = NULL;

void path_cache_clear(void) {
    for (size_t i = 0; i < path_cache_count; i++) {
        free(path_cache[i].name);
        free(path_cache[i].path);
    }
    path_cache_count = 0;
    free(cached_path_env);
    cached_path_env = NULL;
}

size_t path_cache_list(const char ***names_out, const char ***paths_out) {
    *names_out = malloc(path_cache_count * sizeof(char *));
    *paths_out = malloc(path_cache_count * sizeof(char *));
    for (size_t i = 0; i < path_cache_count; i++) {
        (*names_out)[i] = path_cache[i].name;
        (*paths_out)[i] = path_cache[i].path;
    }
    return path_cache_count;
}

static char *path_cache_lookup(const char *name) {

    const char *current_path = getenv("PATH");
    if (!cached_path_env || !current_path ||
        strcmp(cached_path_env, current_path) != 0) {
        path_cache_clear();
        cached_path_env = current_path ? strdup(current_path) : NULL;
        return NULL;
    }
    for (size_t i = 0; i < path_cache_count; i++) {
        if (strcmp(path_cache[i].name, name) == 0)
            return strdup(path_cache[i].path);
    }
    return NULL;
}

static void path_cache_add(const char *name, const char *resolved) {
    if (path_cache_count >= PATH_CACHE_SIZE) {

        free(path_cache[0].name);
        free(path_cache[0].path);
        memmove(path_cache, path_cache + 1,
                (PATH_CACHE_SIZE - 1) * sizeof(path_cache[0]));
        path_cache_count--;
    }
    path_cache[path_cache_count].name = strdup(name);
    path_cache[path_cache_count].path = strdup(resolved);
    path_cache_count++;
}

char *find_in_path(const char *name) {

    if (strchr(name, '/')) {
        if (access(name, X_OK) == 0) return strdup(name);
        return NULL;
    }

    char *cached = path_cache_lookup(name);
    if (cached) return cached;

    const char *path = getenv("PATH");
    if (!path) return NULL;

    char buf[4096];
    const char *p = path;
    while (*p) {
        const char *colon = strchr(p, ':');
        size_t dirlen = colon ? (size_t)(colon - p) : strlen(p);

        if (dirlen + strlen(name) + 2 > sizeof(buf)) {
            p = colon ? colon + 1 : p + strlen(p);
            continue;
        }

        memcpy(buf, p, dirlen);
        buf[dirlen] = '/';
        strcpy(buf + dirlen + 1, name);

        if (access(buf, X_OK) == 0) {
            path_cache_add(name, buf);
            return strdup(buf);
        }

        if (!colon) break;
        p = colon + 1;
    }
    return NULL;
}

static void suggest_command(const char *name) {

    size_t cap = 256;
    size_t count = 0;
    const char **candidates = malloc(cap * sizeof(char *));
    char **allocated = NULL;
    size_t alloc_count = 0, alloc_cap = 0;

    size_t bc = builtin_count();
    for (size_t i = 0; i < bc; i++) {
        if (count >= cap) { cap *= 2; candidates = realloc(candidates, cap * sizeof(char *)); }
        candidates[count++] = builtin_name(i);
    }

    const char *path_env = getenv("PATH");
    if (path_env) {
        char *path_copy = strdup(path_env);
        char *saveptr = NULL;
        for (char *dir = strtok_r(path_copy, ":", &saveptr); dir;
             dir = strtok_r(NULL, ":", &saveptr)) {
            DIR *dp = opendir(dir);
            if (!dp) continue;
            struct dirent *ent;
            while ((ent = readdir(dp)) != NULL) {
                if (ent->d_name[0] == '.') continue;

                if (strcmp(ent->d_name, name) == 0) continue;
                if (count >= cap) { cap *= 2; candidates = realloc(candidates, cap * sizeof(char *)); }
                char *dup = strdup(ent->d_name);
                candidates[count++] = dup;

                if (alloc_count >= alloc_cap) {
                    alloc_cap = alloc_cap ? alloc_cap * 2 : 256;
                    allocated = realloc(allocated, alloc_cap * sizeof(char *));
                }
                allocated[alloc_count++] = dup;
            }
            closedir(dp);
        }
        free(path_copy);
    }

    const char *suggestion = vex_closest_match(name, candidates, count, 3);
    if (suggestion) {
        fprintf(stderr, "  Did you mean: \033[1;32m%s\033[0m\n", suggestion);
    }

    for (size_t i = 0; i < alloc_count; i++) free(allocated[i]);
    free(allocated);
    free(candidates);
}

static char *tilde_expand(const char *path) {
    if (!path || path[0] != '~') return strdup(path);

    if (path[1] == '\0' || path[1] == '/') {
        const char *home = getenv("HOME");
        if (!home) return strdup(path);
        if (path[1] == '\0') return strdup(home);
        size_t hlen = strlen(home);
        size_t plen = strlen(path + 1);
        char *result = malloc(hlen + plen + 1);
        memcpy(result, home, hlen);
        memcpy(result + hlen, path + 1, plen + 1);
        return result;
    }

    const char *slash = strchr(path + 1, '/');
    size_t ulen = slash ? (size_t)(slash - (path + 1)) : strlen(path + 1);
    char *username = strndup(path + 1, ulen);
    struct passwd *pw = getpwnam(username);
    free(username);
    if (!pw) return strdup(path);
    if (!slash) return strdup(pw->pw_dir);
    size_t hlen = strlen(pw->pw_dir);
    size_t plen = strlen(slash);
    char *result = malloc(hlen + plen + 1);
    memcpy(result, pw->pw_dir, hlen);
    memcpy(result + hlen, slash, plen + 1);
    return result;
}

/* Apply file redirections (>, <, <<, 2>) in the child process before exec */
static void apply_redirects(const Redirect *r) {
    if (!r) return;
    if (r->stdout_file) {
        char *path = tilde_expand(r->stdout_file);
        if (!r->stdout_append && vex_opt_noclobber()) {
            struct stat st;
            if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
                vex_err("cannot overwrite existing file '%s' (noclobber is set; use >| to force)", path);
                free(path);
                _exit(1);
            }
        }
        int flags = O_WRONLY | O_CREAT | (r->stdout_append ? O_APPEND : O_TRUNC);
        int fd = open(path, flags, 0644);
        free(path);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            close(fd);
        }
    }
    if (r->stdin_string) {

        int pipefd[2];
        if (pipe(pipefd) == 0) {
            size_t len = strlen(r->stdin_string);
            write(pipefd[1], r->stdin_string, len);
            write(pipefd[1], "\n", 1);
            close(pipefd[1]);
            dup2(pipefd[0], STDIN_FILENO);
            close(pipefd[0]);
        }
    } else if (r->stdin_file) {
        char *path = tilde_expand(r->stdin_file);
        int fd = open(path, O_RDONLY);
        free(path);
        if (fd >= 0) {
            dup2(fd, STDIN_FILENO);
            close(fd);
        }
    }
    if (r->stderr_to_stdout) {
        dup2(STDOUT_FILENO, STDERR_FILENO);
    } else if (r->stderr_file) {
        char *path = tilde_expand(r->stderr_file);
        if (!r->stderr_append && vex_opt_noclobber()) {
            struct stat st;
            if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
                vex_err("cannot overwrite existing file '%s' (noclobber is set; use >| to force)", path);
                free(path);
                _exit(1);
            }
        }
        int flags = O_WRONLY | O_CREAT | (r->stderr_append ? O_APPEND : O_TRUNC);
        int fd = open(path, flags, 0644);
        free(path);
        if (fd >= 0) {
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
    }
}

/* Fork+exec an external command with fd wiring, job control, and stop handling */
int exec_external_redir(const char *name, char **argv, int in_fd, int out_fd,
                        const Redirect *redir) {
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        vex_err("fork failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {

        setpgid(0, 0);
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGTSTP, SIG_DFL);
        signal(SIGTTIN, SIG_DFL);
        signal(SIGTTOU, SIG_DFL);

        if (in_fd != STDIN_FILENO) {
            dup2(in_fd, STDIN_FILENO);
            close(in_fd);
        }
        if (out_fd != STDOUT_FILENO) {
            dup2(out_fd, STDOUT_FILENO);
            close(out_fd);
        }

        apply_redirects(redir);

        char *path = find_in_path(name);
        if (!path) {
            fprintf(stderr, "vex: command not found: %s\n", name);
            suggest_command(name);
            _exit(127);
        }
        execv(path, argv);
        fprintf(stderr, "vex: exec failed: %s: %s\n", name, strerror(errno));
        _exit(126);
    }

    setpgid(pid, pid);

    if (isatty(STDIN_FILENO)) {
        tcsetpgrp(STDIN_FILENO, pid);
    }

    int job_id = job_add(pid, pid, name, false);

    int status;
    waitpid(pid, &status, WUNTRACED);

    if (isatty(STDIN_FILENO)) {
        tcsetpgrp(STDIN_FILENO, job_shell_pgid());
    }

    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (job_id >= 0) job_remove(job_id);
        return code;
    }
    if (WIFSIGNALED(status)) {
        int code = 128 + WTERMSIG(status);
        if (job_id >= 0) job_remove(job_id);
        return code;
    }
    if (WIFSTOPPED(status)) {

        Job *j = job_get(job_id);
        if (j) {
            j->status = JOB_STOPPED;
            j->background = true;
            fprintf(stderr, "\n[%d]  Stopped\t\t%s\n", j->id, j->cmd);
        }
        return 148;
    }

    if (job_id >= 0) job_remove(job_id);
    return -1;
}

int exec_external(const char *name, char **argv, int in_fd, int out_fd) {
    return exec_external_redir(name, argv, in_fd, out_fd, NULL);
}

/* Fork+exec a command into a background job group, returns job id */
int exec_external_bg(const char *name, char **argv, const char *cmd_str) {
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        vex_err("fork failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        setpgid(0, 0);
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGTSTP, SIG_DFL);
        signal(SIGTTIN, SIG_DFL);
        signal(SIGTTOU, SIG_DFL);

        char *path = find_in_path(name);
        if (!path) {
            fprintf(stderr, "vex: command not found: %s\n", name);
            suggest_command(name);
            _exit(127);
        }
        execv(path, argv);
        _exit(126);
    }

    setpgid(pid, pid);
    int job_id = job_add(pid, pid, cmd_str, true);
    if (job_id >= 0) {
        fprintf(stderr, "[%d]  %d\n", job_id, (int)pid);
    }
    return job_id;
}

/* Fork+exec and capture stdout into a VexValue string (for pipelines/subst) */
VexValue *exec_external_capture(const char *name, char **argv, int in_fd) {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        vex_err("pipe failed: %s", strerror(errno));
        return vval_error("pipe failed");
    }

    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return vval_error("fork failed");
    }

    if (pid == 0) {

        setpgid(0, 0);
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGTSTP, SIG_DFL);
        signal(SIGTTIN, SIG_DFL);
        signal(SIGTTOU, SIG_DFL);

        close(pipefd[0]);
        if (in_fd != STDIN_FILENO) {
            dup2(in_fd, STDIN_FILENO);
            close(in_fd);
        }
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        char *path = find_in_path(name);
        if (!path) {
            fprintf(stderr, "vex: command not found: %s\n", name);
            suggest_command(name);
            _exit(127);
        }
        execv(path, argv);
        _exit(126);
    }

    setpgid(pid, pid);
    close(pipefd[1]);

    VexStr output = vstr_empty();
    char buf[4096];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        vstr_append(&output, buf, (size_t)n);
    }
    close(pipefd[0]);

    int status;
    waitpid(pid, &status, 0);

    size_t len = vstr_len(&output);
    if (len > 0 && vstr_data(&output)[len - 1] == '\n') {
        VexStr trimmed = vstr_newn(vstr_data(&output), len - 1);
        vstr_free(&output);
        output = trimmed;
    }

    return vval_string(output);
}

/* Invoke a closure: bind params (with rest/defaults), set $it, eval body, handle return flow */
VexValue *eval_call_closure(EvalCtx *ctx, VexValue *closure,
                            VexValue **args, size_t argc) {
    if (!closure || closure->type != VEX_VAL_CLOSURE) {
        return vval_error("not a closure");
    }

    Scope *call_scope = scope_new(closure->closure.env);

    Param *params = (Param *)closure->closure.params;
    size_t pcount = closure->closure.param_count;
    for (size_t i = 0; i < pcount; i++) {
        if (params[i].is_rest) {

            VexValue *rest = vval_list();
            for (size_t j = i; j < argc; j++) {
                vval_list_push(rest, args[j]);
            }
            scope_set(call_scope, params[i].name, rest);
            vval_release(rest);
            break;
        }
        if (i < argc) {
            scope_set(call_scope, params[i].name, args[i]);
        } else if (params[i].default_val) {
            VexValue *def = eval(ctx, params[i].default_val);
            scope_set(call_scope, params[i].name, def);
            vval_release(def);
        } else {
            VexValue *null = vval_null();
            scope_set(call_scope, params[i].name, null);
            vval_release(null);
        }
    }

    if (argc > 0) {
        scope_set(call_scope, "it", args[0]);
    }

    Scope *saved = ctx->current;
    ctx->current = call_scope;
    VexValue *result = eval(ctx, closure->closure.body);

    if (ctx->flow == FLOW_RETURN) {
        ctx->flow = FLOW_NONE;
        if (ctx->flow_value) {
            vval_release(result);
            result = ctx->flow_value;
            ctx->flow_value = NULL;
        }
    }

    ctx->current = saved;
    scope_free(call_scope);

    return result;
}

static bool has_glob_chars(const char *s) {
    for (; *s; s++) {
        if (*s == '*' || *s == '?' || *s == '[') return true;
    }
    return false;
}

static char **brace_expand(const char *s, size_t *out_count);

static bool has_brace_pattern(const char *s) {
    int depth = 0;
    for (; *s; s++) {
        if (*s == '{') depth++;
        else if (*s == ',' && depth > 0) return true;
        else if (*s == '}' && depth > 0) return true;
    }
    return false;
}

static ssize_t find_closing_brace(const char *s, size_t pos) {
    int depth = 1;
    for (size_t i = pos + 1; s[i]; i++) {
        if (s[i] == '{') depth++;
        else if (s[i] == '}') {
            depth--;
            if (depth == 0) return (ssize_t)i;
        }
    }
    return -1;
}

static char **split_brace_alts(const char *s, size_t len, size_t *alt_count) {
    size_t cap = 8;
    size_t count = 0;
    char **alts = malloc(cap * sizeof(char *));
    size_t start = 0;
    int depth = 0;

    for (size_t i = 0; i <= len; i++) {
        if (i < len && s[i] == '{') depth++;
        else if (i < len && s[i] == '}') depth--;
        else if ((i == len || (s[i] == ',' && depth == 0))) {
            if (count >= cap) {
                cap *= 2;
                alts = realloc(alts, cap * sizeof(char *));
            }
            alts[count] = strndup(s + start, i - start);
            count++;
            start = i + 1;
        }
    }
    *alt_count = count;
    return alts;
}

static char **brace_expand(const char *s, size_t *out_count) {

    ssize_t open = -1;
    ssize_t close = -1;
    bool has_comma = false;

    for (size_t i = 0; s[i]; i++) {
        if (s[i] == '{') {
            ssize_t cl = find_closing_brace(s, i);
            if (cl < 0) continue;

            int depth = 0;
            has_comma = false;
            for (size_t j = i + 1; j < (size_t)cl; j++) {
                if (s[j] == '{') depth++;
                else if (s[j] == '}') depth--;
                else if (s[j] == ',' && depth == 0) { has_comma = true; break; }
            }
            if (has_comma) {
                open = (ssize_t)i;
                close = cl;
                break;
            }
        }
    }

    if (open < 0) {
        char **result = malloc(2 * sizeof(char *));
        result[0] = strdup(s);
        result[1] = NULL;
        *out_count = 1;
        return result;
    }

    char *prefix = strndup(s, (size_t)open);
    size_t inner_len = (size_t)(close - open - 1);
    size_t alt_count = 0;
    char **alts = split_brace_alts(s + open + 1, inner_len, &alt_count);
    const char *suffix = s + close + 1;

    size_t total = 0;
    size_t cap = alt_count * 2;
    char **result = malloc(cap * sizeof(char *));

    for (size_t i = 0; i < alt_count; i++) {
        size_t combined_len = strlen(prefix) + strlen(alts[i]) + strlen(suffix) + 1;
        char *combined = malloc(combined_len);
        snprintf(combined, combined_len, "%s%s%s", prefix, alts[i], suffix);

        size_t sub_count = 0;
        char **sub = brace_expand(combined, &sub_count);
        free(combined);

        for (size_t j = 0; j < sub_count; j++) {
            if (total >= cap) {
                cap *= 2;
                result = realloc(result, cap * sizeof(char *));
            }
            result[total++] = sub[j];
        }
        free(sub);
        free(alts[i]);
    }
    free(alts);
    free(prefix);

    result = realloc(result, (total + 1) * sizeof(char *));
    result[total] = NULL;
    *out_count = total;
    return result;
}

static int str_cmp(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

static bool has_double_star(const char *s) {
    return strstr(s, "**") != NULL;
}

static void rglob_walk(const char *dir, const char *suffix_pat,
                        size_t prefix_len,
                        char ***out, size_t *out_n, size_t *out_cap) {
    DIR *dp = opendir(dir);
    if (!dp) return;

    struct dirent *ent;
    while ((ent = readdir(dp)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;

        size_t dlen = strlen(dir);
        size_t nlen = strlen(ent->d_name);
        char *full = malloc(dlen + 1 + nlen + 1);
        memcpy(full, dir, dlen);
        full[dlen] = '/';
        memcpy(full + dlen + 1, ent->d_name, nlen + 1);

        struct stat st;
        if (lstat(full, &st) < 0) { free(full); continue; }

        const char *rel = full + prefix_len;
        while (*rel == '/') rel++;

        if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
            if (fnmatch(suffix_pat, rel, 0) == 0) {
                if (*out_n >= *out_cap) {
                    *out_cap *= 2;
                    *out = realloc(*out, *out_cap * sizeof(char *));
                }
                (*out)[(*out_n)++] = strdup(full);
            }
        }
        if (S_ISDIR(st.st_mode)) {
            rglob_walk(full, suffix_pat, prefix_len, out, out_n, out_cap);
        }
        free(full);
    }
    closedir(dp);
}

static size_t recursive_glob(const char *pattern, char ***results) {
    const char *ds = strstr(pattern, "**");
    if (!ds) return 0;

    size_t base_len = (size_t)(ds - pattern);
    char *base;
    if (base_len == 0) {
        base = strdup(".");
    } else {

        size_t bl = base_len;
        while (bl > 0 && pattern[bl - 1] == '/') bl--;
        if (bl == 0) {
            base = strdup(".");
        } else {
            base = strndup(pattern, bl);
        }
    }

    const char *after = ds + 2;

    if (*after == '/') after++;
    size_t after_len = strlen(after);
    char *suffix;
    if (after_len == 0) {
        suffix = strdup("*");
    } else {
        suffix = strdup(after);
    }

    size_t n = 0, cap = 64;
    char **out = malloc(cap * sizeof(char *));
    size_t prefix_len = strlen(base);

    rglob_walk(base, suffix, prefix_len, &out, &n, &cap);

    free(base);
    free(suffix);

    if (n > 1) {
        qsort(out, n, sizeof(char *), str_cmp);
    }

    *results = out;
    return n;
}

static char **build_argv(EvalCtx *ctx, ASTNode *node) {

    size_t cap = node->call.arg_count + 16;
    size_t argc = 1;
    char **argv = malloc(cap * sizeof(char *));
    argv[0] = strdup(node->call.cmd_name);

    for (size_t i = 0; i < node->call.arg_count; i++) {
        VexValue *v = eval(ctx, node->call.args[i]);
        VexStr s = vval_to_str(v);
        const char *arg = vstr_data(&s);

        char *tilde_exp = NULL;
        if (arg[0] == '~') {
            tilde_exp = tilde_expand(arg);
            arg = tilde_exp;
        }

        size_t brace_count = 0;
        char **brace_results = NULL;
        if (has_brace_pattern(arg)) {
            brace_results = brace_expand(arg, &brace_count);
        } else {
            brace_results = malloc(2 * sizeof(char *));
            brace_results[0] = strdup(arg);
            brace_results[1] = NULL;
            brace_count = 1;
        }

        for (size_t bi = 0; bi < brace_count; bi++) {
            const char *word = brace_results[bi];
            if (has_glob_chars(word)) {
                if (has_double_star(word)) {

                    char **rg_results = NULL;
                    size_t rg_count = recursive_glob(word, &rg_results);
                    if (rg_count > 0) {
                        for (size_t j = 0; j < rg_count; j++) {
                            if (argc + 1 >= cap) {
                                cap *= 2;
                                argv = realloc(argv, cap * sizeof(char *));
                            }
                            argv[argc++] = rg_results[j];
                        }
                        free(rg_results);
                    } else {

                        if (argc + 1 >= cap) {
                            cap *= 2;
                            argv = realloc(argv, cap * sizeof(char *));
                        }
                        argv[argc++] = strdup(word);
                        free(rg_results);
                    }
                } else {
                    glob_t g;
                    int ret = glob(word, GLOB_NOCHECK, NULL, &g);
                    if (ret == 0 && g.gl_pathc > 0) {
                        for (size_t j = 0; j < g.gl_pathc; j++) {
                            if (argc + 1 >= cap) {
                                cap *= 2;
                                argv = realloc(argv, cap * sizeof(char *));
                            }
                            argv[argc++] = strdup(g.gl_pathv[j]);
                        }
                    } else {
                        if (argc + 1 >= cap) {
                            cap *= 2;
                            argv = realloc(argv, cap * sizeof(char *));
                        }
                        argv[argc++] = strdup(word);
                    }
                    globfree(&g);
                }
            } else {
                if (argc + 1 >= cap) {
                    cap *= 2;
                    argv = realloc(argv, cap * sizeof(char *));
                }
                argv[argc++] = strdup(word);
            }
            free(brace_results[bi]);
        }
        free(brace_results);
        free(tilde_exp);
        vstr_free(&s);
        vval_release(v);
    }
    argv[argc] = NULL;
    return argv;
}

static void free_argv(char **argv) {
    if (!argv) return;
    for (int i = 0; argv[i]; i++) free(argv[i]);
    free(argv);
}

static VexValue *eval_node(EvalCtx *ctx, ASTNode *node);

static VexValue *eval_binary(EvalCtx *ctx, ASTNode *node) {
    VexValue *left = eval(ctx, node->binary.left);
    VexValue *right = eval(ctx, node->binary.right);
    VexValue *result = NULL;

    if (left->type == VEX_VAL_INT && right->type == VEX_VAL_INT) {
        int64_t l = left->integer, r = right->integer;
        switch (node->binary.op) {
        case TOK_PLUS:    result = vval_int(l + r); break;
        case TOK_MINUS:   result = vval_int(l - r); break;
        case TOK_STAR:    result = vval_int(l * r); break;
        case TOK_SLASH:
            if (r == 0) { ctx->had_error = true; result = vval_error("division by zero"); break; }
            result = vval_int(l / r); break;
        case TOK_PERCENT:
            if (r == 0) { ctx->had_error = true; result = vval_error("division by zero"); break; }
            result = vval_int(l % r); break;
        case TOK_EQ:      result = vval_bool(l == r); break;
        case TOK_NEQ:     result = vval_bool(l != r); break;
        case TOK_LT:      result = vval_bool(l < r); break;
        case TOK_GT:      result = vval_bool(l > r); break;
        case TOK_LTE:     result = vval_bool(l <= r); break;
        case TOK_GTE:     result = vval_bool(l >= r); break;
        default:
            result = vval_error("unsupported operator for integers");
        }
    }

    else if (left->type == VEX_VAL_STRING && right->type == VEX_VAL_STRING) {
        switch (node->binary.op) {
        case TOK_PLUS: {
            VexStr s = vstr_clone(&left->string);
            vstr_append_str(&s, &right->string);
            result = vval_string(s);
            break;
        }
        case TOK_EQ:  result = vval_bool(vstr_eq(&left->string, &right->string)); break;
        case TOK_NEQ: result = vval_bool(!vstr_eq(&left->string, &right->string)); break;
        case TOK_REGEX_MATCH: {
            regex_t re;
            const char *pattern = vstr_data(&right->string);
            const char *subject = vstr_data(&left->string);
            int rc = regcomp(&re, pattern, REG_EXTENDED | REG_NOSUB);
            if (rc != 0) {
                result = vval_error("invalid regex pattern");
            } else {
                rc = regexec(&re, subject, 0, NULL, 0);
                result = vval_bool(rc == 0);
                regfree(&re);
            }
            break;
        }
        default:
            result = vval_error("unsupported operator for strings");
        }
    }

    else if ((left->type == VEX_VAL_FLOAT || left->type == VEX_VAL_INT) &&
             (right->type == VEX_VAL_FLOAT || right->type == VEX_VAL_INT)) {
        double l = left->type == VEX_VAL_FLOAT ? left->floating : (double)left->integer;
        double r = right->type == VEX_VAL_FLOAT ? right->floating : (double)right->integer;
        switch (node->binary.op) {
        case TOK_PLUS:    result = vval_float(l + r); break;
        case TOK_MINUS:   result = vval_float(l - r); break;
        case TOK_STAR:    result = vval_float(l * r); break;
        case TOK_SLASH:   result = vval_float(l / r); break;
        case TOK_EQ:      result = vval_bool(l == r); break;
        case TOK_NEQ:     result = vval_bool(l != r); break;
        case TOK_LT:      result = vval_bool(l < r); break;
        case TOK_GT:      result = vval_bool(l > r); break;
        case TOK_LTE:     result = vval_bool(l <= r); break;
        case TOK_GTE:     result = vval_bool(l >= r); break;
        default:
            result = vval_error("unsupported operator for floats");
        }
    }

    else if (node->binary.op == TOK_EQ) {
        result = vval_bool(vval_equal(left, right));
    }
    else if (node->binary.op == TOK_NEQ) {
        result = vval_bool(!vval_equal(left, right));
    }

    else if (node->binary.op == TOK_REGEX_MATCH) {
        result = vval_error("=~ requires string operands");
    }

    else if (node->binary.op == TOK_AND) {
        result = vval_bool(vval_truthy(left) && vval_truthy(right));
    }
    else if (node->binary.op == TOK_OR) {
        result = vval_bool(vval_truthy(left) || vval_truthy(right));
    }

    else {
        result = vval_error("type mismatch in binary expression");
    }

    vval_release(left);
    vval_release(right);
    return result;
}

/* Main AST dispatch: walks every node type (literals, calls, pipes, control flow, etc.) */
static VexValue *eval_node(EvalCtx *ctx, ASTNode *node) {
    if (!node) return vval_null();

    switch (node->kind) {
    case AST_LITERAL:
        return vval_retain(node->literal);

    case AST_IDENT: {

        if (node->name[0] == '?' && node->name[1] == '\0')
            return vval_int(ctx->last_exit_code);
        if (node->name[0] == '$' && node->name[1] == '\0')
            return vval_int((int64_t)getpid());
        if (node->name[0] == '@' && node->name[1] == '\0') {
            VexValue *argv = scope_get(ctx->current, "argv");
            if (!argv) argv = scope_get(ctx->global, "argv");
            return argv ? vval_retain(argv) : vval_list();
        }

        /* $in: exposes the previous pipeline stage's output to the current stage */
        if (node->name[0] == 'i' && node->name[1] == 'n' && node->name[2] == '\0') {
            return ctx->pipeline_input ? vval_retain(ctx->pipeline_input) : vval_null();
        }

        VexValue *v = scope_get(ctx->current, node->name);
        if (v) return vval_retain(v);

        const char *env_val = getenv(node->name);
        if (env_val) return vval_string_cstr(env_val);

        /* Script commands registered via def-cmd (no-arg invocation) */
        VexValue *scmd_cl = script_cmd_get_closure(node->name);
        if (scmd_cl) {
            VexValue *call_args[1];
            call_args[0] = ctx->pipeline_input ? vval_retain(ctx->pipeline_input) : vval_null();
            VexValue *result = eval_call_closure(ctx, scmd_cl, call_args, 1);
            vval_release(call_args[0]);
            return result;
        }

        /* In a pipeline, treat unknown idents as bare strings (command args) */
        if (ctx->pipeline_input) {
            return vval_string_cstr(node->name);
        }

        vex_err("undefined variable: %s", node->name);

        size_t bc = builtin_count();
        const char **names = malloc(bc * sizeof(char *));
        for (size_t i = 0; i < bc; i++) names[i] = builtin_name(i);
        const char *suggestion = vex_closest_match(node->name, names, bc, 3);
        if (suggestion) {
            fprintf(stderr, "  Did you mean: \033[1;32m%s\033[0m\n\n", suggestion);
        }
        free(names);
        ctx->had_error = true;
        return vval_null();
    }

    case AST_UNARY: {
        VexValue *operand = eval(ctx, node->unary.operand);
        VexValue *result;
        if (node->unary.op == TOK_MINUS) {
            if (operand->type == VEX_VAL_INT)
                result = vval_int(-operand->integer);
            else if (operand->type == VEX_VAL_FLOAT)
                result = vval_float(-operand->floating);
            else
                result = vval_error("cannot negate non-numeric value");
        } else if (node->unary.op == TOK_NOT) {
            result = vval_bool(!vval_truthy(operand));
        } else {
            result = vval_error("unknown unary operator");
        }
        vval_release(operand);
        return result;
    }

    case AST_BINARY:
        return eval_binary(ctx, node);

    case AST_LET:
    case AST_MUT: {
        VexValue *val = eval(ctx, node->binding.init);
        if (val && val->type == VEX_VAL_ERROR && ctx->had_error) {

            return val;
        }
        scope_set(ctx->current, node->binding.var_name, val);
        vval_release(val);
        return vval_null();
    }

    case AST_ASSIGN: {
        VexValue *val = eval(ctx, node->assign.value);
        if (node->assign.target->kind == AST_IDENT) {
            if (!scope_update(ctx->current, node->assign.target->name, val)) {
                vex_err("cannot assign to undefined variable: %s",
                        node->assign.target->name);
                ctx->had_error = true;
            }
        }
        vval_release(val);
        return vval_null();
    }

    case AST_IF: {
        VexValue *cond = eval(ctx, node->if_stmt.cond);
        bool truthy = vval_truthy(cond);
        vval_release(cond);
        if (truthy) {
            return eval(ctx, node->if_stmt.then_block);
        } else if (node->if_stmt.else_block) {
            return eval(ctx, node->if_stmt.else_block);
        }
        return vval_null();
    }

    case AST_FOR: {
        VexValue *iter = eval(ctx, node->for_stmt.iter);
        if (!iter) return vval_null();
        VexValue *result = vval_null();
        if (iter->type == VEX_VAL_LIST) {
            Scope *loop_scope = scope_new(ctx->current);
            ctx->current = loop_scope;
            for (size_t i = 0; i < iter->list.len; i++) {
                scope_set(ctx->current, node->for_stmt.var_name, iter->list.data[i]);
                vval_release(result);
                result = eval(ctx, node->for_stmt.body);
                if (ctx->flow == FLOW_BREAK) { ctx->flow = FLOW_NONE; break; }
                if (ctx->flow == FLOW_CONTINUE) { ctx->flow = FLOW_NONE; continue; }
                if (ctx->flow == FLOW_RETURN) break;
            }
            ctx->current = loop_scope->parent;
            scope_free(loop_scope);
        } else if (iter->type == VEX_VAL_RANGE) {
            Scope *loop_scope = scope_new(ctx->current);
            ctx->current = loop_scope;
            int64_t start = iter->range.start;
            int64_t end = iter->range.end;
            bool excl = iter->range.exclusive;
            for (int64_t i = start; excl ? i < end : i <= end; i++) {
                VexValue *idx = vval_int(i);
                scope_set(ctx->current, node->for_stmt.var_name, idx);
                vval_release(idx);
                vval_release(result);
                result = eval(ctx, node->for_stmt.body);
                if (ctx->flow == FLOW_BREAK) { ctx->flow = FLOW_NONE; break; }
                if (ctx->flow == FLOW_CONTINUE) { ctx->flow = FLOW_NONE; continue; }
                if (ctx->flow == FLOW_RETURN) break;
            }
            ctx->current = loop_scope->parent;
            scope_free(loop_scope);
        }
        vval_release(iter);
        return result;
    }

    case AST_WHILE: {
        VexValue *result = vval_null();
        for (;;) {
            VexValue *cond = eval(ctx, node->loop_stmt.cond);
            bool truthy = vval_truthy(cond);
            vval_release(cond);
            if (!truthy) break;
            vval_release(result);
            result = eval(ctx, node->loop_stmt.body);
            if (ctx->flow == FLOW_BREAK) { ctx->flow = FLOW_NONE; break; }
            if (ctx->flow == FLOW_CONTINUE) { ctx->flow = FLOW_NONE; continue; }
            if (ctx->flow == FLOW_RETURN) break;
        }
        return result;
    }

    case AST_LOOP: {
        VexValue *result = vval_null();
        for (;;) {
            vval_release(result);
            result = eval(ctx, node->loop_stmt.body);
            if (ctx->flow == FLOW_BREAK) { ctx->flow = FLOW_NONE; break; }
            if (ctx->flow == FLOW_CONTINUE) { ctx->flow = FLOW_NONE; continue; }
            if (ctx->flow == FLOW_RETURN) break;
        }
        return result;
    }

    case AST_BREAK:
        ctx->flow = FLOW_BREAK;
        return vval_null();

    case AST_CONTINUE:
        ctx->flow = FLOW_CONTINUE;
        return vval_null();

    case AST_RETURN: {
        if (node->ret_val) {
            ctx->flow_value = eval(ctx, node->ret_val);
        }
        ctx->flow = FLOW_RETURN;
        return vval_null();
    }

    case AST_FN: {
        VexValue *fn = vval_alloc_local(VEX_VAL_CLOSURE);
        fn->closure.params = (ASTNode *)node->fn.params;
        fn->closure.body = node->fn.body;
        fn->closure.env = ctx->current;
        fn->closure.param_count = node->fn.param_count;
        if (node->fn.fn_name) {
            scope_set(ctx->current, node->fn.fn_name, fn);
            vval_release(fn);
            return vval_null();
        }
        return fn;
    }

    case AST_BLOCK: {
        VexValue *result = vval_null();
        for (size_t i = 0; i < node->block.count; i++) {
            vval_release(result);
            result = eval(ctx, node->block.stmts[i]);
            if (ctx->had_error || ctx->flow != FLOW_NONE) break;
        }
        return result;
    }

    case AST_LIST: {
        VexValue *list = vval_list();
        for (size_t i = 0; i < node->list.count; i++) {
            VexValue *item = eval(ctx, node->list.items[i]);
            vval_list_push(list, item);
            vval_release(item);
        }
        return list;
    }

    case AST_RECORD: {
        VexValue *rec = vval_record();
        for (size_t i = 0; i < node->record.count; i++) {
            VexValue *val = eval(ctx, node->record.values[i]);
            vval_record_set(rec, node->record.keys[i], val);
            vval_release(val);
        }
        return rec;
    }

    case AST_FIELD_ACCESS: {
        VexValue *obj = eval(ctx, node->field.object);
        if (!obj) return vval_null();
        if (obj->type != VEX_VAL_RECORD) {
            vex_err("cannot access field '%s' on %s",
                    node->field.field, vval_type_name(obj->type));
            vval_release(obj);
            return vval_null();
        }
        VexValue *val = vval_record_get(obj, node->field.field);
        VexValue *result = val ? vval_retain(val) : vval_null();
        vval_release(obj);
        return result;
    }

    case AST_CALL: {
        /* Dispatch: try builtin -> plugin -> user closure -> external, in order */
        if (vex_opt_xtrace()) {
            fprintf(stderr, "+ %s", node->call.cmd_name);
            for (size_t i = 0; i < node->call.arg_count; i++) {
                if (node->call.args[i]->kind == AST_LITERAL &&
                    node->call.args[i]->literal->type == VEX_VAL_STRING) {
                    fprintf(stderr, " %s",
                            vstr_data(&node->call.args[i]->literal->string));
                } else {
                    fprintf(stderr, " <expr>");
                }
            }
            fprintf(stderr, "\n");
        }

        const BuiltinCmd *cmd = builtin_lookup(node->call.cmd_name);
        if (cmd) {

            VexValue **args = NULL;
            if (node->call.arg_count > 0) {
                args = malloc(node->call.arg_count * sizeof(VexValue *));
                for (size_t i = 0; i < node->call.arg_count; i++) {
                    args[i] = eval(ctx, node->call.args[i]);
                }
            }

            int saved_stdout = -1;
            int saved_stdin = -1;
            const Redirect *r = &node->call.redir;
            if (r->stdout_file) {
                if (!r->stdout_append && vex_opt_noclobber()) {
                    struct stat st;
                    if (stat(r->stdout_file, &st) == 0 && S_ISREG(st.st_mode)) {
                        vex_err("cannot overwrite existing file '%s' (noclobber is set; use >| to force)", r->stdout_file);
                        ctx->had_error = true;
                        ctx->last_exit_code = 1;
                        for (size_t i = 0; i < node->call.arg_count; i++)
                            vval_release(args[i]);
                        free(args);
                        return vval_null();
                    }
                }
                saved_stdout = dup(STDOUT_FILENO);
                int flags = O_WRONLY | O_CREAT | (r->stdout_append ? O_APPEND : O_TRUNC);
                int fd = open(r->stdout_file, flags, 0644);
                if (fd >= 0) {
                    dup2(fd, STDOUT_FILENO);
                    close(fd);
                }
            }
            if (r->stdin_string) {
                saved_stdin = dup(STDIN_FILENO);
                int pipefd[2];
                if (pipe(pipefd) == 0) {
                    size_t len = strlen(r->stdin_string);
                    write(pipefd[1], r->stdin_string, len);
                    write(pipefd[1], "\n", 1);
                    close(pipefd[1]);
                    dup2(pipefd[0], STDIN_FILENO);
                    close(pipefd[0]);
                }
            } else if (r->stdin_file) {
                saved_stdin = dup(STDIN_FILENO);
                int fd = open(r->stdin_file, O_RDONLY);
                if (fd >= 0) {
                    dup2(fd, STDIN_FILENO);
                    close(fd);
                }
            }
            VexValue *result = cmd->fn(ctx, ctx->pipeline_input, args,
                                       node->call.arg_count);

            if (saved_stdout >= 0) {
                dup2(saved_stdout, STDOUT_FILENO);
                close(saved_stdout);
            }

            if (saved_stdin >= 0) {
                dup2(saved_stdin, STDIN_FILENO);
                close(saved_stdin);
            }
            for (size_t i = 0; i < node->call.arg_count; i++) {
                vval_release(args[i]);
            }
            free(args);
            return result;
        }

        if (plugin_cmd_exists(node->call.cmd_name)) {
            VexValue **args = NULL;
            if (node->call.arg_count > 0) {
                args = malloc(node->call.arg_count * sizeof(VexValue *));
                for (size_t i = 0; i < node->call.arg_count; i++)
                    args[i] = eval(ctx, node->call.args[i]);
            }
            VexValue *result = plugin_cmd_exec(node->call.cmd_name,
                                               ctx->pipeline_input, args,
                                               node->call.arg_count);
            for (size_t i = 0; i < node->call.arg_count; i++)
                vval_release(args[i]);
            free(args);
            return result;
        }

        /* Script commands registered via def-cmd */
        VexValue *scmd_closure = script_cmd_get_closure(node->call.cmd_name);
        if (scmd_closure) {
            size_t total = node->call.arg_count + 1;
            VexValue **call_args = malloc(total * sizeof(VexValue *));
            call_args[0] = ctx->pipeline_input ? vval_retain(ctx->pipeline_input) : vval_null();
            for (size_t i = 0; i < node->call.arg_count; i++)
                call_args[i + 1] = eval(ctx, node->call.args[i]);
            VexValue *result = eval_call_closure(ctx, scmd_closure, call_args, total);
            for (size_t i = 0; i < total; i++)
                vval_release(call_args[i]);
            free(call_args);
            return result;
        }

        VexValue *fn = scope_get(ctx->current, node->call.cmd_name);
        if (fn && fn->type == VEX_VAL_CLOSURE) {
            VexValue **call_args = NULL;
            if (node->call.arg_count > 0) {
                call_args = malloc(node->call.arg_count * sizeof(VexValue *));
                for (size_t i = 0; i < node->call.arg_count; i++)
                    call_args[i] = eval(ctx, node->call.args[i]);
            }
            VexValue *result = eval_call_closure(ctx, fn, call_args,
                                                 node->call.arg_count);
            for (size_t i = 0; i < node->call.arg_count; i++)
                vval_release(call_args[i]);
            free(call_args);
            return result;
        }

        char *ext_path = find_in_path(node->call.cmd_name);
        if (!ext_path) {
            vex_err("command not found: %s", node->call.cmd_name);
            suggest_command(node->call.cmd_name);
            ctx->had_error = true;
            ctx->last_exit_code = 127;
            return vval_null();
        }
        free(ext_path);

        char **argv = build_argv(ctx, node);
        if (ctx->in_pipeline) {
            VexValue *result = exec_external_capture(node->call.cmd_name,
                                                     argv, STDIN_FILENO);
            free_argv(argv);
            return result;
        }
        const Redirect *r = (node->call.redir.stdout_file || node->call.redir.stdin_file ||
                             node->call.redir.stdin_string ||
                             node->call.redir.stderr_file || node->call.redir.stderr_to_stdout)
                            ? &node->call.redir : NULL;
        ctx->last_exit_code = exec_external_redir(node->call.cmd_name, argv,
                                                   STDIN_FILENO, STDOUT_FILENO, r);
        free_argv(argv);
        return vval_int(ctx->last_exit_code);
    }

    case AST_EXTERNAL_CALL: {

        char *ext_path = find_in_path(node->call.cmd_name);
        if (!ext_path) {
            vex_err("command not found: %s", node->call.cmd_name);
            suggest_command(node->call.cmd_name);
            ctx->had_error = true;
            ctx->last_exit_code = 127;
            return vval_null();
        }
        free(ext_path);

        char **argv = build_argv(ctx, node);

        if (ctx->in_pipeline) {
            VexValue *result = exec_external_capture(node->call.cmd_name,
                                                     argv, STDIN_FILENO);
            free_argv(argv);
            return result;
        }
        const Redirect *r = (node->call.redir.stdout_file || node->call.redir.stdin_file ||
                             node->call.redir.stdin_string ||
                             node->call.redir.stderr_file || node->call.redir.stderr_to_stdout)
                            ? &node->call.redir : NULL;
        ctx->last_exit_code = exec_external_redir(node->call.cmd_name, argv,
                                                   STDIN_FILENO, STDOUT_FILENO, r);
        free_argv(argv);
        return vval_int(ctx->last_exit_code);
    }

    case AST_PIPELINE: {
        /* Value pipeline: thread each stage's result as $in to the next stage */
        VexValue *saved_input = ctx->pipeline_input;
        bool saved_in_pipeline = ctx->in_pipeline;
        VexValue *result = NULL;

        for (size_t i = 0; i < node->pipeline.count; i++) {
            ctx->pipeline_input = result;

            ctx->in_pipeline = (i < node->pipeline.count - 1);
            VexValue *stage_result = eval(ctx, node->pipeline.stages[i]);
            if (result) vval_release(result);
            result = stage_result;
        }

        ctx->pipeline_input = saved_input;
        ctx->in_pipeline = saved_in_pipeline;
        return result ? result : vval_null();
    }

    case AST_BYTE_PIPELINE: {
        /* Unix-style byte pipe: fork all-external stages with real pipe(2) fds */
        size_t n = node->pipeline.count;
        if (n == 0) return vval_null();

        bool all_external = true;
        for (size_t i = 0; i < n; i++) {
            ASTNode *stage = node->pipeline.stages[i];
            if (stage->kind != AST_EXTERNAL_CALL && stage->kind != AST_CALL)
                all_external = false;
            else if (stage->kind == AST_CALL && builtin_exists(stage->call.cmd_name))
                all_external = false;
        }

        if (!all_external) {

            VexValue *saved_input = ctx->pipeline_input;
            bool saved_in_pipeline = ctx->in_pipeline;
            VexValue *result = NULL;
            for (size_t i = 0; i < n; i++) {
                ctx->pipeline_input = result;
                ctx->in_pipeline = (i < n - 1);
                VexValue *stage_result = eval(ctx, node->pipeline.stages[i]);
                if (result) vval_release(result);
                result = stage_result;
            }
            ctx->pipeline_input = saved_input;
            ctx->in_pipeline = saved_in_pipeline;
            return result ? result : vval_null();
        }

        char ***all_argv = calloc(n, sizeof(char **));
        char **paths = calloc(n, sizeof(char *));
        for (size_t i = 0; i < n; i++) {
            ASTNode *stage = node->pipeline.stages[i];
            paths[i] = find_in_path(stage->call.cmd_name);
            all_argv[i] = build_argv(ctx, stage);
        }

        int prev_pipe_read = -1;
        pid_t *pids = calloc(n, sizeof(pid_t));
        pid_t pgid = 0;

        for (size_t i = 0; i < n; i++) {
            int pipefd[2] = {-1, -1};
            if (i < n - 1) {
                if (pipe(pipefd) < 0) {
                    vex_err("pipe failed: %s", strerror(errno));
                    break;
                }
            }

            fflush(stdout);
            fflush(stderr);
            pid_t pid = fork();
            if (pid < 0) {
                vex_err("fork failed: %s", strerror(errno));
                break;
            }

            if (pid == 0) {

                setpgid(0, pgid > 0 ? pgid : 0);
                signal(SIGINT, SIG_DFL);
                signal(SIGQUIT, SIG_DFL);
                signal(SIGTSTP, SIG_DFL);
                signal(SIGTTIN, SIG_DFL);
                signal(SIGTTOU, SIG_DFL);

                if (prev_pipe_read >= 0) {
                    dup2(prev_pipe_read, STDIN_FILENO);
                    close(prev_pipe_read);
                }

                if (i < n - 1) {
                    close(pipefd[0]);
                    dup2(pipefd[1], STDOUT_FILENO);
                    close(pipefd[1]);
                }

                if (!paths[i]) {
                    fprintf(stderr, "vex: command not found: %s\n",
                            node->pipeline.stages[i]->call.cmd_name);
                    suggest_command(node->pipeline.stages[i]->call.cmd_name);
                    _exit(127);
                }
                execv(paths[i], all_argv[i]);
                _exit(126);
            }

            if (i == 0) pgid = pid;
            setpgid(pid, pgid);
            pids[i] = pid;

            if (prev_pipe_read >= 0) close(prev_pipe_read);

            if (i < n - 1) {
                close(pipefd[1]);
                prev_pipe_read = pipefd[0];
            }
        }

        char pipe_cmd[1024];
        pipe_cmd[0] = '\0';
        for (size_t i = 0; i < n; i++) {
            if (i > 0) strncat(pipe_cmd, " | ", sizeof(pipe_cmd) - strlen(pipe_cmd) - 1);
            strncat(pipe_cmd, node->pipeline.stages[i]->call.cmd_name,
                    sizeof(pipe_cmd) - strlen(pipe_cmd) - 1);
        }

        int pipe_job_id = job_add(pids[0], pgid, pipe_cmd, false);

        if (isatty(STDIN_FILENO)) {
            tcsetpgrp(STDIN_FILENO, pgid);
        }

        int last_status = 0;
        bool pipeline_stopped = false;
        for (size_t i = 0; i < n; i++) {
            if (pids[i] > 0) {
                int status;
                waitpid(pids[i], &status, WUNTRACED);
                if (WIFSTOPPED(status)) {
                    pipeline_stopped = true;
                } else if (i == n - 1) {
                    if (WIFEXITED(status))
                        last_status = WEXITSTATUS(status);
                    else if (WIFSIGNALED(status))
                        last_status = 128 + WTERMSIG(status);
                }
            }
        }
        free(pids);

        for (size_t i = 0; i < n; i++) {
            free_argv(all_argv[i]);
            free(paths[i]);
        }
        free(all_argv);
        free(paths);

        if (isatty(STDIN_FILENO)) {
            tcsetpgrp(STDIN_FILENO, job_shell_pgid());
        }

        if (pipeline_stopped) {
            Job *j = job_get(pipe_job_id);
            if (j) {
                j->status = JOB_STOPPED;
                j->background = true;
                fprintf(stderr, "\n[%d]  Stopped\t\t%s\n", j->id, j->cmd);
            }
            ctx->last_exit_code = 148;
            return vval_int(148);
        }

        if (pipe_job_id >= 0) job_remove(pipe_job_id);
        ctx->last_exit_code = last_status;
        return vval_int(last_status);
    }

    case AST_INDEX: {
        VexValue *obj = eval(ctx, node->index_expr.object);
        VexValue *idx = eval(ctx, node->index_expr.index);
        if (!obj || !idx) {
            vval_release(obj);
            vval_release(idx);
            return vval_null();
        }
        VexValue *result = vval_null();

        if (obj->type == VEX_VAL_LIST && idx->type == VEX_VAL_INT) {
            int64_t i = idx->integer;
            if (i < 0) i += (int64_t)obj->list.len;
            if (i >= 0 && (size_t)i < obj->list.len) {
                result = vval_retain(obj->list.data[i]);
            }
        } else if (obj->type == VEX_VAL_RECORD && idx->type == VEX_VAL_STRING) {
            VexValue *val = vval_record_get(obj, vstr_data(&idx->string));
            if (val) result = vval_retain(val);
        } else if (obj->type == VEX_VAL_STRING && idx->type == VEX_VAL_INT) {

            const char *s = vstr_data(&obj->string);
            int64_t i = idx->integer;
            size_t len = vstr_len(&obj->string);
            if (i < 0) i += (int64_t)len;
            if (i >= 0 && (size_t)i < len) {
                result = vval_string(vstr_newn(s + i, 1));
            }
        }

        vval_release(obj);
        vval_release(idx);
        return result;
    }

    case AST_RANGE: {
        VexValue *start = eval(ctx, node->range.start);
        VexValue *end = eval(ctx, node->range.end);
        VexValue *result;
        if (start->type == VEX_VAL_INT && end->type == VEX_VAL_INT) {
            result = vval_range(start->integer, end->integer, node->range.exclusive);
        } else {
            result = vval_error("range requires integer bounds");
        }
        vval_release(start);
        vval_release(end);
        return result;
    }

    case AST_STRING_INTERP: {
        VexStr out = vstr_empty();
        for (size_t i = 0; i < node->interp.count; i++) {
            VexValue *part = eval(ctx, node->interp.parts[i]);
            VexStr s = vval_to_str(part);
            vstr_append_str(&out, &s);
            vstr_free(&s);
            vval_release(part);
        }
        return vval_string(out);
    }

    case AST_MATCH: {

        VexValue *subject = eval(ctx, node->pipeline.stages[0]);
        size_t arm_count = (node->pipeline.count - 1) / 2;
        VexValue *result = vval_null();

        for (size_t i = 0; i < arm_count; i++) {
            ASTNode *pattern = node->pipeline.stages[1 + i * 2];
            ASTNode *body = node->pipeline.stages[1 + i * 2 + 1];

            if (pattern->kind == AST_LITERAL && pattern->literal == NULL) {
                vval_release(result);
                result = eval(ctx, body);
                break;
            }

            VexValue *pat_val = eval(ctx, pattern);
            bool matched = false;

            if (pat_val->type == VEX_VAL_RANGE && subject->type == VEX_VAL_INT) {
                int64_t v = subject->integer;
                if (pat_val->range.exclusive)
                    matched = (v >= pat_val->range.start && v < pat_val->range.end);
                else
                    matched = (v >= pat_val->range.start && v <= pat_val->range.end);
            }

            else if (pat_val->type == subject->type) {
                if (pat_val->type == VEX_VAL_INT)
                    matched = (pat_val->integer == subject->integer);
                else if (pat_val->type == VEX_VAL_STRING)
                    matched = vstr_eq(&pat_val->string, &subject->string);
                else if (pat_val->type == VEX_VAL_BOOL)
                    matched = (pat_val->boolean == subject->boolean);
            }

            vval_release(pat_val);
            if (matched) {
                vval_release(result);
                result = eval(ctx, body);
                break;
            }
        }

        vval_release(subject);
        return result;
    }

    case AST_TRY_CATCH: {
        bool saved_error = ctx->had_error;
        ctx->had_error = false;
        VexValue *result = eval(ctx, node->try_catch.try_block);

        if (ctx->had_error || (result && result->type == VEX_VAL_ERROR)) {
            ctx->had_error = false;

            Scope *catch_scope = scope_new(ctx->current);
            if (result && result->type == VEX_VAL_ERROR) {
                VexValue *msg = vval_string_cstr(result->error->message);
                scope_set(catch_scope, node->try_catch.catch_var, msg);
                vval_release(msg);
            } else {
                VexValue *msg = vval_string_cstr("unknown error");
                scope_set(catch_scope, node->try_catch.catch_var, msg);
                vval_release(msg);
            }
            vval_release(result);

            ctx->current = catch_scope;
            result = eval(ctx, node->try_catch.catch_block);
            ctx->current = catch_scope->parent;
            scope_free(catch_scope);
        }
        ctx->had_error = saved_error;
        return result;
    }

    case AST_ERROR_PROPAGATE: {
        VexValue *val = eval(ctx, node->propagate_expr);
        if (val && val->type == VEX_VAL_ERROR) {

            ctx->flow = FLOW_RETURN;
            ctx->flow_value = vval_retain(val);
        }
        return val;
    }

    case AST_USE: {
        const char *path = node->use_stmt.path;

        if (node->use_stmt.is_plugin) {
            if (plugin_load(path)) {
                return vval_null();
            }
            ctx->had_error = true;
            return vval_error("plugin load failed");
        }

        char fullpath[4096];
        FILE *f = fopen(path, "r");
        if (!f) {
            snprintf(fullpath, sizeof(fullpath), "%s.vex", path);
            f = fopen(fullpath, "r");
        }
        if (!f) {
            vex_err("use: cannot open '%s'", path);
            return vval_error("module not found");
        }

        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *source = malloc((size_t)size + 1);
        fread(source, 1, (size_t)size, f);
        source[size] = '\0';
        fclose(f);

        Parser parser = parser_init(source, ctx->arena);
        ASTNode *program = parser_parse(&parser);

        VexValue *result = vval_null();
        if (!parser.had_error) {
            vval_release(result);
            result = eval(ctx, program);
        }
        free(source);
        return result;
    }

    case AST_BACKGROUND: {
        /* Run command in background process group via &-syntax */
        ASTNode *inner = node->bg_stmt;

        if (inner->kind == AST_CALL || inner->kind == AST_EXTERNAL_CALL) {
            char **argv = build_argv(ctx, inner);
            int job_id = exec_external_bg(inner->call.cmd_name, argv,
                                           inner->call.cmd_name);
            free_argv(argv);
            return vval_int(job_id);
        }

        return eval(ctx, inner);
    }

    case AST_COND_CHAIN: {
        VexValue *result = eval(ctx, node->cond_chain.cmds[0]);
        for (size_t i = 0; i < node->cond_chain.cmd_count - 1; i++) {
            bool success = !ctx->had_error && result->type != VEX_VAL_ERROR &&
                           ctx->last_exit_code == 0;
            TokenType op = node->cond_chain.ops[i];
            if ((op == TOK_AND_AND && success) || (op == TOK_OR_OR && !success)) {
                vval_release(result);
                ctx->had_error = false;
                result = eval(ctx, node->cond_chain.cmds[i + 1]);
            } else {

            }
        }
        return result;
    }

    case AST_CMD_SUBST: {
        /* $(...) capture: redirect stdout to pipe, eval inner, return captured string */
        int pipefd[2];
        if (pipe(pipefd) == -1) return vval_error("pipe failed");

        int saved_stdout = dup(STDOUT_FILENO);
        if (saved_stdout < 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            return vval_error("dup failed");
        }
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        VexValue *result = eval(ctx, node->subst_cmd);

        if (result && result->type != VEX_VAL_NULL) {
            ASTNode *inner = node->subst_cmd;
            bool is_cmd = (inner->kind == AST_CALL || inner->kind == AST_EXTERNAL_CALL ||
                          inner->kind == AST_PIPELINE || inner->kind == AST_BYTE_PIPELINE ||
                          inner->kind == AST_COND_CHAIN);
            if (!is_cmd) {
                vval_print(result, stdout);
            }
        }
        fflush(stdout);
        vval_release(result);

        dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);

        VexStr captured = vstr_new("");
        char buf[4096];
        ssize_t nr;
        while ((nr = read(pipefd[0], buf, sizeof(buf))) > 0) {
            vstr_append(&captured, buf, (size_t)nr);
        }
        close(pipefd[0]);

        const char *data = vstr_data(&captured);
        size_t len = vstr_len(&captured);
        while (len > 0 && data[len - 1] == '\n') len--;
        VexValue *val = vval_string(vstr_newn(data, len));
        vstr_free(&captured);
        return val;
    }

    case AST_PROC_SUBST: {
        /* <(...) process substitution: fork child, return /dev/fd/N path */
        int pipefd[2];
        if (pipe(pipefd) == -1) return vval_error("pipe failed");

        fflush(stdout);
        fflush(stderr);
        pid_t pid = fork();
        if (pid < 0) {
            close(pipefd[0]);
            close(pipefd[1]);
            return vval_error("fork failed");
        }

        if (pid == 0) {

            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[1]);

            signal(SIGINT, SIG_DFL);
            signal(SIGQUIT, SIG_DFL);

            VexValue *result = eval(ctx, node->subst_cmd);

            if (result && result->type != VEX_VAL_NULL) {
                ASTNode *inner = node->subst_cmd;
                bool is_cmd = (inner->kind == AST_CALL || inner->kind == AST_EXTERNAL_CALL ||
                              inner->kind == AST_PIPELINE || inner->kind == AST_BYTE_PIPELINE);
                if (!is_cmd) {
                    vval_print(result, stdout);
                    printf("\n");
                }
            }
            fflush(stdout);
            vval_release(result);
            _exit(0);
        }

        close(pipefd[1]);
        char fd_path[64];
        snprintf(fd_path, sizeof(fd_path), "/dev/fd/%d", pipefd[0]);

        waitpid(pid, NULL, WNOHANG);
        return vval_string_cstr(fd_path);
    }

    case AST_SUBSHELL: {
        /* Fork a subshell, eval block in child, wait and return exit code */
        fflush(stdout);
        fflush(stderr);
        pid_t pid = fork();
        if (pid < 0) {
            vex_err("subshell: fork failed");
            return vval_error("fork failed");
        }
        if (pid == 0) {

            VexValue *result = vval_null();
            for (size_t i = 0; i < node->block.count; i++) {
                vval_release(result);
                result = eval_node(ctx, node->block.stmts[i]);
            }
            int code = (result && result->type == VEX_VAL_ERROR) ? 1 : 0;
            vval_release(result);
            fflush(stdout);
            fflush(stderr);
            _exit(code);
        }

        int status = 0;
        waitpid(pid, &status, 0);
        ctx->last_exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
        return vval_int(ctx->last_exit_code);
    }

    case AST_PARAM_EXPAND: {
        const char *varname = node->param_expand.var_name;
        const char *operand = node->param_expand.operand;
        int op = node->param_expand.expand_op;

        VexValue *val = scope_get(ctx->current, varname);
        if (val) {
            vval_retain(val);
        } else {
            const char *ev = getenv(varname);
            if (ev) val = vval_string_cstr(ev);
        }
        bool is_set = (val != NULL && val->type != VEX_VAL_NULL);
        bool is_empty = !is_set ||
            (val && val->type == VEX_VAL_STRING &&
             vstr_len(&val->string) == 0);

        switch (op) {
        case PEXP_LENGTH: {
            int64_t r = 0;
            if (is_set && val->type == VEX_VAL_STRING) {
                r = (int64_t)vstr_len(&val->string);
            } else if (is_set) {
                VexStr s = vval_to_str(val);
                r = (int64_t)vstr_len(&s);
                vstr_free(&s);
            }
            if (val) vval_release(val);
            return vval_int(r);
        }
        case PEXP_DEFAULT:
            if (is_empty) {
                if (val) vval_release(val);
                return vval_string_cstr(operand ? operand : "");
            }
            return val;
        case PEXP_ASSIGN:
            if (is_empty) {
                if (val) vval_release(val);
                VexValue *v = vval_string_cstr(operand ? operand : "");
                scope_set(ctx->current, varname, v);
                return v;
            }
            return val;
        case PEXP_ERROR:
            if (is_empty) {
                if (val) vval_release(val);
                vex_err("%s: %s", varname,
                        operand ? operand : "parameter null or not set");
                ctx->had_error = true;
                return vval_error(operand ? operand
                                          : "parameter null or not set");
            }
            return val;
        case PEXP_ALTVAL:
            if (val) vval_release(val);
            if (!is_empty)
                return vval_string_cstr(operand ? operand : "");
            return vval_string_cstr("");
        case PEXP_TRIM_L:
        case PEXP_TRIM_LL: {
            if (!is_set || val->type != VEX_VAL_STRING) {
                if (val) vval_release(val);
                return vval_string_cstr("");
            }
            const char *s = vstr_data(&val->string);
            size_t slen = vstr_len(&val->string);
            if (!operand || !operand[0]) return val;
            if (op == PEXP_TRIM_L) {
                for (size_t i = 0; i <= slen; i++) {
                    char *tmp = strndup(s, i);
                    if (fnmatch(operand, tmp, 0) == 0) {
                        free(tmp);
                        VexValue *r = vval_string_cstr(s + i);
                        vval_release(val);
                        return r;
                    }
                    free(tmp);
                }
            } else {
                for (size_t i = slen; i > 0; i--) {
                    char *tmp = strndup(s, i);
                    if (fnmatch(operand, tmp, 0) == 0) {
                        free(tmp);
                        VexValue *r = vval_string_cstr(s + i);
                        vval_release(val);
                        return r;
                    }
                    free(tmp);
                }
            }
            return val;
        }
        case PEXP_TRIM_R:
        case PEXP_TRIM_RR: {
            if (!is_set || val->type != VEX_VAL_STRING) {
                if (val) vval_release(val);
                return vval_string_cstr("");
            }
            const char *s = vstr_data(&val->string);
            size_t slen = vstr_len(&val->string);
            if (!operand || !operand[0]) return val;
            if (op == PEXP_TRIM_R) {
                for (size_t i = slen; i > 0; i--) {
                    if (fnmatch(operand, s + i, 0) == 0) {
                        VexValue *r = vval_string(vstr_newn(s, i));
                        vval_release(val);
                        return r;
                    }
                }
                if (fnmatch(operand, s, 0) == 0) {
                    vval_release(val);
                    return vval_string_cstr("");
                }
            } else {
                for (size_t i = 0; i <= slen; i++) {
                    if (fnmatch(operand, s + i, 0) == 0) {
                        VexValue *r = vval_string(vstr_newn(s, i));
                        vval_release(val);
                        return r;
                    }
                }
            }
            return val;
        }
        case PEXP_REPLACE:
        case PEXP_REPLACE_ALL: {
            if (!is_set || val->type != VEX_VAL_STRING) {
                if (val) vval_release(val);
                return vval_string_cstr("");
            }
            const char *s = vstr_data(&val->string);
            if (!operand) return val;
            char *pat = strdup(operand);
            if (!pat) return val;
            char *rep = "";
            char *slash = strchr(pat, '/');
            if (slash) { *slash = '\0'; rep = slash + 1; }
            size_t pat_len = strlen(pat);
            VexStr out = vstr_empty();
            bool did_replace = false;
            while (*s) {
                if (pat_len > 0 && strncmp(s, pat, pat_len) == 0) {
                    vstr_append_cstr(&out, rep);
                    s += pat_len;
                    did_replace = true;
                    if (op == PEXP_REPLACE) {
                        vstr_append_cstr(&out, s);
                        break;
                    }
                } else {
                    vstr_append(&out, s, 1);
                    s++;
                }
            }
            (void)did_replace;
            free(pat);
            vval_release(val);
            return vval_string(out);
        }
        case PEXP_UPPER: {
            if (!is_set || val->type != VEX_VAL_STRING) {
                if (val) vval_release(val);
                return vval_string_cstr("");
            }
            const char *s = vstr_data(&val->string);
            size_t slen = vstr_len(&val->string);
            char *up = malloc(slen + 1);
            for (size_t i = 0; i < slen; i++)
                up[i] = (char)toupper((unsigned char)s[i]);
            up[slen] = '\0';
            VexValue *r = vval_string(vstr_newn(up, slen));
            free(up);
            vval_release(val);
            return r;
        }
        case PEXP_LOWER: {
            if (!is_set || val->type != VEX_VAL_STRING) {
                if (val) vval_release(val);
                return vval_string_cstr("");
            }
            const char *s = vstr_data(&val->string);
            size_t slen = vstr_len(&val->string);
            char *lo = malloc(slen + 1);
            for (size_t i = 0; i < slen; i++)
                lo[i] = (char)tolower((unsigned char)s[i]);
            lo[slen] = '\0';
            VexValue *r = vval_string(vstr_newn(lo, slen));
            free(lo);
            vval_release(val);
            return r;
        }
        case PEXP_SLICE: {
            if (!is_set || val->type != VEX_VAL_STRING) {
                if (val) vval_release(val);
                return vval_string_cstr("");
            }
            const char *s = vstr_data(&val->string);
            size_t slen = vstr_len(&val->string);
            if (!operand) return val;
            long offset = strtol(operand, NULL, 10);
            const char *colon = strchr(operand, ':');
            long length = -1;
            if (colon) length = strtol(colon + 1, NULL, 10);
            if (offset < 0) offset = (long)slen + offset;
            if (offset < 0) offset = 0;
            if ((size_t)offset >= slen) {
                vval_release(val);
                return vval_string_cstr("");
            }
            size_t avail = slen - (size_t)offset;
            size_t take = (length >= 0 && (size_t)length < avail)
                ? (size_t)length : avail;
            VexValue *r = vval_string(vstr_newn(s + offset, take));
            vval_release(val);
            return r;
        }
        default:
            if (is_set) return val;
            if (val) vval_release(val);
            return vval_string_cstr("");
        }
    }

    default:
        vex_err("unimplemented AST node: %d", node->kind);
        return vval_null();
    }
}

/* Public entry point: evaluate an AST node and return its value */
VexValue *eval(EvalCtx *ctx, ASTNode *node) {
    return eval_node(ctx, node);
}

/* Public entry point for pipeline evaluation (delegates to eval_node) */
VexValue *eval_pipeline(EvalCtx *ctx, ASTNode *node) {
    return eval_node(ctx, node);
}
