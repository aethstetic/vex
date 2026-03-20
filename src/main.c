#include "vex.h"
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>
#include <pwd.h>

#define VEX_VERSION "0.1.2"

static char *get_history_path(void) {
    const char *home = getenv("HOME");
    if (!home) return NULL;
    size_t len = strlen(home) + 32;
    char *path = malloc(len);
    if (!path) return NULL;
    snprintf(path, len, "%s/.config/vex/history", home);
    return path;
}

static const char *find_git_dir(void) {
    static char git_dir[4096];
    static char cached_cwd[4096];
    static bool has_cached = false;
    static bool cached_found = false;

    char cwd[4096];
    if (!getcwd(cwd, sizeof(cwd))) return NULL;

    if (has_cached && strcmp(cwd, cached_cwd) == 0)
        return cached_found ? git_dir : NULL;

    memcpy(cached_cwd, cwd, sizeof(cached_cwd));
    has_cached = true;

    char *dir = cwd;
    while (dir[0]) {
        snprintf(git_dir, sizeof(git_dir), "%s/.git", dir);
        struct stat st;
        if (stat(git_dir, &st) == 0) {
            cached_found = true;
            return git_dir;
        }
        char *slash = strrchr(dir, '/');
        if (!slash || slash == dir) break;
        *slash = '\0';
    }
    cached_found = false;
    return NULL;
}

static const char *get_git_branch(void) {
    static char branch[256];
    const char *gd = find_git_dir();
    if (!gd) return NULL;

    char path[4096];
    snprintf(path, sizeof(path), "%s/HEAD", gd);
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    char buf[512];
    if (fgets(buf, sizeof(buf), f)) {
        fclose(f);
        if (strncmp(buf, "ref: refs/heads/", 16) == 0) {
            size_t len = strlen(buf + 16);
            if (len > 0 && buf[16 + len - 1] == '\n') len--;
            if (len >= sizeof(branch)) len = sizeof(branch) - 1;
            memcpy(branch, buf + 16, len);
            branch[len] = '\0';
            return branch;
        }

        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') len--;
        if (len > 7) len = 7;
        memcpy(branch, buf, len);
        branch[len] = '\0';
        return branch;
    }
    fclose(f);
    return NULL;
}

static const char *get_git_status(void) {
    static char status[32];
    static struct timespec last_check;
    static char last_cwd[4096];
    static bool has_cached = false;

    char cwd[4096];
    if (has_cached && getcwd(cwd, sizeof(cwd))) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - last_check.tv_sec)
                       + (now.tv_nsec - last_check.tv_nsec) / 1e9;
        if (elapsed < 10.0 && strcmp(cwd, last_cwd) == 0)
            return status;
    }

    const char *gd = find_git_dir();
    if (!gd) { status[0] = '\0'; return ""; }

    FILE *fp = popen("git status --porcelain 2>/dev/null", "r");
    if (!fp) return "";

    bool has_staged = false, has_unstaged = false, has_untracked = false;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '?' && line[1] == '?') has_untracked = true;
        else if (line[0] != ' ' && line[0] != '?') has_staged = true;
        if (line[1] != ' ' && line[1] != '?' && line[1] != '\0' && line[1] != '\n')
            has_unstaged = true;

        if (has_staged && has_unstaged && has_untracked) break;
    }
    pclose(fp);

    char *p = status;
    if (has_staged) *p++ = '+';
    if (has_unstaged) *p++ = '*';
    if (has_untracked) *p++ = '?';
    *p = '\0';

    has_cached = true;
    clock_gettime(CLOCK_MONOTONIC, &last_check);
    if (getcwd(last_cwd, sizeof(last_cwd)) == NULL)
        last_cwd[0] = '\0';
    return status;
}

static struct timespec cmd_start_time;
static double last_cmd_duration_ms = 0.0;
static EditState *repl_editor = NULL;
static EvalCtx *repl_ctx = NULL;

void cmd_timer_start(void) {
    clock_gettime(CLOCK_MONOTONIC, &cmd_start_time);
}

void cmd_timer_stop(void) {
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &end);
    last_cmd_duration_ms = (double)(end.tv_sec - cmd_start_time.tv_sec) * 1000.0
                         + (double)(end.tv_nsec - cmd_start_time.tv_nsec) / 1e6;
}

static const char *format_duration(double ms) {
    static char buf[64];
    if (ms < 1.0) return "";
    if (ms < 1000.0)
        snprintf(buf, sizeof(buf), "%.0fms", ms);
    else if (ms < 60000.0)
        snprintf(buf, sizeof(buf), "%.1fs", ms / 1000.0);
    else
        snprintf(buf, sizeof(buf), "%dm%ds", (int)(ms / 60000.0),
                 ((int)(ms / 1000.0)) % 60);
    return buf;
}

static size_t display_width(const char *s) {
    size_t w = 0;
    bool in_esc = false;
    while (*s) {
        if (*s == '\033') {
            in_esc = true;
        } else if (in_esc) {
            if ((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z'))
                in_esc = false;
        } else {
            int32_t cp = utf8_decode(&s);
            if (cp >= 0) w += (size_t)utf8_charwidth(cp);
            continue;
        }
        s++;
    }
    return w;
}

static void buf_append(char **buf, size_t *len, size_t *cap,
                        const char *s, size_t slen) {
    while (*len + slen + 1 > *cap) {
        *cap = (*cap < 64) ? 128 : *cap * 2;
        char *nb = realloc(*buf, *cap);
        if (!nb) return;
        *buf = nb;
    }
    memcpy(*buf + *len, s, slen);
    *len += slen;
    (*buf)[*len] = '\0';
}

static void buf_appends(char **buf, size_t *len, size_t *cap, const char *s) {
    buf_append(buf, len, cap, s, strlen(s));
}

static const char *get_collapsed_cwd(void) {
    static char collapsed[4096];
    char cwd[4096];
    if (!getcwd(cwd, sizeof(cwd))) return "?";
    const char *home = getenv("HOME");
    if (home && strncmp(cwd, home, strlen(home)) == 0 &&
        (cwd[strlen(home)] == '/' || cwd[strlen(home)] == '\0')) {
        snprintf(collapsed, sizeof(collapsed), "~%s", cwd + strlen(home));
        return collapsed;
    }
    snprintf(collapsed, sizeof(collapsed), "%s", cwd);
    return collapsed;
}

static const char *get_cwd_basename(void) {
    static char base[256];
    char cwd[4096];
    if (!getcwd(cwd, sizeof(cwd))) return "?";
    const char *slash = strrchr(cwd, '/');
    if (slash && slash[1]) {
        snprintf(base, sizeof(base), "%s", slash + 1);
    } else {
        snprintf(base, sizeof(base), "%s", cwd);
    }
    return base;
}

static const char *lookup_color(const char *name, size_t len) {

    if (len == 3 && strncmp(name, "red", 3) == 0) return "\033[31m";
    if (len == 5 && strncmp(name, "green", 5) == 0) return "\033[32m";
    if (len == 6 && strncmp(name, "yellow", 6) == 0) return "\033[33m";
    if (len == 4 && strncmp(name, "blue", 4) == 0) return "\033[34m";
    if (len == 7 && strncmp(name, "magenta", 7) == 0) return "\033[35m";
    if (len == 6 && strncmp(name, "purple", 6) == 0) return "\033[35m";
    if (len == 4 && strncmp(name, "cyan", 4) == 0) return "\033[36m";
    if (len == 5 && strncmp(name, "white", 5) == 0) return "\033[37m";
    if (len == 5 && strncmp(name, "black", 5) == 0) return "\033[30m";
    if (len == 4 && strncmp(name, "bold", 4) == 0) return "\033[1m";
    if (len == 3 && strncmp(name, "dim", 3) == 0) return "\033[2m";
    if (len == 6 && strncmp(name, "italic", 6) == 0) return "\033[3m";
    if (len == 9 && strncmp(name, "underline", 9) == 0) return "\033[4m";
    if (len == 7 && strncmp(name, "reverse", 7) == 0) return "\033[7m";
    if (len == 5 && strncmp(name, "reset", 5) == 0) return "\033[0m";

    if (len == 10 && strncmp(name, "bright_red", 10) == 0) return "\033[91m";
    if (len == 12 && strncmp(name, "bright_green", 12) == 0) return "\033[92m";
    if (len == 13 && strncmp(name, "bright_yellow", 13) == 0) return "\033[93m";
    if (len == 11 && strncmp(name, "bright_blue", 11) == 0) return "\033[94m";
    if (len == 14 && strncmp(name, "bright_magenta", 14) == 0) return "\033[95m";
    if (len == 11 && strncmp(name, "bright_cyan", 11) == 0) return "\033[96m";
    if (len == 12 && strncmp(name, "bright_white", 12) == 0) return "\033[97m";

    if (len == 6 && strncmp(name, "bg_red", 6) == 0) return "\033[41m";
    if (len == 8 && strncmp(name, "bg_green", 8) == 0) return "\033[42m";
    if (len == 9 && strncmp(name, "bg_yellow", 9) == 0) return "\033[43m";
    if (len == 7 && strncmp(name, "bg_blue", 7) == 0) return "\033[44m";
    if (len == 10 && strncmp(name, "bg_magenta", 10) == 0) return "\033[45m";
    if (len == 7 && strncmp(name, "bg_cyan", 7) == 0) return "\033[46m";
    if (len == 8 && strncmp(name, "bg_white", 8) == 0) return "\033[47m";
    if (len == 8 && strncmp(name, "bg_black", 8) == 0) return "\033[40m";

    if (len == 13 && strncmp(name, "bg_bright_red", 13) == 0) return "\033[101m";
    if (len == 15 && strncmp(name, "bg_bright_green", 15) == 0) return "\033[102m";
    if (len == 16 && strncmp(name, "bg_bright_yellow", 16) == 0) return "\033[103m";
    if (len == 14 && strncmp(name, "bg_bright_blue", 14) == 0) return "\033[104m";
    if (len == 13 && strncmp(name, "bg_bright_cyan", 13) == 0) return "\033[106m";
    if (len == 15 && strncmp(name, "bg_bright_white", 15) == 0) return "\033[107m";

    if (len == 13 && strncmp(name, "strikethrough", 13) == 0) return "\033[9m";
    return NULL;
}

static void emit_color_token(char **buf, size_t *len, size_t *cap,
                              const char *tok, size_t tlen) {

    const char *code = lookup_color(tok, tlen);
    if (code) {
        buf_appends(buf, len, cap, code);
        return;
    }

    char tmp[128];
    if (tlen >= sizeof(tmp)) return;
    memcpy(tmp, tok, tlen);
    tmp[tlen] = '\0';

    if (tlen > 3 && strncmp(tmp, "fg:", 3) == 0) {
        int n = atoi(tmp + 3);
        if (n >= 0 && n <= 255) {
            char esc[24];
            snprintf(esc, sizeof(esc), "\033[38;5;%dm", n);
            buf_appends(buf, len, cap, esc);
        }
        return;
    }

    if (tlen > 3 && strncmp(tmp, "bg:", 3) == 0 && tmp[3] >= '0' && tmp[3] <= '9') {
        int n = atoi(tmp + 3);
        if (n >= 0 && n <= 255) {
            char esc[24];
            snprintf(esc, sizeof(esc), "\033[48;5;%dm", n);
            buf_appends(buf, len, cap, esc);
        }
        return;
    }

    if (tlen > 4 && strncmp(tmp, "rgb:", 4) == 0) {
        int r, g, b;
        if (sscanf(tmp + 4, "%d;%d;%d", &r, &g, &b) == 3 &&
            r >= 0 && r <= 255 && g >= 0 && g <= 255 && b >= 0 && b <= 255) {
            char esc[32];
            snprintf(esc, sizeof(esc), "\033[38;2;%d;%d;%dm", r, g, b);
            buf_appends(buf, len, cap, esc);
        }
        return;
    }

    if (tlen > 7 && strncmp(tmp, "bg_rgb:", 7) == 0) {
        int r, g, b;
        if (sscanf(tmp + 7, "%d;%d;%d", &r, &g, &b) == 3 &&
            r >= 0 && r <= 255 && g >= 0 && g <= 255 && b >= 0 && b <= 255) {
            char esc[32];
            snprintf(esc, sizeof(esc), "\033[48;2;%d;%d;%dm", r, g, b);
            buf_appends(buf, len, cap, esc);
        }
        return;
    }

    if (tlen == 7 && tmp[0] == '#') {
        unsigned int r, g, b;
        if (sscanf(tmp + 1, "%02x%02x%02x", &r, &g, &b) == 3) {
            char esc[32];
            snprintf(esc, sizeof(esc), "\033[38;2;%d;%d;%dm", r, g, b);
            buf_appends(buf, len, cap, esc);
        }
        return;
    }

    if (tlen == 10 && strncmp(tmp, "bg:", 3) == 0 && tmp[3] == '#') {
        unsigned int r, g, b;
        if (sscanf(tmp + 4, "%02x%02x%02x", &r, &g, &b) == 3) {
            char esc[32];
            snprintf(esc, sizeof(esc), "\033[48;2;%d;%d;%dm", r, g, b);
            buf_appends(buf, len, cap, esc);
        }
        return;
    }

    bool is_sgr = (tlen > 0);
    for (size_t i = 0; i < tlen; i++) {
        if (tmp[i] != ';' && (tmp[i] < '0' || tmp[i] > '9')) {
            is_sgr = false;
            break;
        }
    }
    if (is_sgr) {
        char esc[64];
        snprintf(esc, sizeof(esc), "\033[%sm", tmp);
        buf_appends(buf, len, cap, esc);
    }
}

static void emit_colors(char **buf, size_t *len, size_t *cap,
                         const char *spec, size_t spec_len) {
    const char *p = spec;
    const char *end = spec + spec_len;
    while (p < end) {

        while (p < end && (*p == ' ' || *p == ',')) p++;
        if (p >= end) break;
        const char *tok = p;
        while (p < end && *p != ',' && *p != ' ') p++;
        size_t tlen = (size_t)(p - tok);
        emit_color_token(buf, len, cap, tok, tlen);
    }
}

static char *format_prompt(const char *fmt, int last_exit_code) {
    size_t cap = 256, len = 0;
    char *buf = malloc(cap);
    buf[0] = '\0';

    for (const char *p = fmt; *p; p++) {
        if (*p != '%') {
            buf_append(&buf, &len, &cap, p, 1);
            continue;
        }
        p++;
        if (!*p) break;

        switch (*p) {
        case 'd':
            buf_appends(&buf, &len, &cap, get_collapsed_cwd());
            break;
        case 'D':
            buf_appends(&buf, &len, &cap, get_cwd_basename());
            break;
        case 'g': {
            const char *branch = get_git_branch();
            if (branch) buf_appends(&buf, &len, &cap, branch);
            break;
        }
        case 'G': {

            const char *gs = get_git_status();
            if (gs[0]) buf_appends(&buf, &len, &cap, gs);
            break;
        }
        case 'E': {

            const char *dur = format_duration(last_cmd_duration_ms);
            if (dur[0]) buf_appends(&buf, &len, &cap, dur);
            break;
        }
        case 'j': {

            int jcount = job_active_count();
            if (jcount > 0) {
                char jbuf[16];
                snprintf(jbuf, sizeof(jbuf), "%d", jcount);
                buf_appends(&buf, &len, &cap, jbuf);
            }
            break;
        }
        case 't': {
            time_t now = time(NULL);
            struct tm *tm = localtime(&now);
            if (tm) {
                char tbuf[16];
                snprintf(tbuf, sizeof(tbuf), "%02d:%02d", tm->tm_hour, tm->tm_min);
                buf_appends(&buf, &len, &cap, tbuf);
            }
            break;
        }
        case 'T': {
            time_t now = time(NULL);
            struct tm *tm = localtime(&now);
            if (tm) {
                char tbuf[16];
                snprintf(tbuf, sizeof(tbuf), "%02d:%02d:%02d",
                         tm->tm_hour, tm->tm_min, tm->tm_sec);
                buf_appends(&buf, &len, &cap, tbuf);
            }
            break;
        }
        case 'n': {
            const char *user = getenv("USER");
            if (!user) {
                struct passwd *pw = getpwuid(getuid());
                user = pw ? pw->pw_name : "?";
            }
            buf_appends(&buf, &len, &cap, user);
            break;
        }
        case 'h': {
            char hostname[256];
            if (gethostname(hostname, sizeof(hostname)) == 0) {
                char *dot = strchr(hostname, '.');
                if (dot) *dot = '\0';
                buf_appends(&buf, &len, &cap, hostname);
            }
            break;
        }
        case 'e': {
            if (last_exit_code != 0) {
                char ebuf[16];
                snprintf(ebuf, sizeof(ebuf), "%d", last_exit_code);
                buf_appends(&buf, &len, &cap, ebuf);
            }
            break;
        }
        case 'v':
            if (repl_editor && repl_editor->vi_mode)
                buf_appends(&buf, &len, &cap,
                            repl_editor->vi_insert ? "INSERT" : "NORMAL");
            break;
        case '#':
            buf_append(&buf, &len, &cap, (getuid() == 0) ? "#" : "$", 1);
            break;
        case '%':
            buf_append(&buf, &len, &cap, "%", 1);
            break;
        case '{': {

            const char *start = p + 1;
            const char *end = strchr(start, '}');
            if (end) {
                emit_colors(&buf, &len, &cap, start, (size_t)(end - start));
                p = end;
            } else {

                buf_append(&buf, &len, &cap, "%{", 2);
            }
            break;
        }
        default:

            buf_append(&buf, &len, &cap, "%", 1);
            buf_append(&buf, &len, &cap, p, 1);
            break;
        }
    }

    return buf;
}

static char *build_default_prompt(int last_exit_code) {
    const char *git = get_git_branch();
    const char *gs = git ? get_git_status() : "";
    char fmt[512];
    if (git && git[0]) {
        if (gs[0]) {
            snprintf(fmt, sizeof(fmt),
                     "%%{bold,blue}%%d%%{reset} %%{purple}(%%g%%{reset} %%{red}%%G%%{purple})%%{reset} %%{bold,yellow}vex%%{reset}> ");
        } else {
            snprintf(fmt, sizeof(fmt),
                     "%%{bold,blue}%%d%%{reset} %%{purple}(%%g)%%{reset} %%{bold,yellow}vex%%{reset}> ");
        }
    } else {
        snprintf(fmt, sizeof(fmt),
                 "%%{bold,blue}%%d%%{reset} %%{bold,yellow}vex%%{reset}> ");
    }
    return format_prompt(fmt, last_exit_code);
}

static char *build_prompt(EvalCtx *ctx, int last_exit_code) {

    char *fn_prompt = prompt_fn_eval(ctx);
    if (fn_prompt) return fn_prompt;

    char *plugin_prompt = plugin_prompt_eval();
    if (plugin_prompt) return plugin_prompt;

    const char *custom = getenv("VEX_PROMPT");
    if (custom) {
        return format_prompt(custom, last_exit_code);
    }
    return build_default_prompt(last_exit_code);
}

static char *build_rprompt(EvalCtx *ctx, int last_exit_code) {

    char *fn_rprompt = rprompt_fn_eval(ctx);
    if (fn_rprompt) return fn_rprompt;

    char *plugin_rprompt = plugin_rprompt_eval();
    if (plugin_rprompt) return plugin_rprompt;

    const char *custom = getenv("VEX_RPROMPT");
    if (custom) {
        return format_prompt(custom, last_exit_code);
    }
    return strdup("");
}

static void run_file(EvalCtx *ctx, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        vex_err("cannot open %s: %s", path, strerror(errno));
        return;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    if (size < 0) { fclose(f); vex_err("cannot read %s", path); return; }
    fseek(f, 0, SEEK_SET);

    char *source = malloc((size_t)size + 1);
    if (!source) { fclose(f); vex_err("out of memory"); return; }
    size_t nread = fread(source, 1, (size_t)size, f);
    source[nread] = '\0';
    fclose(f);

    Parser p = parser_init(source, ctx->arena);

    for (;;) {
        ASTNode *stmt = parser_parse_line(&p);
        if (!stmt || p.had_error) break;
        VexValue *result = eval(ctx, stmt);
        vval_release(result);
        if (vex_opt_errexit() && (ctx->had_error || ctx->last_exit_code != 0))
            break;
    }

    arena_reset(ctx->arena);
    free(source);
}

static bool needs_continuation(const char *input) {
    int braces = 0, brackets = 0, parens = 0;
    bool in_string = false, in_raw = false;

    for (const char *p = input; *p; p++) {
        if (in_string) {
            if (*p == '\\' && p[1]) { p++; continue; }
            if (*p == '"') in_string = false;
            continue;
        }
        if (in_raw) {
            if (*p == '\'') in_raw = false;
            continue;
        }
        if (*p == '"') { in_string = true; continue; }
        if (*p == '\'') { in_raw = true; continue; }
        if (*p == '#') break;
        if (*p == '{') braces++;
        else if (*p == '}') braces--;
        else if (*p == '[') brackets++;
        else if (*p == ']') brackets--;
        else if (*p == '(') parens++;
        else if (*p == ')') parens--;
    }

    if (in_string || in_raw) return true;
    if (braces > 0 || brackets > 0 || parens > 0) return true;

    size_t len = strlen(input);
    while (len > 0 && (input[len-1] == ' ' || input[len-1] == '\t')) len--;
    if (len > 0 && input[len-1] == '|') return true;
    if (len > 0 && input[len-1] == '\\') return true;
    if (len >= 2 && input[len-2] == '&' && input[len-1] == '&') return true;
    if (len >= 2 && input[len-2] == '|' && input[len-1] == '|') return true;

    {
        const char *p = input;
        while (*p) {

            if (*p == '"') {
                p++;
                while (*p && *p != '"') {
                    if (*p == '\\' && p[1]) p++;
                    p++;
                }
                if (*p) p++;
                continue;
            }
            if (*p == '\'') {
                p++;
                while (*p && *p != '\'') p++;
                if (*p) p++;
                continue;
            }

            if (*p == '#') {
                while (*p && *p != '\n') p++;
                continue;
            }

            if (p[0] == '<' && p[1] == '<' && p[2] != '<') {
                const char *d = p + 2;
                while (*d == ' ' || *d == '\t') d++;

                char delim[128];
                size_t dlen = 0;

                if (*d == '\'' || *d == '"') {
                    char q = *d++;
                    while (*d && *d != q && dlen < sizeof(delim) - 1)
                        delim[dlen++] = *d++;
                    if (*d == q) d++;
                } else {
                    while (*d && *d != '\n' && *d != ' ' && *d != '\t' &&
                           *d != ';' && dlen < sizeof(delim) - 1)
                        delim[dlen++] = *d++;
                }
                delim[dlen] = '\0';

                if (dlen == 0) { p = d; continue; }

                const char *line = d;
                while (*line && *line != '\n') line++;
                if (*line == '\n') line++;

                bool found = false;
                while (*line) {

                    const char *lstart = line;
                    while (*line && *line != '\n') line++;
                    size_t llen = (size_t)(line - lstart);
                    if (llen == dlen && strncmp(lstart, delim, dlen) == 0) {
                        found = true;
                        break;
                    }
                    if (*line == '\n') line++;
                }

                if (!found) return true;
                p = d;
                continue;
            }
            p++;
        }
    }

    return false;
}

static void run_command(EvalCtx *ctx, const char *line) {
    Parser p = parser_init(line, ctx->arena);
    ASTNode *stmt = parser_parse_line(&p);

    if (p.had_error || !stmt) {
        arena_reset(ctx->arena);
        return;
    }

    VexValue *result = eval(ctx, stmt);

    bool is_pipeline = (stmt->kind == AST_PIPELINE);
    bool is_builtin_call = (stmt->kind == AST_CALL &&
                            builtin_exists(stmt->call.cmd_name));
    bool suppress = (stmt->kind == AST_EXTERNAL_CALL ||
                     stmt->kind == AST_BYTE_PIPELINE ||
                     stmt->kind == AST_COND_CHAIN ||
                     stmt->kind == AST_SUBSHELL ||
                     (stmt->kind == AST_CALL && !is_builtin_call &&
                      find_in_path(stmt->call.cmd_name)));
    if (suppress) is_builtin_call = true;
    if (result && result->type != VEX_VAL_NULL) {
        if (is_pipeline || !is_builtin_call) {
            vval_print(result, stdout);
            printf("\n");
        }
    }

    vval_release(result);
    arena_reset(ctx->arena);
}

static void run_string(EvalCtx *ctx, const char *source) {
    Parser p = parser_init(source, ctx->arena);
    VexValue *result = NULL;
    ASTNode *last_stmt = NULL;

    for (;;) {
        ASTNode *stmt = parser_parse_line(&p);
        if (!stmt) break;
        if (p.had_error) break;

        if (result) vval_release(result);
        last_stmt = stmt;
        result = eval(ctx, stmt);

        if (vex_opt_errexit() && (ctx->had_error || ctx->last_exit_code != 0)) {
            break;
        }
    }

    if (result && result->type != VEX_VAL_NULL && last_stmt) {
        bool is_pipeline = (last_stmt->kind == AST_PIPELINE);
        bool is_builtin_call = (last_stmt->kind == AST_CALL &&
                                builtin_exists(last_stmt->call.cmd_name));
        bool suppress = (last_stmt->kind == AST_EXTERNAL_CALL ||
                        last_stmt->kind == AST_BYTE_PIPELINE ||
                        last_stmt->kind == AST_COND_CHAIN ||
                        last_stmt->kind == AST_SUBSHELL ||
                        (last_stmt->kind == AST_CALL && !is_builtin_call &&
                         find_in_path(last_stmt->call.cmd_name)));
        if (suppress) is_builtin_call = true;
        if (is_pipeline || !is_builtin_call) {
            vval_print(result, stdout);
            printf("\n");
        }
    }
    if (result) vval_release(result);

    arena_reset(ctx->arena);
}

static VexValue *shell_state_provider(void) {
    VexValue *rec = vval_record();

    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)))
        vval_record_set(rec, "cwd", vval_string(vstr_new(cwd)));
    else
        vval_record_set(rec, "cwd", vval_string(vstr_new("")));

    const char *branch = get_git_branch();
    vval_record_set(rec, "git_branch",
                    branch ? vval_string(vstr_new(branch))
                           : vval_string(vstr_new("")));

    const char *gs = get_git_status();
    vval_record_set(rec, "git_status", vval_string(vstr_new(gs)));

    int exit_code = repl_ctx ? repl_ctx->last_exit_code : 0;
    vval_record_set(rec, "exit_code", vval_int(exit_code));

    vval_record_set(rec, "duration_ms", vval_float(last_cmd_duration_ms));

    if (repl_editor && repl_editor->vi_mode)
        vval_record_set(rec, "vi_mode",
                        vval_string(vstr_new(repl_editor->vi_insert ? "insert" : "normal")));
    else
        vval_record_set(rec, "vi_mode", vval_string(vstr_new("")));

    return rec;
}

static void repl(EvalCtx *ctx) {
    EditState editor;
    edit_init(&editor);
    builtin_set_editor(&editor);
    builtin_set_comp_ctx(ctx);

    repl_editor = &editor;
    repl_ctx = ctx;
    plugin_set_state_provider(shell_state_provider);

    char *hist_path = get_history_path();
    if (hist_path) {
        edit_history_load(&editor, hist_path);
    }

    printf("\033[1mVex Shell\033[0m v%s\n", VEX_VERSION);
    printf("Type 'help' for available commands, 'exit' to quit.\n\n");

    for (;;) {

        job_notify();

        if (vex_got_sigwinch) {
            vex_got_sigwinch = 0;
            edit_get_term_size(&editor);
        }

        hooks_run_precmd(ctx);

        char *prompt = build_prompt(ctx, ctx->last_exit_code);
        free(editor.rprompt);
        editor.rprompt = build_rprompt(ctx, ctx->last_exit_code);
        editor.rprompt_width = display_width(editor.rprompt);

        /* OSC 133;A prompt start */
        write(STDOUT_FILENO, "\033]133;A\007", 8);

        char *line = edit_readline(&editor, prompt);

        /* OSC 133;B command start */
        write(STDOUT_FILENO, "\033]133;B\007", 8);

        free(prompt);

        if (!line) {
            printf("\n");
            break;
        }

        if (line[0] == '\0') {
            free(line);
            continue;
        }

        while (needs_continuation(line)) {
            char *cont = edit_readline(&editor, "  ... ");
            if (!cont) break;
            size_t old_len = strlen(line);
            size_t cont_len = strlen(cont);
            line = realloc(line, old_len + 1 + cont_len + 1);
            line[old_len] = '\n';
            memcpy(line + old_len + 1, cont, cont_len + 1);
            free(cont);
        }

        edit_history_add(&editor, line);

        if (hist_path) {
            FILE *hf = fopen(hist_path, "a");
            if (hf) {
                fprintf(hf, "%s\n", line);
                fclose(hf);
            }
        }

        /* OSC 133;C execution start */
        write(STDOUT_FILENO, "\033]133;C\007", 8);

        ctx->had_error = false;
        hooks_run_preexec(ctx, line);
        cmd_timer_start();
        run_command(ctx, line);
        cmd_timer_stop();

        /* OSC 133;D command finished */
        {
            char osc_d[32];
            int osc_len = snprintf(osc_d, sizeof(osc_d),
                                   "\033]133;D;%d\007", ctx->last_exit_code);
            write(STDOUT_FILENO, osc_d, (size_t)osc_len);
        }

        {
            VexValue *dur = vval_float(last_cmd_duration_ms);
            scope_set(ctx->global, "CMD_DURATION", dur);
            vval_release(dur);
        }
        free(line);

        if (vex_opt_errexit() && (ctx->had_error || ctx->last_exit_code != 0)) {
            break;
        }

        trap_check_pending(ctx);
    }

    {
        const char *exit_cmd = trap_get_exit_handler();
        if (exit_cmd && exit_cmd[0] != '\0') {
            run_command(ctx, exit_cmd);
        }
    }

    if (hist_path) {
        edit_history_save(&editor, hist_path);
        free(hist_path);
    }

    edit_free(&editor);
}

int main(int argc, char **argv) {

    builtins_init();
    undo_init();
    plugin_api_init();
    job_init();
    EvalCtx ctx = eval_ctx_new();

    bool is_login = false;
    if (argv[0][0] == '-') is_login = true;

    int arg_shift = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--login") == 0 || strcmp(argv[i], "-l") == 0) {
            is_login = true;
            arg_shift = i;
            break;
        }

        if (strcmp(argv[i], "-c") == 0 || argv[i][0] != '-') break;
        if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) break;
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) break;
    }

    if (arg_shift > 0) {
        for (int i = arg_shift; i < argc - 1; i++)
            argv[i] = argv[i + 1];
        argc--;
    }

    if (is_login) setenv("VEX_LOGIN_SHELL", "1", 1);

    {
        const char *home = getenv("HOME");
        if (home) {
            char dir[4096];
            struct stat st;

            snprintf(dir, sizeof(dir), "%s/.config/vex", home);
            if (stat(dir, &st) != 0) {
                snprintf(dir, sizeof(dir), "%s/.config", home);
                mkdir(dir, 0755);
                snprintf(dir, sizeof(dir), "%s/.config/vex", home);
                mkdir(dir, 0755);
                snprintf(dir, sizeof(dir), "%s/.config/vex/themes", home);
                mkdir(dir, 0755);

                char conf[4096];
                snprintf(conf, sizeof(conf), "%s/.config/vex/config.vex", home);
                FILE *f = fopen(conf, "w");
                if (f) {
                    fprintf(f, "# Vex shell configuration\n");
                    fprintf(f, "# See `man vex` or `help` for documentation\n\n");

                    fprintf(f, "# Prompt\n");
                    fprintf(f, "# export VEX_PROMPT \"%%{bold,blue}%%D%%{reset} %%{green}%%g%%{reset} %%# \"\n");
                    fprintf(f, "# export VEX_RPROMPT \"%%{dim}%%t%%{reset}\"\n\n");

                    fprintf(f, "# Editing mode: emacs (default) or vi\n");
                    fprintf(f, "# export VEX_EDIT_MODE \"emacs\"\n\n");

                    fprintf(f, "# Syntax colors (ANSI codes, hex #rrggbb, or 256-color)\n");
                    fprintf(f, "# export VEX_COLOR_BUILTIN \"#89b4fa\"\n");
                    fprintf(f, "# export VEX_COLOR_COMMAND \"#a6e3a1\"\n");
                    fprintf(f, "# export VEX_COLOR_STRING \"#a6e3a1\"\n");
                    fprintf(f, "# export VEX_COLOR_KEYWORD \"#cba6f7\"\n");
                    fprintf(f, "# export VEX_COLOR_NUMBER \"#f9e2af\"\n");
                    fprintf(f, "# export VEX_COLOR_ERROR \"#f38ba8\"\n");
                    fprintf(f, "# export VEX_COLOR_VARIABLE \"#89dceb\"\n");
                    fprintf(f, "# export VEX_COLOR_COMMENT \"#6c7086\"\n\n");

                    fprintf(f, "# Aliases\n");
                    fprintf(f, "# alias ll = ls -la\n");
                    fprintf(f, "# alias la = ls -a\n");
                    fprintf(f, "# alias g = git\n");
                    fprintf(f, "# alias gs = git status\n");
                    fprintf(f, "# alias gp = git push\n\n");

                    fprintf(f, "# Plugins\n");
                    fprintf(f, "# use plugin \"hello_plugin.so\"\n");
                    fclose(f);
                }

                snprintf(dir, sizeof(dir), "%s/.local", home);
                mkdir(dir, 0755);
                snprintf(dir, sizeof(dir), "%s/.local/share", home);
                mkdir(dir, 0755);
                snprintf(dir, sizeof(dir), "%s/.local/share/vex", home);
                mkdir(dir, 0755);

                snprintf(dir, sizeof(dir), "%s/.config/vex/plugins", home);
                mkdir(dir, 0755);
                snprintf(dir, sizeof(dir), "%s/.config/vex/plugins/hello", home);
                mkdir(dir, 0755);

                {
                    char hello_path[4096];
                    snprintf(hello_path, sizeof(hello_path),
                             "%s/.config/vex/plugins/hello/init.vex", home);
                    FILE *hp = fopen(hello_path, "w");
                    if (hp) {
                        fprintf(hp, "# Hello plugin — example autoloaded plugin\n");
                        fprintf(hp, "# Plugins in ~/.config/vex/plugins/ are loaded on startup\n");
                        fprintf(hp, "# Delete this folder to remove the greeting\n\n");
                        fprintf(hp, "def-cmd \"hello\" \"hello [name]\" \"Say hello\" {|input, name|\n");
                        fprintf(hp, "    let who = if $name != null { $name } else { $USER }\n");
                        fprintf(hp, "    \"Hello, \" + $who + \"!\"\n");
                        fprintf(hp, "}\n");
                        fclose(hp);
                    }
                }

                if (isatty(STDIN_FILENO)) {
                    fprintf(stderr, "Created ~/.config/vex/config.vex\n");
                }
            }
        }
    }

    if (is_login) {
        struct stat st;
        const char *home = getenv("HOME");
        char config_path[4096];

        if (stat("/etc/vex/profile.vex", &st) == 0 && S_ISREG(st.st_mode)) {
            run_file(&ctx, "/etc/vex/profile.vex");
            ctx.had_error = false;
        }

        if (home) {
            snprintf(config_path, sizeof(config_path), "%s/.config/vex/profile.vex", home);
            if (stat(config_path, &st) == 0 && S_ISREG(st.st_mode)) {
                run_file(&ctx, config_path);
                ctx.had_error = false;
            }
        }
    }

    {
        struct stat st;

        if (stat("/etc/vex/config.vex", &st) == 0 && S_ISREG(st.st_mode)) {
            run_file(&ctx, "/etc/vex/config.vex");
            ctx.had_error = false;
        }

        const char *home = getenv("HOME");
        if (home) {
            char config_path[4096];

            snprintf(config_path, sizeof(config_path),
                     "%s/.config/vex/config.vex", home);
            if (stat(config_path, &st) == 0 && S_ISREG(st.st_mode)) {
                run_file(&ctx, config_path);
                ctx.had_error = false;
            }
        }
    }

    pkg_autoload(&ctx);
    ctx.had_error = false;

    if (argc > 1) {
        if (strcmp(argv[1], "-c") == 0 && argc > 2) {

            {
                VexValue *v = vval_string_cstr("vex");
                scope_set(ctx.global, "0", v);
                vval_release(v);
            }
            VexValue *cargv_list = vval_list();
            for (int i = 3; i < argc; i++) {
                char name[16];
                snprintf(name, sizeof(name), "%d", i - 2);
                VexValue *arg = vval_string_cstr(argv[i]);
                scope_set(ctx.global, name, arg);
                vval_list_push(cargv_list, arg);
                vval_release(arg);
            }
            scope_set(ctx.global, "argv", cargv_list);
            vval_release(cargv_list);
            {
                VexValue *ac = vval_int(argc - 3);
                scope_set(ctx.global, "argc", ac);
                vval_release(ac);
            }

            run_string(&ctx, argv[2]);
        } else if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0) {
            printf("vex %s\n", VEX_VERSION);
        } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("Usage: vex [options] [script]\n");
            printf("  -l, --login    Start as a login shell\n");
            printf("  -c <command>   Execute a command string\n");
            printf("  -v, --version  Show version\n");
            printf("  -h, --help     Show this help\n");
        } else {

            {
                VexValue *v = vval_string_cstr(argv[1]);
                scope_set(ctx.global, "0", v);
                vval_release(v);
            }
            VexValue *sargv_list = vval_list();
            for (int i = 2; i < argc; i++) {
                char name[16];
                snprintf(name, sizeof(name), "%d", i - 1);
                VexValue *arg = vval_string_cstr(argv[i]);
                scope_set(ctx.global, name, arg);
                vval_list_push(sargv_list, arg);
                vval_release(arg);
            }
            scope_set(ctx.global, "argv", sargv_list);
            vval_release(sargv_list);
            {
                VexValue *ac = vval_int(argc - 2);
                scope_set(ctx.global, "argc", ac);
                vval_release(ac);
            }

            if (vex_is_sh_script(argv[1])) {
                ctx.last_exit_code = vex_run_sh_script(argv[1], argc - 2, &argv[2]);
            } else {
                run_file(&ctx, argv[1]);

                VexValue *main_fn = scope_get(ctx.global, "main");
                if (main_fn && main_fn->type == VEX_VAL_CLOSURE) {
                    VexValue *sargv = scope_get(ctx.global, "argv");
                    if (!sargv) sargv = vval_list();
                    else vval_retain(sargv);
                    VexValue *main_args[] = { sargv };
                    VexValue *r = eval_call_closure(&ctx, main_fn, main_args, 1);
                    vval_release(r);
                    vval_release(sargv);
                }
            }
        }
    } else {
        repl(&ctx);
    }

    if (argc > 1) {
        const char *exit_cmd = trap_get_exit_handler();
        if (exit_cmd && exit_cmd[0] != '\0') {
            run_command(&ctx, exit_cmd);
        }
    }

    eval_ctx_free(&ctx);
    undo_free();
    plugin_cleanup();
    job_cleanup();
    return 0;
}
