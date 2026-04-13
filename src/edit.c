#include "vex.h"
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/stat.h>
#include <strings.h>
#include <glob.h>

static struct termios orig_termios;
static bool termios_saved = false;

bool edit_enable_raw(EditState *e) {
    if (e->raw_mode) return true;
    if (!isatty(STDIN_FILENO)) return false;

    if (!termios_saved) {
        if (tcgetattr(STDIN_FILENO, &orig_termios) == -1) return false;
        termios_saved = true;
    }

    struct termios raw = orig_termios;

    raw.c_iflag &= ~(unsigned)(BRKINT | ICRNL | INPCK | ISTRIP | IXON);

    raw.c_oflag &= ~(unsigned)(OPOST);

    raw.c_cflag |= (unsigned)(CS8);

    raw.c_lflag &= ~(unsigned)(ECHO | ICANON | IEXTEN | ISIG);

    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == -1) return false;
    e->raw_mode = true;
    write(STDOUT_FILENO, "\033[?2004h", 8);
    return true;
}

void edit_disable_raw(EditState *e) {
    if (e->raw_mode && termios_saved) {
        write(STDOUT_FILENO, "\033[?2004l", 8);
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        e->raw_mode = false;
    }
}

void edit_get_term_size(EditState *e) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        e->term_cols = ws.ws_col;
        e->term_rows = ws.ws_row;
    } else {
        e->term_cols = 80;
        e->term_rows = 24;
    }
}

static int get_cursor_pos(int *row, int *col) {
    char buf[32];
    unsigned int i = 0;

    if (write(STDOUT_FILENO, "\033[6n", 4) != 4) return -1;

    while (i < sizeof(buf) - 1) {
        if (read(STDIN_FILENO, buf + i, 1) != 1) break;
        if (buf[i] == 'R') break;
        i++;
    }
    buf[i] = '\0';

    if (buf[0] != '\033' || buf[1] != '[') return -1;
    if (sscanf(buf + 2, "%d;%d", row, col) != 2) return -1;
    return 0;
}

static void buf_init(EditBuf *b) {
    b->cap = VEX_EDIT_BUF_INIT;
    b->buf = malloc(b->cap);
    b->buf[0] = '\0';
    b->len = 0;
    b->pos = 0;
}

static void buf_free(EditBuf *b) {
    free(b->buf);
    b->buf = NULL;
    b->len = 0;
    b->cap = 0;
    b->pos = 0;
}

static void buf_grow(EditBuf *b, size_t needed) {
    if (b->len + needed + 1 > b->cap) {
        while (b->cap < b->len + needed + 1) b->cap *= 2;
        char *tmp = realloc(b->buf, b->cap);
        if (!tmp) return;
        b->buf = tmp;
    }
}

static void buf_insert(EditBuf *b, const char *s, size_t n) {
    buf_grow(b, n);

    memmove(b->buf + b->pos + n, b->buf + b->pos, b->len - b->pos);
    memcpy(b->buf + b->pos, s, n);
    b->len += n;
    b->pos += n;
    b->buf[b->len] = '\0';
}

static void buf_insert_char(EditBuf *b, char c) {
    buf_insert(b, &c, 1);
}

static void buf_delete_back(EditBuf *b) {
    if (b->pos == 0) return;

    size_t prev = b->pos - 1;
    while (prev > 0 && utf8_is_cont(b->buf[prev])) prev--;
    size_t clen = b->pos - prev;
    memmove(b->buf + prev, b->buf + b->pos, b->len - b->pos);
    b->len -= clen;
    b->pos -= clen;
    b->buf[b->len] = '\0';
}

static void buf_delete_forward(EditBuf *b) {
    if (b->pos >= b->len) return;

    size_t next = b->pos + 1;
    while (next < b->len && utf8_is_cont(b->buf[next])) next++;
    size_t clen = next - b->pos;
    memmove(b->buf + b->pos, b->buf + next, b->len - next);
    b->len -= clen;
    b->buf[b->len] = '\0';
}

static void buf_clear(EditBuf *b) {
    b->len = 0;
    b->pos = 0;
    b->buf[0] = '\0';
}

static void buf_set(EditBuf *b, const char *s) {
    size_t n = strlen(s);
    buf_grow(b, n);
    memcpy(b->buf, s, n);
    b->len = n;
    b->pos = n;
    b->buf[b->len] = '\0';
}

static void cursor_left(EditBuf *b) {
    if (b->pos == 0) return;
    b->pos--;
    while (b->pos > 0 && utf8_is_cont(b->buf[b->pos])) b->pos--;
}

static void cursor_right(EditBuf *b) {
    if (b->pos >= b->len) return;
    b->pos++;
    while (b->pos < b->len && utf8_is_cont(b->buf[b->pos])) b->pos++;
}

static void cursor_word_left(EditBuf *b) {
    if (b->pos == 0) return;

    while (b->pos > 0 && b->buf[b->pos - 1] == ' ') b->pos--;

    while (b->pos > 0 && b->buf[b->pos - 1] != ' ') b->pos--;
}

static void cursor_word_right(EditBuf *b) {

    while (b->pos < b->len && b->buf[b->pos] != ' ') b->pos++;

    while (b->pos < b->len && b->buf[b->pos] == ' ') b->pos++;
}

static void cursor_word_end(EditBuf *b) {
    if (b->pos < b->len) b->pos++;

    while (b->pos < b->len && b->buf[b->pos] == ' ') b->pos++;

    while (b->pos < b->len && b->buf[b->pos + 1] != ' ' &&
           b->pos + 1 < b->len) b->pos++;
}

static void cursor_WORD_right(EditBuf *b) {
    while (b->pos < b->len && b->buf[b->pos] != ' ') b->pos++;
    while (b->pos < b->len && b->buf[b->pos] == ' ') b->pos++;
}

static void cursor_WORD_left(EditBuf *b) {
    if (b->pos > 0) b->pos--;
    while (b->pos > 0 && b->buf[b->pos] == ' ') b->pos--;
    while (b->pos > 0 && b->buf[b->pos - 1] != ' ') b->pos--;
}

static void cursor_WORD_end(EditBuf *b) {
    if (b->pos < b->len) b->pos++;
    while (b->pos < b->len && b->buf[b->pos] == ' ') b->pos++;
    while (b->pos < b->len && b->pos + 1 < b->len &&
           b->buf[b->pos + 1] != ' ') b->pos++;
}

static void cursor_home(EditBuf *b) { b->pos = 0; }
static void cursor_end(EditBuf *b) { b->pos = b->len; }

static void kill_ring_save(EditState *e, const char *text, size_t len) {
    free(e->kill_ring);
    e->kill_ring = malloc(len + 1);
    memcpy(e->kill_ring, text, len);
    e->kill_ring[len] = '\0';
    e->kill_ring_len = len;
}

static void kill_to_end(EditState *e) {
    EditBuf *b = &e->buf;
    size_t kill_len = b->len - b->pos;
    if (kill_len > 0)
        kill_ring_save(e, b->buf + b->pos, kill_len);
    b->len = b->pos;
    b->buf[b->len] = '\0';
}

static void kill_to_start(EditState *e) {
    EditBuf *b = &e->buf;
    if (b->pos > 0)
        kill_ring_save(e, b->buf, b->pos);
    memmove(b->buf, b->buf + b->pos, b->len - b->pos);
    b->len -= b->pos;
    b->pos = 0;
    b->buf[b->len] = '\0';
}

static void kill_word_back(EditState *e) {
    EditBuf *b = &e->buf;
    size_t old = b->pos;
    cursor_word_left(b);
    size_t diff = old - b->pos;
    if (diff > 0)
        kill_ring_save(e, b->buf + b->pos, diff);
    memmove(b->buf + b->pos, b->buf + old, b->len - old);
    b->len -= diff;
    b->buf[b->len] = '\0';
}

static void kill_word_forward(EditState *e) {
    EditBuf *b = &e->buf;
    size_t old = b->pos;

    while (b->pos < b->len && b->buf[b->pos] != ' ') b->pos++;

    while (b->pos < b->len && b->buf[b->pos] == ' ') b->pos++;
    size_t end = b->pos;
    b->pos = old;
    size_t diff = end - old;
    if (diff > 0)
        kill_ring_save(e, b->buf + old, diff);
    memmove(b->buf + old, b->buf + end, b->len - end);
    b->len -= diff;
    b->buf[b->len] = '\0';
}

static void yank(EditState *e) {
    if (!e->kill_ring || e->kill_ring_len == 0) return;
    buf_insert(&e->buf, e->kill_ring, e->kill_ring_len);
}

static void vi_save_undo(EditState *e) {
    free(e->undo_buf);
    e->undo_buf = strndup(e->buf.buf, e->buf.len);
    e->undo_len = e->buf.len;
    e->undo_pos = e->buf.pos;
    e->undo_valid = true;
}

static void history_init(EditHistory *h) {
    h->cap = 64;
    h->entries = malloc(h->cap * sizeof(char *));
    h->count = 0;
    h->browse_pos = 0;
    h->saved_line = NULL;
}

static void history_free(EditHistory *h) {
    for (size_t i = 0; i < h->count; i++) free(h->entries[i]);
    free(h->entries);
    free(h->saved_line);
}

void edit_history_add(EditState *e, const char *line) {
    if (!line || line[0] == '\0') return;

    if (e->history.count > 0 &&
        strcmp(e->history.entries[e->history.count - 1], line) == 0)
        return;

    const char *histsize_env = getenv("VEX_HISTSIZE");
    size_t max = histsize_env ? (size_t)atoi(histsize_env) : VEX_EDIT_HISTORY_MAX;
    if (max < 100) max = 100;

    while (e->history.count >= max) {
        free(e->history.entries[0]);
        memmove(e->history.entries, e->history.entries + 1,
                (e->history.count - 1) * sizeof(char *));
        e->history.count--;
    }

    if (e->history.count >= e->history.cap) {
        e->history.cap *= 2;
        e->history.entries = realloc(e->history.entries,
                                     e->history.cap * sizeof(char *));
    }
    e->history.entries[e->history.count++] = strdup(line);
}

void edit_history_load(EditState *e, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        if (line[0]) edit_history_add(e, line);
    }
    fclose(f);
}

void edit_history_save(EditState *e, const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return;

    const char *histsize_env = getenv("VEX_HISTSIZE");
    size_t max = histsize_env ? (size_t)atoi(histsize_env) : VEX_EDIT_HISTORY_MAX;
    if (max < 100) max = 100;
    size_t start = e->history.count > max ? e->history.count - max : 0;
    for (size_t i = start; i < e->history.count; i++) {
        fprintf(f, "%s\n", e->history.entries[i]);
    }
    fclose(f);
}

static void history_browse_up(EditState *e) {
    if (e->history.count == 0) return;

    if (e->history.browse_pos == e->history.count) {
        free(e->history.saved_line);
        e->history.saved_line = strdup(e->buf.buf);
    }

    if (e->history.browse_pos > 0) {
        e->history.browse_pos--;
        buf_set(&e->buf, e->history.entries[e->history.browse_pos]);
    }
}

static void history_browse_down(EditState *e) {
    if (e->history.browse_pos >= e->history.count) return;

    e->history.browse_pos++;
    if (e->history.browse_pos == e->history.count) {

        if (e->history.saved_line) {
            buf_set(&e->buf, e->history.saved_line);
        } else {
            buf_clear(&e->buf);
        }
    } else {
        buf_set(&e->buf, e->history.entries[e->history.browse_pos]);
    }
}

static const char *find_history_hint(EditState *e) {
    if (e->buf.len == 0) return NULL;

    /* Only suggest when buffer has a space (full command + partial args) */
    bool has_space = false;
    for (size_t i = 0; i < e->buf.len; i++) {
        if (e->buf.buf[i] == ' ') { has_space = true; break; }
    }
    if (!has_space) return NULL;

    for (size_t i = e->history.count; i > 0; i--) {
        const char *entry = e->history.entries[i - 1];
        if (strncmp(entry, e->buf.buf, e->buf.len) == 0 &&
            strlen(entry) > e->buf.len) {
            const char *hint = entry + e->buf.len;
            /* Don't suggest flags unless user is already in a flag */
            if (hint[0] == ' ' && hint[1] == '-') continue;
            return hint;
        }
    }
    return NULL;
}

static int read_key(void) {
    char c;
    int nread;

    while ((nread = (int)read(STDIN_FILENO, &c, 1)) != 1) {
        if (nread == -1 && errno != EAGAIN) return -1;
    }

    if (c == '\033') {
        char seq[5];

        if (read(STDIN_FILENO, seq, 1) != 1) return KEY_ESC;
        if (read(STDIN_FILENO, seq + 1, 1) != 1) return KEY_ESC;

        if (seq[0] == '[') {
            if (seq[1] >= '0' && seq[1] <= '9') {
                if (read(STDIN_FILENO, seq + 2, 1) != 1) return KEY_ESC;

                if (seq[2] == '~') {
                    switch (seq[1]) {
                    case '1': return KEY_HOME;
                    case '3': return KEY_DELETE;
                    case '4': return KEY_END;
                    case '5': return KEY_PAGE_UP;
                    case '6': return KEY_PAGE_DOWN;
                    case '7': return KEY_HOME;
                    case '8': return KEY_END;
                    }
                }

                if (seq[1] == '1' && seq[2] == ';') {
                    char mod, arrow;
                    if (read(STDIN_FILENO, &mod, 1) != 1) return KEY_ESC;
                    if (read(STDIN_FILENO, &arrow, 1) != 1) return KEY_ESC;
                    if (mod == '5') {
                        if (arrow == 'C') return KEY_CTRL_RIGHT;
                        if (arrow == 'D') return KEY_CTRL_LEFT;
                    }
                }

                if (seq[1] == '2' && seq[2] == '0') {
                    char s3, s4;
                    if (read(STDIN_FILENO, &s3, 1) != 1) return KEY_ESC;
                    if (read(STDIN_FILENO, &s4, 1) != 1) return KEY_ESC;
                    if (s3 == '0' && s4 == '~') return KEY_PASTE_START;
                    if (s3 == '1' && s4 == '~') return KEY_PASTE_END;
                }
            } else {
                switch (seq[1]) {
                case 'A': return KEY_UP;
                case 'B': return KEY_DOWN;
                case 'C': return KEY_RIGHT;
                case 'D': return KEY_LEFT;
                case 'H': return KEY_HOME;
                case 'F': return KEY_END;
                case 'Z': return KEY_SHIFT_TAB;
                }
            }
        } else if (seq[0] == 'O') {
            switch (seq[1]) {
            case 'H': return KEY_HOME;
            case 'F': return KEY_END;
            }
        }

        if (seq[0] == 'b') return KEY_CTRL_LEFT;
        if (seq[0] == 'f') return KEY_CTRL_RIGHT;

        return KEY_ESC;
    }

    return (unsigned char)c;
}

static size_t prompt_display_width(const char *prompt) {
    size_t w = 0;
    bool in_esc = false;
    while (*prompt) {
        if (*prompt == '\033') {
            in_esc = true;
        } else if (in_esc) {
            if ((*prompt >= 'A' && *prompt <= 'Z') ||
                (*prompt >= 'a' && *prompt <= 'z'))
                in_esc = false;
        } else {
            int32_t cp = utf8_decode(&prompt);
            if (cp >= 0) w += (size_t)utf8_charwidth(cp);
            continue;
        }
        prompt++;
    }
    return w;
}

#define CLR_RESET "\033[0m"

static const char *clr_keyword  = "\033[1;35m";
static const char *clr_builtin  = "\033[1;36m";
static const char *clr_string   = "\033[0;32m";
static const char *clr_number   = "\033[0;33m";
static const char *clr_operator = "\033[0;37m";
static const char *clr_comment  = "\033[0;90m";
static const char *clr_bool     = "\033[0;33m";
static const char *clr_pipe     = "\033[1;34m";
static const char *clr_caret    = "\033[1;31m";
static const char *clr_error    = "\033[1;31m";
static const char *clr_variable = "\033[0;36m";
static const char *clr_command  = "\033[0;32m";

static bool    colors_initialized = false;
static char    color_bufs[14][32];

static const char *parse_color_env(const char *env_name,
                                   const char *default_val, int idx) {
    const char *val = getenv(env_name);
    if (!val) return default_val;

    if (val[0] == '#' && strlen(val) == 7) {
        unsigned int r, g, b;
        if (sscanf(val + 1, "%02x%02x%02x", &r, &g, &b) == 3) {
            snprintf(color_bufs[idx], sizeof(color_bufs[idx]),
                     "\033[38;2;%u;%u;%um", r, g, b);
            return color_bufs[idx];
        }
    }

    snprintf(color_bufs[idx], sizeof(color_bufs[idx]), "\033[%sm", val);
    return color_bufs[idx];
}

static void init_colors(void) {
    if (colors_initialized) return;
    colors_initialized = true;
    clr_keyword  = parse_color_env("VEX_COLOR_KEYWORD",  "\033[1;35m", 0);
    clr_builtin  = parse_color_env("VEX_COLOR_BUILTIN",  "\033[1;36m", 1);
    clr_string   = parse_color_env("VEX_COLOR_STRING",   "\033[0;32m", 2);
    clr_number   = parse_color_env("VEX_COLOR_NUMBER",   "\033[0;33m", 3);
    clr_operator = parse_color_env("VEX_COLOR_OPERATOR", "\033[0;37m", 4);
    clr_comment  = parse_color_env("VEX_COLOR_COMMENT",  "\033[0;90m", 5);
    clr_bool     = parse_color_env("VEX_COLOR_BOOL",     "\033[0;33m", 6);
    clr_pipe     = parse_color_env("VEX_COLOR_PIPE",     "\033[1;34m", 7);
    clr_caret    = parse_color_env("VEX_COLOR_CARET",    "\033[1;31m", 8);
    clr_error    = parse_color_env("VEX_COLOR_ERROR",    "\033[1;31m", 9);
    clr_variable = parse_color_env("VEX_COLOR_VARIABLE", "\033[0;36m", 10);
    clr_command  = parse_color_env("VEX_COLOR_COMMAND",  "\033[0;32m", 11);
}

static const char *token_color(TokenType type) {
    switch (type) {
    case TOK_LET: case TOK_MUT: case TOK_FN:
    case TOK_IF: case TOK_ELSE:
    case TOK_FOR: case TOK_IN: case TOK_WHILE: case TOK_LOOP:
    case TOK_BREAK: case TOK_CONTINUE: case TOK_RETURN:
    case TOK_MATCH: case TOK_TRY: case TOK_CATCH:
    case TOK_USE: case TOK_ERROR_KW:
    case TOK_AND: case TOK_OR: case TOK_NOT:
        return clr_keyword;

    case TOK_TRUE: case TOK_FALSE: case TOK_NULL:
        return clr_bool;

    case TOK_INT: case TOK_FLOAT:
        return clr_number;

    case TOK_STRING: case TOK_RAW_STRING:
        return clr_string;

    case TOK_PIPE: case TOK_BYTE_PIPE:
        return clr_pipe;

    case TOK_CARET:
        return clr_caret;

    case TOK_EQ: case TOK_NEQ: case TOK_LT: case TOK_GT:
    case TOK_LTE: case TOK_GTE: case TOK_ASSIGN:
    case TOK_PLUS: case TOK_MINUS: case TOK_STAR:
    case TOK_SLASH: case TOK_PERCENT:
    case TOK_DOT: case TOK_DOTDOT: case TOK_DOTDOTLT:
    case TOK_SPREAD: case TOK_FAT_ARROW: case TOK_ARROW:
    case TOK_QUESTION: case TOK_TILDE: case TOK_DOLLAR_LPAREN:
    case TOK_LT_LPAREN:
    case TOK_AND_AND: case TOK_OR_OR: case TOK_APPEND:
    case TOK_HEREDOC:
    case TOK_HEREDOC_STRING:
        return clr_operator;

    case TOK_IDENT:
        return NULL;

    case TOK_ERROR:
        return clr_error;

    default:
        return NULL;
    }
}

#define PATH_CACHE_SIZE 64
static struct {
    char name[128];
    bool exists;
} path_cache[PATH_CACHE_SIZE];
static size_t path_cache_count = 0;

static bool cached_path_exists(const char *name) {

    for (size_t i = 0; i < path_cache_count; i++) {
        if (strcmp(path_cache[i].name, name) == 0)
            return path_cache[i].exists;
    }

    char *path = find_in_path(name);
    bool exists = (path != NULL);
    free(path);

    if (path_cache_count < PATH_CACHE_SIZE) {
        size_t nlen = strlen(name);
        if (nlen > 127) nlen = 127;
        memcpy(path_cache[path_cache_count].name, name, nlen);
        path_cache[path_cache_count].name[nlen] = '\0';
        path_cache[path_cache_count].exists = exists;
        path_cache_count++;
    }
    return exists;
}

static void highlight_append(VexStr *out, const char *buf, size_t len) {
    init_colors();
    if (len == 0) return;

    char *src = malloc(len + 1);
    memcpy(src, buf, len);
    src[len] = '\0';

    Lexer lex = lexer_init(src);
    size_t last_end = 0;
    bool cmd_pos = true;
    bool after_dollar = false;

    for (;;) {
        Token tok = lexer_next(&lex);
        if (tok.type == TOK_EOF) break;

        /* TOK_ERROR start is a message, not in source */
        if (tok.type == TOK_ERROR) continue;

        size_t tok_start = (size_t)(tok.start - src);
        size_t tok_end = tok_start + tok.length;

        if (tok_start > last_end) {
            const char *gap = buf + last_end;
            size_t gap_len = tok_start - last_end;
            size_t comment_off = gap_len;
            for (size_t i = 0; i < gap_len; i++) {
                if (gap[i] == '#') { comment_off = i; break; }
            }
            if (comment_off < gap_len) {
                if (comment_off > 0)
                    vstr_append(out, gap, comment_off);
                vstr_append_cstr(out, clr_comment);
                vstr_append(out, gap + comment_off, gap_len - comment_off);
                vstr_append_cstr(out, CLR_RESET);
            } else {
                vstr_append(out, gap, gap_len);
            }
        }

        const char *color = token_color(tok.type);

        if (tok.type == TOK_DOLLAR || tok.type == TOK_DOLLAR_LPAREN) {
            color = clr_variable;
            after_dollar = true;
        } else if (after_dollar && tok.type == TOK_IDENT) {
            color = clr_variable;
            after_dollar = false;
        } else {
            after_dollar = false;
        }

        if (tok.type == TOK_IDENT && !color) {
            char name[128];
            size_t nlen = tok.length < 127 ? tok.length : 127;
            memcpy(name, tok.start, nlen);
            name[nlen] = '\0';
            if (builtin_exists(name) || alias_lookup(name)) {
                color = clr_builtin;
            } else if (cmd_pos) {
                if (cached_path_exists(name)) {
                    color = clr_builtin;
                } else {
                    color = clr_error;
                }
            }
        }

        if (tok.type == TOK_NEWLINE) {
            vstr_append(out, buf + tok_start, tok.length);
            last_end = tok_end;
            continue;
        }

        if (color) {
            vstr_append_cstr(out, color);
            vstr_append(out, buf + tok_start, tok.length);
            vstr_append_cstr(out, CLR_RESET);
        } else {
            vstr_append(out, buf + tok_start, tok.length);
        }

        if (tok.type == TOK_PIPE || tok.type == TOK_BYTE_PIPE ||
            tok.type == TOK_SEMI || tok.type == TOK_AND_AND ||
            tok.type == TOK_OR_OR) {
            cmd_pos = true;
        } else if (tok.type != TOK_NEWLINE) {
            cmd_pos = false;
        }

        last_end = tok_end;
    }

    if (last_end < len) {
        const char *gap = buf + last_end;
        size_t gap_len = len - last_end;
        size_t comment_off = gap_len;
        for (size_t i = 0; i < gap_len; i++) {
            if (gap[i] == '#') { comment_off = i; break; }
        }
        if (comment_off < gap_len) {
            if (comment_off > 0)
                vstr_append(out, gap, comment_off);
            vstr_append_cstr(out, clr_comment);
            vstr_append(out, gap + comment_off, gap_len - comment_off);
            vstr_append_cstr(out, CLR_RESET);
        } else {
            vstr_append(out, gap, gap_len);
        }
    }

    free(src);
}

static void comp_free(EditState *e) {
    if (e->comp_matches) {
        for (size_t i = 0; i < e->comp_count; i++)
            free(e->comp_matches[i]);
        free(e->comp_matches);
        e->comp_matches = NULL;
    }
    if (e->comp_descs) {
        for (size_t i = 0; i < e->comp_count; i++)
            free(e->comp_descs[i]);
        free(e->comp_descs);
        e->comp_descs = NULL;
    }
    e->comp_count = 0;
    e->completing = false;
}

static size_t find_word_start(const char *buf, size_t pos) {
    size_t i = pos;
    while (i > 0 && buf[i-1] != ' ' && buf[i-1] != '|' &&
           buf[i-1] != '(' && buf[i-1] != '{' && buf[i-1] != ';')
        i--;
    return i;
}

typedef enum {
    COMP_CTX_COMMAND,
    COMP_CTX_FILES,
    COMP_CTX_DIRS,
    COMP_CTX_GENERIC,
    COMP_CTX_WORDS,
    COMP_CTX_COMMANDS,
} CompCtx;

static CompCtx get_comp_context(const char *buf, size_t word_start) {

    for (size_t i = word_start; buf[i] && buf[i] != ' '; i++) {
        if (buf[i] == '/') return COMP_CTX_FILES;
    }

    bool is_first_word = true;
    for (size_t i = 0; i < word_start; i++) {
        if (buf[i] != ' ' && buf[i] != '\t') {
            is_first_word = false;
            break;
        }
    }
    if (is_first_word) return COMP_CTX_COMMAND;

    size_t cmd_start = word_start;

    while (cmd_start > 0 && buf[cmd_start - 1] == ' ') cmd_start--;

    size_t seg_start = cmd_start;
    while (seg_start > 0 && buf[seg_start - 1] != '|' &&
           buf[seg_start - 1] != ';' && buf[seg_start - 1] != '{')
        seg_start--;
    while (seg_start < cmd_start && buf[seg_start] == ' ') seg_start++;

    size_t cmd_end = seg_start;
    while (cmd_end < cmd_start && buf[cmd_end] != ' ') cmd_end++;
    char cmd[128];
    size_t clen = cmd_end - seg_start;
    if (clen >= sizeof(cmd)) clen = sizeof(cmd) - 1;
    memcpy(cmd, buf + seg_start, clen);
    cmd[clen] = '\0';

    if (strcmp(cmd, "cd") == 0 || strcmp(cmd, "j") == 0 ||
        strcmp(cmd, "ji") == 0 || strcmp(cmd, "mkdir") == 0 ||
        strcmp(cmd, "pushd") == 0 || strcmp(cmd, "rmdir") == 0)
        return COMP_CTX_DIRS;

    if (strcmp(cmd, "open") == 0 || strcmp(cmd, "save") == 0 ||
        strcmp(cmd, "use") == 0 || strcmp(cmd, "source") == 0 || strcmp(cmd, ".") == 0 ||
        cmd[0] == '^')
        return COMP_CTX_FILES;

    int spec_kind = comp_spec_get_kind(cmd);
    if (spec_kind >= 0) {
        switch (spec_kind) {
        case 0: return COMP_CTX_FILES;
        case 1: return COMP_CTX_DIRS;
        case 2: return COMP_CTX_WORDS;
        case 3: return COMP_CTX_COMMANDS;
        }
    }

    return COMP_CTX_GENERIC;
}

static bool comp_ensure_cap(EditState *e, size_t *cap) {
    if (e->comp_count >= *cap) {
        *cap *= 2;
        char **tmp = realloc(e->comp_matches, *cap * sizeof(char *));
        if (!tmp) return false;
        e->comp_matches = tmp;
    }
    return true;
}

static void gather_file_completions(EditState *e, const char *prefix, size_t prefix_len) {

    const char *last_slash = NULL;
    for (size_t i = 0; i < prefix_len; i++) {
        if (prefix[i] == '/') last_slash = prefix + i;
    }

    char dir[4096] = ".";
    const char *name_prefix = prefix;
    size_t name_prefix_len = prefix_len;

    if (last_slash) {
        size_t dir_len = (size_t)(last_slash - prefix);
        if (dir_len == 0) {
            strcpy(dir, "/");
        } else {
            if (dir_len >= sizeof(dir)) dir_len = sizeof(dir) - 1;
            memcpy(dir, prefix, dir_len);
            dir[dir_len] = '\0';
        }
        name_prefix = last_slash + 1;
        name_prefix_len = prefix_len - (size_t)(name_prefix - prefix);
    }

    DIR *d = opendir(dir);
    if (!d) return;

    size_t cap = 32;
    e->comp_matches = vex_xmalloc(cap * sizeof(char *));

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' && name_prefix_len == 0) continue;
        if (ent->d_name[0] == '.' && name_prefix[0] != '.') continue;
        if (name_prefix_len > 0 &&
            strncasecmp(ent->d_name, name_prefix, name_prefix_len) != 0) continue;

        if (!comp_ensure_cap(e, &cap)) break;

        char path[4096];
        if (last_slash) {
            size_t dir_part = (size_t)(last_slash - prefix) + 1;
            char dir_str[4096];
            memcpy(dir_str, prefix, dir_part);
            dir_str[dir_part] = '\0';
            snprintf(path, sizeof(path), "%s%s", dir_str, ent->d_name);
        } else {
            snprintf(path, sizeof(path), "%s", ent->d_name);
        }

        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISDIR(st.st_mode)) {
            size_t plen = strlen(path);
            if (plen < sizeof(path) - 1) {
                path[plen] = '/';
                path[plen + 1] = '\0';
            }
        }

        e->comp_matches[e->comp_count++] = strdup(path);
    }
    closedir(d);
}

static void gather_dir_completions(EditState *e, const char *prefix, size_t prefix_len) {
    const char *last_slash = NULL;
    for (size_t i = 0; i < prefix_len; i++) {
        if (prefix[i] == '/') last_slash = prefix + i;
    }

    char dir[4096] = ".";
    const char *name_prefix = prefix;
    size_t name_prefix_len = prefix_len;

    if (last_slash) {
        size_t dir_len = (size_t)(last_slash - prefix);
        if (dir_len == 0) strcpy(dir, "/");
        else { if (dir_len >= sizeof(dir)) dir_len = sizeof(dir) - 1;
            memcpy(dir, prefix, dir_len); dir[dir_len] = '\0'; }
        name_prefix = last_slash + 1;
        name_prefix_len = prefix_len - (size_t)(name_prefix - prefix);
    }

    DIR *d = opendir(dir);
    if (!d) return;

    size_t cap = 32;
    e->comp_matches = vex_xmalloc(cap * sizeof(char *));

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' && name_prefix_len == 0) continue;
        if (ent->d_name[0] == '.' && name_prefix[0] != '.') continue;
        if (name_prefix_len > 0 &&
            strncasecmp(ent->d_name, name_prefix, name_prefix_len) != 0) continue;

        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
        struct stat st;
        if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode)) continue;

        if (!comp_ensure_cap(e, &cap)) break;

        char path[4096];
        if (last_slash) {
            size_t dir_part = (size_t)(last_slash - prefix) + 1;
            char dir_str[4096];
            memcpy(dir_str, prefix, dir_part);
            dir_str[dir_part] = '\0';
            snprintf(path, sizeof(path), "%s%s/", dir_str, ent->d_name);
        } else {
            snprintf(path, sizeof(path), "%s/", ent->d_name);
        }
        e->comp_matches[e->comp_count++] = strdup(path);
    }
    closedir(d);
}

static char **path_cmd_cache = NULL;
static size_t path_cmd_count = 0;
static char *path_cmd_env = NULL;

static void path_cache_rebuild(void) {
    for (size_t i = 0; i < path_cmd_count; i++)
        free(path_cmd_cache[i]);
    free(path_cmd_cache);
    free(path_cmd_env);

    path_cmd_count = 0;
    size_t cap = 256;
    path_cmd_cache = malloc(cap * sizeof(char *));

    const char *path_env = getenv("PATH");
    path_cmd_env = path_env ? strdup(path_env) : NULL;
    if (!path_env) return;

    char *path_copy = strdup(path_env);
    char *saveptr = NULL;
    for (char *dir = strtok_r(path_copy, ":", &saveptr); dir;
         dir = strtok_r(NULL, ":", &saveptr)) {
        DIR *pd = opendir(dir);
        if (!pd) continue;
        struct dirent *ent;
        while ((ent = readdir(pd)) != NULL) {
            if (ent->d_name[0] == '.') continue;

            char full[4096];
            snprintf(full, sizeof(full), "%s/%s", dir, ent->d_name);
            if (access(full, X_OK) != 0) continue;

            bool dup = false;
            for (size_t i = 0; i < path_cmd_count; i++) {
                if (strcmp(path_cmd_cache[i], ent->d_name) == 0) {
                    dup = true; break;
                }
            }
            if (dup) continue;

            if (path_cmd_count >= cap) {
                cap *= 2;
                path_cmd_cache = realloc(path_cmd_cache, cap * sizeof(char *));
            }
            path_cmd_cache[path_cmd_count++] = strdup(ent->d_name);
        }
        closedir(pd);
    }
    free(path_copy);
}

static void path_cache_ensure(void) {
    const char *current = getenv("PATH");
    if (!path_cmd_cache ||
        (current && (!path_cmd_env || strcmp(current, path_cmd_env) != 0)) ||
        (!current && path_cmd_env)) {
        path_cache_rebuild();
    }
}

static void gather_command_completions(EditState *e, const char *prefix, size_t prefix_len) {
    if (prefix_len == 0) return;

    size_t cap = 64;
    e->comp_matches = vex_xmalloc(cap * sizeof(char *));

    static const char *keywords[] = {
        "let", "mut", "fn", "if", "else", "for", "in", "while", "loop",
        "break", "continue", "return", "match", "try", "catch", "use",
        "true", "false", "null", "and", "or", "not",
        NULL
    };

    for (int i = 0; keywords[i]; i++) {
        if (strncasecmp(keywords[i], prefix, prefix_len) == 0 &&
            strlen(keywords[i]) > prefix_len) {
            if (!comp_ensure_cap(e, &cap)) break;
            e->comp_matches[e->comp_count++] = strdup(keywords[i]);
        }
    }

    size_t bc = builtin_count();
    for (size_t i = 0; i < bc; i++) {
        const char *name = builtin_name(i);
        if (strncasecmp(name, prefix, prefix_len) == 0 &&
            strlen(name) > prefix_len) {
            if (!comp_ensure_cap(e, &cap)) break;
            e->comp_matches[e->comp_count++] = strdup(name);
        }
    }

    size_t pc = plugin_cmd_count();
    for (size_t i = 0; i < pc; i++) {
        const char *name = plugin_cmd_name(i);
        if (name && strncasecmp(name, prefix, prefix_len) == 0 &&
            strlen(name) > prefix_len) {
            if (!comp_ensure_cap(e, &cap)) break;
            e->comp_matches[e->comp_count++] = strdup(name);
        }
    }

    size_t sc = script_cmd_count();
    for (size_t i = 0; i < sc; i++) {
        const char *name = script_cmd_name(i);
        if (name && strncasecmp(name, prefix, prefix_len) == 0 &&
            strlen(name) > prefix_len) {
            if (!comp_ensure_cap(e, &cap)) break;
            e->comp_matches[e->comp_count++] = strdup(name);
        }
    }

    path_cache_ensure();
    for (size_t i = 0; i < path_cmd_count; i++) {
        const char *name = path_cmd_cache[i];
        if (strncasecmp(name, prefix, prefix_len) != 0) continue;
        if (strlen(name) <= prefix_len) continue;

        bool dup = false;
        for (size_t j = 0; j < e->comp_count; j++) {
            if (strcmp(e->comp_matches[j], name) == 0) {
                dup = true; break;
            }
        }
        if (dup) continue;

        if (!comp_ensure_cap(e, &cap)) break;
        e->comp_matches[e->comp_count++] = strdup(name);
    }

    DIR *d = opendir(".");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            if (prefix_len > 0 &&
                strncmp(ent->d_name, prefix, prefix_len) != 0) continue;
            if (strlen(ent->d_name) <= prefix_len) continue;

            bool dup = false;
            for (size_t i = 0; i < e->comp_count; i++) {
                if (strcmp(e->comp_matches[i], ent->d_name) == 0) {
                    dup = true;
                    break;
                }
            }
            if (dup) continue;

            if (!comp_ensure_cap(e, &cap)) break;

            struct stat st;
            char *entry;
            if (stat(ent->d_name, &st) == 0 && S_ISDIR(st.st_mode)) {
                size_t nlen = strlen(ent->d_name);
                entry = malloc(nlen + 2);
                memcpy(entry, ent->d_name, nlen);
                entry[nlen] = '/';
                entry[nlen + 1] = '\0';
            } else {
                entry = strdup(ent->d_name);
            }
            e->comp_matches[e->comp_count++] = entry;
        }
        closedir(d);
    }
}

static void gather_word_completions(EditState *e, const char *prefix, size_t prefix_len,
                                     const char *cmd_name) {
    const char **words;
    size_t count = comp_spec_get_words(cmd_name, &words);
    if (count == 0) return;

    size_t flag_count = 0;
    for (size_t i = 0; i < count; i++)
        if (words[i][0] == '-') flag_count++;
    bool mostly_flags = (flag_count > count / 2);
    if (mostly_flags && (prefix_len == 0 || prefix[0] != '-'))
        return;

    size_t cap = 32;
    e->comp_matches = vex_xmalloc(cap * sizeof(char *));

    for (size_t i = 0; i < count; i++) {
        if (prefix_len > 0 && strncasecmp(words[i], prefix, prefix_len) != 0) continue;
        if (strlen(words[i]) <= prefix_len) continue;
        if (!comp_ensure_cap(e, &cap)) break;
        e->comp_matches[e->comp_count++] = strdup(words[i]);
    }
}

static char *extract_cmd_name(const char *buf, size_t word_start) {
    size_t seg_start = word_start;
    while (seg_start > 0 && buf[seg_start - 1] == ' ') seg_start--;
    size_t s = seg_start;
    while (s > 0 && buf[s - 1] != '|' && buf[s - 1] != ';' && buf[s - 1] != '{') s--;
    while (s < seg_start && buf[s] == ' ') s++;
    size_t e = s;
    while (e < seg_start && buf[e] != ' ') e++;
    static char cmd[128];
    size_t clen = e - s;
    if (clen >= sizeof(cmd)) clen = sizeof(cmd) - 1;
    memcpy(cmd, buf + s, clen);
    cmd[clen] = '\0';

    if (e < seg_start) {
        size_t sub_s = e;
        while (sub_s < seg_start && buf[sub_s] == ' ') sub_s++;
        size_t sub_e = sub_s;
        while (sub_e < seg_start && buf[sub_e] != ' ') sub_e++;
        if (sub_e > sub_s && sub_e < word_start) {

            char compound[128];
            size_t sub_len = sub_e - sub_s;
            if (clen + 1 + sub_len < sizeof(compound)) {
                memcpy(compound, cmd, clen);
                compound[clen] = '-';
                memcpy(compound + clen + 1, buf + sub_s, sub_len);
                compound[clen + 1 + sub_len] = '\0';

                if (comp_spec_get_kind(compound) >= 0) {
                    memcpy(cmd, compound, clen + 1 + sub_len + 1);
                }
            }
        }
    }

    return cmd;
}

static void do_complete(EditState *e) {
    if (!e->completing) {
        comp_free(e);

        size_t word_start = find_word_start(e->buf.buf, e->buf.pos);
        const char *word = e->buf.buf + word_start;
        size_t word_len = e->buf.pos - word_start;

        e->comp_word_start = word_start;
        e->comp_word_len = word_len;
        e->comp_idx = 0;

        if (word_len > 0 && word[0] == '$') {
            const char *var_prefix = word + 1;
            size_t var_plen = word_len - 1;
            char prefix_buf[128];
            if (var_plen < sizeof(prefix_buf)) {
                memcpy(prefix_buf, var_prefix, var_plen);
                prefix_buf[var_plen] = '\0';

                size_t var_count = 0;
                char **vars = scope_complete_vars(prefix_buf, &var_count);
                if (vars && var_count > 0) {
                    e->comp_matches = malloc(var_count * sizeof(char *));
                    e->comp_count = 0;
                    for (size_t i = 0; i < var_count; i++) {

                        size_t nlen = strlen(vars[i]);
                        char *match = vex_xmalloc(nlen + 2);
                        match[0] = '$';
                        memcpy(match + 1, vars[i], nlen + 1);
                        e->comp_matches[e->comp_count++] = match;
                        free(vars[i]);
                    }
                    free(vars);
                    goto have_completions;
                }
                if (vars) free(vars);
            }
        }

        bool have_dynamic = false;
        if (word_start > 0) {
            char *cmd = extract_cmd_name(e->buf.buf, word_start);
            if (cmd[0]) {

                char prefix[256];
                size_t plen = word_len < sizeof(prefix) - 1 ? word_len : sizeof(prefix) - 1;
                memcpy(prefix, word, plen);
                prefix[plen] = '\0';

                VexValue *dyn = comp_callback_query(cmd, prefix);
                if (dyn && dyn->type == VEX_VAL_LIST) {
                    size_t count = vval_list_len(dyn);
                    e->comp_matches = malloc((count + 1) * sizeof(char *));
                    e->comp_count = 0;
                    for (size_t ci = 0; ci < count; ci++) {
                        VexValue *item = vval_list_get(dyn, ci);
                        if (item && item->type == VEX_VAL_STRING) {
                            const char *s = vstr_data(&item->string);
                            if (word_len == 0 || strncmp(s, prefix, word_len) == 0) {
                                e->comp_matches[e->comp_count++] = strdup(s);
                            }
                        }
                    }
                    have_dynamic = (e->comp_count > 0);
                    if (!have_dynamic) {
                        free(e->comp_matches);
                        e->comp_matches = NULL;
                    }
                }
                if (dyn) vval_release(dyn);
            }
        }

        if (!have_dynamic) {
            CompCtx comp_ctx = get_comp_context(e->buf.buf, word_start);
            switch (comp_ctx) {
            case COMP_CTX_COMMAND:
                gather_command_completions(e, word, word_len);
                break;
            case COMP_CTX_DIRS:
                gather_dir_completions(e, word, word_len);
                break;
            case COMP_CTX_FILES:
                gather_file_completions(e, word, word_len);
                break;
            case COMP_CTX_GENERIC:
                if (word_len > 0 && word[0] == '-') {
                    char *cmd = extract_cmd_name(e->buf.buf, word_start);
                    if (cmd[0]) {
                        comp_spec_try_help(cmd);
                        gather_word_completions(e, word, word_len, cmd);
                        if (e->comp_count > 0) break;
                    }
                }
                gather_file_completions(e, word, word_len);
                break;
            case COMP_CTX_WORDS: {
                char *cmd = extract_cmd_name(e->buf.buf, word_start);
                gather_word_completions(e, word, word_len, cmd);
                if (e->comp_count == 0 && word_len > 0 && word[0] == '-') {
                    comp_spec_try_help(cmd);
                    gather_word_completions(e, word, word_len, cmd);
                }
                if (e->comp_count == 0)
                    gather_file_completions(e, word, word_len);
                break;
            }
            case COMP_CTX_COMMANDS:
                gather_command_completions(e, word, word_len);
                break;
            }
        }

have_completions:
        if (e->comp_count == 0) return;

        e->comp_descs = calloc(e->comp_count, sizeof(char *));
        for (size_t i = 0; i < e->comp_count; i++) {
            const BuiltinCmd *cmd = builtin_lookup(e->comp_matches[i]);
            if (cmd && cmd->description) {
                e->comp_descs[i] = strdup(cmd->description);
            }
        }

        if (e->comp_count == 1) {

            const char *match = e->comp_matches[0];
            size_t match_len = strlen(match);

            size_t tail_len = e->buf.len - e->buf.pos;
            size_t new_len = e->comp_word_start + match_len + tail_len;
            buf_grow(&e->buf, new_len);
            memmove(e->buf.buf + e->comp_word_start + match_len,
                    e->buf.buf + e->buf.pos, tail_len);
            memcpy(e->buf.buf + e->comp_word_start, match, match_len);
            e->buf.len = new_len;
            e->buf.pos = e->comp_word_start + match_len;
            e->buf.buf[e->buf.len] = '\0';

            if (match_len > 0 && match[match_len - 1] != '/') {
                buf_insert_char(&e->buf, ' ');
            }

            comp_free(e);
            return;
        }

        e->completing = true;
    } else {

        e->comp_idx = (e->comp_idx + 1) % e->comp_count;
    }

    const char *match = e->comp_matches[e->comp_idx];
    size_t match_len = strlen(match);
    size_t tail_start = e->comp_word_start + e->comp_word_len;

    size_t tail_len = e->buf.len > tail_start ? e->buf.len - tail_start : 0;

    size_t new_len = e->comp_word_start + match_len + tail_len;
    buf_grow(&e->buf, new_len);

    if (tail_len > 0) {
        memmove(e->buf.buf + e->comp_word_start + match_len,
                e->buf.buf + tail_start, tail_len);
    }
    memcpy(e->buf.buf + e->comp_word_start, match, match_len);
    e->buf.len = new_len;
    e->buf.pos = e->comp_word_start + match_len;
    e->buf.buf[e->buf.len] = '\0';
    e->comp_word_len = match_len;
}

static const char *format_preview_size(off_t size, char *buf, size_t buflen) {
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

static void get_command_preview(const char *buf, size_t len, VexStr *preview) {
    if (len == 0) return;

    const char *p = buf;
    while (*p == ' ' || *p == '\t') p++;

    bool is_rm = (strncmp(p, "rm ", 3) == 0);
    bool is_mv = (strncmp(p, "mv ", 3) == 0);
    bool is_cp = (strncmp(p, "cp ", 3) == 0);

    if (!is_rm && !is_mv && !is_cp) return;
    p += 3;
    while (*p == ' ') p++;
    if (*p == '\0') return;

    while (*p == '-') {
        while (*p && *p != ' ') p++;
        while (*p == ' ') p++;
    }
    if (*p == '\0') return;

    if (is_rm) {
        glob_t gl;
        memset(&gl, 0, sizeof(gl));
        int first = 1;

        const char *arg = p;
        while (*arg) {
            while (*arg == ' ') arg++;
            if (*arg == '\0') break;
            const char *end = arg;
            while (*end && *end != ' ') end++;

            char pattern[4096];
            size_t plen = (size_t)(end - arg);
            if (plen >= sizeof(pattern)) plen = sizeof(pattern) - 1;
            memcpy(pattern, arg, plen);
            pattern[plen] = '\0';

            int flags = GLOB_NOCHECK;
            if (!first) flags |= GLOB_APPEND;
            glob(pattern, flags, NULL, &gl);
            first = 0;
            arg = end;
        }

        if (gl.gl_pathc == 0) {
            globfree(&gl);
            return;
        }

        size_t file_count = 0;
        size_t dir_count = 0;
        off_t total_size = 0;
        VexStr names = vstr_empty();

        for (size_t i = 0; i < gl.gl_pathc; i++) {
            struct stat st;
            if (stat(gl.gl_pathv[i], &st) != 0) continue;

            if (S_ISDIR(st.st_mode)) {
                dir_count++;
            } else {
                file_count++;
                total_size += st.st_size;
            }

            if (vstr_len(&names) > 0) vstr_append_cstr(&names, ", ");
            const char *base = strrchr(gl.gl_pathv[i], '/');
            vstr_append_cstr(&names, base ? base + 1 : gl.gl_pathv[i]);

            if (file_count + dir_count >= 8 && i + 1 < gl.gl_pathc) {
                char more[32];
                snprintf(more, sizeof(more), " +%zu more",
                         gl.gl_pathc - i - 1);
                vstr_append_cstr(&names, more);
                for (size_t j = i + 1; j < gl.gl_pathc; j++) {
                    if (stat(gl.gl_pathv[j], &st) == 0) {
                        if (S_ISDIR(st.st_mode)) dir_count++;
                        else { file_count++; total_size += st.st_size; }
                    }
                }
                break;
            }
        }
        globfree(&gl);

        if (file_count + dir_count == 0) {
            vstr_free(&names);
            return;
        }

        char sizebuf[32];
        format_preview_size(total_size, sizebuf, sizeof(sizebuf));

        vstr_append_cstr(preview, "\033[90m  trash: ");
        vstr_append_str(preview, &names);
        if (file_count > 0) {
            char info[64];
            snprintf(info, sizeof(info), " (%zu file%s, %s)",
                     file_count, file_count == 1 ? "" : "s", sizebuf);
            vstr_append_cstr(preview, info);
        }
        if (dir_count > 0) {
            char info[64];
            snprintf(info, sizeof(info), " (%zu dir%s — use rm -r)",
                     dir_count, dir_count == 1 ? "" : "s");
            vstr_append_cstr(preview, info);
        }
        vstr_append_cstr(preview, "\033[0m");
        vstr_free(&names);

    } else if (is_mv || is_cp) {
        const char *src_start = p;
        while (*p && *p != ' ') p++;
        size_t src_len = (size_t)(p - src_start);
        while (*p == ' ') p++;
        if (*p == '\0') return; /* no dest yet */

        char src[4096], dst[4096];
        if (src_len >= sizeof(src)) src_len = sizeof(src) - 1;
        memcpy(src, src_start, src_len);
        src[src_len] = '\0';

        const char *dst_start = p;
        while (*p && *p != ' ') p++;
        size_t dst_len = (size_t)(p - dst_start);
        if (dst_len >= sizeof(dst)) dst_len = sizeof(dst) - 1;
        memcpy(dst, dst_start, dst_len);
        dst[dst_len] = '\0';

        struct stat st;
        if (stat(src, &st) != 0) return;

        char sizebuf[32];
        format_preview_size(st.st_size, sizebuf, sizeof(sizebuf));

        const char *src_base = strrchr(src, '/');
        src_base = src_base ? src_base + 1 : src;
        const char *dst_base = strrchr(dst, '/');
        dst_base = dst_base ? dst_base + 1 : dst;

        vstr_append_cstr(preview, "\033[90m  ");
        vstr_append_cstr(preview, is_mv ? "move" : "copy");
        vstr_append_cstr(preview, ": ");
        vstr_append_cstr(preview, src_base);
        vstr_append_cstr(preview, " -> ");
        vstr_append_cstr(preview, dst_base);
        if (!S_ISDIR(st.st_mode)) {
            char info[64];
            snprintf(info, sizeof(info), " (%s)", sizebuf);
            vstr_append_cstr(preview, info);
        }
        vstr_append_cstr(preview, "\033[0m");
    }
}

static void render(EditState *e) {

    VexStr out = vstr_empty();

    if (e->old_row_count > 1) {
        char move_up[32];
        snprintf(move_up, sizeof(move_up), "\033[%zuA", e->old_row_count - 1);
        vstr_append_cstr(&out, move_up);
    }
    vstr_append_cstr(&out, "\r\033[J");

    if (e->vi_mode) {
        if (e->vi_insert)
            vstr_append_cstr(&out, "\033[1;32m[I]\033[0m ");
        else
            vstr_append_cstr(&out, "\033[1;33m[N]\033[0m ");
    }

    vstr_append_cstr(&out, e->prompt);

    highlight_append(&out, e->buf.buf, e->buf.len);

    if (e->completing && e->comp_count > 1) {
        char indicator[64];
        snprintf(indicator, sizeof(indicator), " \033[90m(%zu/%zu)",
                 e->comp_idx + 1, e->comp_count);
        vstr_append_cstr(&out, indicator);
        if (e->comp_descs && e->comp_descs[e->comp_idx]) {
            vstr_append_cstr(&out, " ");
            vstr_append_cstr(&out, e->comp_descs[e->comp_idx]);
        }
        vstr_append_cstr(&out, "\033[0m");
    } else {
        const char *hint = find_history_hint(e);
        if (hint) {
            vstr_append_cstr(&out, "\033[90m");
            vstr_append_cstr(&out, hint);
            vstr_append_cstr(&out, "\033[0m");
        }
    }

    vstr_append_cstr(&out, "\033[K");

    if (e->rprompt && e->rprompt_width > 0) {
        size_t vi_ind_w = e->vi_mode ? 4 : 0;
        size_t content_width = vi_ind_w + e->prompt_width +
                               utf8_strwidth(e->buf.buf, e->buf.len);

        const char *hint_str = find_history_hint(e);
        if (hint_str) content_width += utf8_strwidth(hint_str, strlen(hint_str));

        if (content_width + e->rprompt_width + 2 <= (size_t)e->term_cols) {
            char rmove[32];
            snprintf(rmove, sizeof(rmove), "\033[%dG",
                     e->term_cols - (int)e->rprompt_width + 1);
            vstr_append_cstr(&out, rmove);
            vstr_append_cstr(&out, e->rprompt);
        }
    }

    size_t preview_rows = 0;
    if (!e->completing && e->buf.len > 0) {
        VexStr preview = vstr_empty();
        get_command_preview(e->buf.buf, e->buf.len, &preview);
        if (vstr_len(&preview) > 0) {
            vstr_append_cstr(&out, "\n\r\033[K");
            vstr_append_str(&out, &preview);
            preview_rows = 1;
        }
        vstr_free(&preview);
    }

    if (preview_rows > 0) {
        char move_up[32];
        snprintf(move_up, sizeof(move_up), "\033[%zuA", preview_rows);
        vstr_append_cstr(&out, move_up);
    }

    e->comp_menu_rows = 0;

    size_t vi_indicator_width = e->vi_mode ? 4 : 0;
    size_t total_width = vi_indicator_width + e->prompt_width +
                         utf8_strwidth(e->buf.buf, e->buf.len);
    const char *hint_str = find_history_hint(e);
    if (hint_str) total_width += utf8_strwidth(hint_str, strlen(hint_str));
    size_t content_rows = e->term_cols > 0 ? (total_width + (size_t)e->term_cols - 1) / (size_t)e->term_cols : 1;
    if (content_rows < 1) content_rows = 1;
    e->old_row_count = content_rows;

    size_t cursor_col = vi_indicator_width + e->prompt_width +
                        utf8_strwidth(e->buf.buf, e->buf.pos);

    size_t cursor_row = e->term_cols > 0 ? cursor_col / (size_t)e->term_cols : 0;
    size_t cursor_phys_col = e->term_cols > 0 ? cursor_col % (size_t)e->term_cols : cursor_col;

    if (content_rows > 1) {
        char move_up[32];
        snprintf(move_up, sizeof(move_up), "\033[%zuA", content_rows - 1);
        vstr_append_cstr(&out, move_up);
    }
    vstr_append_cstr(&out, "\r");

    if (cursor_row > 0) {
        char move_down[32];
        snprintf(move_down, sizeof(move_down), "\033[%zuB", cursor_row);
        vstr_append_cstr(&out, move_down);
    }
    if (cursor_phys_col > 0) {
        char move[32];
        snprintf(move, sizeof(move), "\033[%zuC", cursor_phys_col);
        vstr_append_cstr(&out, move);
    }

    write(STDOUT_FILENO, vstr_data(&out), vstr_len(&out));
    vstr_free(&out);
}

static void clear_screen(void) {
    write(STDOUT_FILENO, "\033[H\033[2J", 7);
}

static void swap_chars(EditBuf *b) {
    if (b->pos == 0 || b->len < 2) return;
    if (b->pos == b->len) b->pos--;

    size_t p = b->pos;
    size_t prev = p > 0 ? p - 1 : 0;
    char tmp = b->buf[prev];
    b->buf[prev] = b->buf[p];
    b->buf[p] = tmp;
    if (b->pos < b->len) b->pos++;
}

static void search_render(EditState *e) {
    VexStr out = vstr_empty();
    vstr_append_cstr(&out, "\r\033[K");

    vstr_append_cstr(&out, "(reverse-i-search)'");
    vstr_append(&out, e->search_query, e->search_len);
    vstr_append_cstr(&out, "': ");

    if (e->search_match_idx >= 0) {
        const char *line = e->history.entries[(size_t)e->search_match_idx];
        vstr_append_cstr(&out, line);
    }

    size_t prompt_len = 20 + e->search_len + 2;
    if (e->search_match_idx >= 0) {
        size_t cur = prompt_len + e->search_match_pos;
        vstr_append_cstr(&out, "\r");
        if (cur > 0) {
            char move[32];
            snprintf(move, sizeof(move), "\033[%zuC", cur);
            vstr_append_cstr(&out, move);
        }
    }

    write(STDOUT_FILENO, vstr_data(&out), vstr_len(&out));
    vstr_free(&out);
}

static void search_find(EditState *e, ssize_t start_from) {
    if (e->search_len == 0) {
        e->search_match_idx = -1;
        return;
    }
    for (ssize_t i = start_from; i >= 0; i--) {
        const char *found = strstr(e->history.entries[(size_t)i],
                                   e->search_query);
        if (found) {
            e->search_match_idx = i;
            e->search_match_pos = (size_t)(found -
                                   e->history.entries[(size_t)i]);
            return;
        }
    }
    e->search_match_idx = -1;
}

static bool reverse_search(EditState *e) {
    e->searching = true;
    e->search_len = 0;
    e->search_query[0] = '\0';
    e->search_match_idx = -1;
    e->search_match_pos = 0;

    search_render(e);

    for (;;) {
        int key = read_key();
        if (key == -1) {
            e->searching = false;
            return false;
        }

        switch (key) {
        case KEY_ENTER:

            if (e->search_match_idx >= 0) {
                buf_set(&e->buf,
                        e->history.entries[(size_t)e->search_match_idx]);
            }
            e->searching = false;
            return true;

        case KEY_CTRL_C:
        case KEY_CTRL_G:
        case KEY_ESC:

            e->searching = false;
            return false;

        case KEY_CTRL_R:

            if (e->search_match_idx > 0) {
                search_find(e, e->search_match_idx - 1);
            }
            break;

        case KEY_CTRL_S:

            if (e->search_match_idx >= 0 &&
                (size_t)e->search_match_idx < e->history.count - 1) {

                for (size_t i = (size_t)e->search_match_idx + 1;
                     i < e->history.count; i++) {
                    const char *found = strstr(e->history.entries[i],
                                               e->search_query);
                    if (found) {
                        e->search_match_idx = (ssize_t)i;
                        e->search_match_pos = (size_t)(found -
                                              e->history.entries[i]);
                        break;
                    }
                }
            }
            break;

        case KEY_BACKSPACE:
        case KEY_CTRL_H:
            if (e->search_len > 0) {
                e->search_query[--e->search_len] = '\0';
                search_find(e, (ssize_t)e->history.count - 1);
            }
            break;

        default:

            if (key < 32 || key == KEY_UP || key == KEY_DOWN ||
                key == KEY_LEFT || key == KEY_RIGHT) {
                if (e->search_match_idx >= 0) {
                    buf_set(&e->buf,
                            e->history.entries[(size_t)e->search_match_idx]);
                }
                e->searching = false;
                return true;
            }

            if (key >= 32 && key < 127 &&
                e->search_len < sizeof(e->search_query) - 1) {
                e->search_query[e->search_len++] = (char)key;
                e->search_query[e->search_len] = '\0';

                ssize_t from = e->search_match_idx >= 0
                    ? e->search_match_idx
                    : (ssize_t)e->history.count - 1;
                search_find(e, from);
            }
            break;
        }

        search_render(e);
    }
}

static void vi_set_cursor_block(void) {
    write(STDOUT_FILENO, "\033[2 q", 5);
}

static void vi_set_cursor_bar(void) {
    write(STDOUT_FILENO, "\033[6 q", 5);
}

void edit_init(EditState *e) {
    memset(e, 0, sizeof(EditState));
    buf_init(&e->buf);
    history_init(&e->history);
    e->raw_mode = false;
    e->prompt = NULL;
    e->prompt_width = 0;

    const char *mode = getenv("VEX_EDIT_MODE");
    if (mode && strcmp(mode, "vi") == 0) {
        e->vi_mode = true;
        e->vi_insert = true;
    }
}

void edit_free(EditState *e) {
    buf_free(&e->buf);
    history_free(&e->history);
    comp_free(e);
    free(e->prompt);
    free(e->rprompt);
    free(e->hint);
    free(e->kill_ring);
    free(e->undo_buf);
    free(e->saved_input);
    for (size_t i = 0; i < e->paste_queue_count; i++)
        free(e->paste_queue[i]);
    free(e->paste_queue);
    edit_disable_raw(e);
}

static void abbr_expand_buf(EditBuf *buf) {
    if (buf->len == 0) return;
    size_t start = 0;
    for (size_t i = 0; i < buf->len; i++) {
        if (buf->buf[i] == '|' || buf->buf[i] == ';')
            start = i + 1;
    }
    while (start < buf->len && buf->buf[start] == ' ') start++;
    size_t end = start;
    while (end < buf->len && buf->buf[end] != ' ') end++;
    if (end == buf->len && end > start) {
        char word[128];
        size_t wlen = end - start;
        if (wlen < sizeof(word)) {
            memcpy(word, buf->buf + start, wlen);
            word[wlen] = '\0';
            const char *expansion = abbr_lookup(word);
            if (expansion) {
                size_t elen = strlen(expansion);
                size_t tail_len = buf->len - end;
                size_t new_len = start + elen + tail_len;
                buf_grow(buf, new_len);
                memmove(buf->buf + start + elen,
                        buf->buf + end, tail_len);
                memcpy(buf->buf + start, expansion, elen);
                buf->len = new_len;
                buf->pos = new_len;
                buf->buf[buf->len] = '\0';
            }
        }
    }
}

char *edit_readline(EditState *e, const char *prompt) {
    if (e->paste_queue_count > 0) {
        char *line = e->paste_queue[0];
        memmove(e->paste_queue, e->paste_queue + 1,
                (e->paste_queue_count - 1) * sizeof(char *));
        e->paste_queue_count--;
        if (prompt) {
            write(STDOUT_FILENO, prompt, strlen(prompt));
        }
        VexStr hl = vstr_empty();
        highlight_append(&hl, line, strlen(line));
        write(STDOUT_FILENO, vstr_data(&hl), vstr_len(&hl));
        vstr_free(&hl);
        write(STDOUT_FILENO, "\r\n", 2);
        e->old_row_count = 0;
        return line;
    }

    if (!isatty(STDIN_FILENO)) {

        static char line[4096];
        if (!fgets(line, sizeof(line), stdin)) return NULL;
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        return strdup(line);
    }

    const char *edit_mode = getenv("VEX_EDIT_MODE");
    if (edit_mode && strcmp(edit_mode, "vi") == 0) {
        e->vi_mode = true;
    } else if (edit_mode && strcmp(edit_mode, "emacs") == 0) {
        e->vi_mode = false;
        e->vi_insert = false;
    }

    if (e->vi_mode) e->vi_insert = true;

    free(e->prompt);
    e->prompt = strdup(prompt);
    e->prompt_width = prompt_display_width(prompt);

    buf_clear(&e->buf);
    if (e->saved_input) {
        buf_set(&e->buf, e->saved_input);
        e->buf.pos = e->saved_input_pos;
        free(e->saved_input);
        e->saved_input = NULL;
    }
    e->history.browse_pos = e->history.count;

    if (!edit_enable_raw(e)) {

        write(STDOUT_FILENO, prompt, strlen(prompt));
        static char line[4096];
        if (!fgets(line, sizeof(line), stdin)) return NULL;
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        return strdup(line);
    }

    edit_get_term_size(e);

    if (e->vi_mode) {
        if (e->vi_insert) vi_set_cursor_bar();
        else vi_set_cursor_block();
    }

    render(e);

    for (;;) {

        if (vex_got_sigwinch) {
            vex_got_sigwinch = 0;
            edit_get_term_size(e);
        }

        int key = read_key();
        if (key == -1) {
            edit_disable_raw(e);
            return NULL;
        }

        if (key == KEY_PASTE_START) {
            e->in_paste = true;
            continue;
        }
        if (key == KEY_PASTE_END) {
            e->in_paste = false;
            if (e->buf.len > 0) {
                size_t nl_count = 0;
                for (size_t i = 0; i < e->buf.len; i++) {
                    if (e->buf.buf[i] == '\n') nl_count++;
                }
                if (nl_count > 0) {
                    char *text = strdup(e->buf.buf);
                    char *saveptr = NULL;
                    char *line = strtok_r(text, "\n", &saveptr);
                    char *first_line = NULL;
                    if (line) {
                        while (*line == ' ' || *line == '\t') line++;
                        first_line = strdup(line);
                        buf_clear(&e->buf);
                        buf_set(&e->buf, first_line);
                        e->buf.pos = e->buf.len;
                    }
                    while ((line = strtok_r(NULL, "\n", &saveptr)) != NULL) {
                        while (*line == ' ' || *line == '\t') line++;
                        if (line[0] == '\0') continue;
                        if (e->paste_queue_count >= e->paste_queue_cap) {
                            e->paste_queue_cap = e->paste_queue_cap ? e->paste_queue_cap * 2 : 8;
                            e->paste_queue = realloc(e->paste_queue,
                                                     e->paste_queue_cap * sizeof(char *));
                        }
                        e->paste_queue[e->paste_queue_count++] = strdup(line);
                    }
                    free(text);
                    if (e->vi_mode) vi_set_cursor_bar();
                    edit_disable_raw(e);
                    write(STDOUT_FILENO, "\r\033[K", 4);
                    if (e->prompt)
                        write(STDOUT_FILENO, e->prompt, strlen(e->prompt));
                    if (first_line) {
                        VexStr hl = vstr_empty();
                        highlight_append(&hl, first_line, strlen(first_line));
                        write(STDOUT_FILENO, vstr_data(&hl), vstr_len(&hl));
                        vstr_free(&hl);
                    }
                    write(STDOUT_FILENO, "\r\n", 2);
                    e->old_row_count = 0;
                    if (e->vi_mode) e->vi_insert = true;
                    char *result = first_line ? first_line : strdup("");
                    return result;
                }
            }
            render(e);
            continue;
        }

        if (e->in_paste) {
            if (key == KEY_ENTER || key == '\n' || key == '\r') {
                buf_insert_char(&e->buf, '\n');
            } else if (key >= 32 && key < 127) {
                buf_insert_char(&e->buf, (char)key);
            } else if (key >= 128) {
                buf_insert_char(&e->buf, (char)key);
            }
            continue;
        }

        if (key != KEY_TAB && key != KEY_SHIFT_TAB && e->completing) {
            comp_free(e);
        }

        if (e->vi_mode && !e->vi_insert) {

            if ((key >= '1' && key <= '9') || (key == '0' && e->vi_repeat > 0)) {
                e->vi_repeat = e->vi_repeat * 10 + (key - '0');
                render(e);
                continue;
            }
            int count = e->vi_repeat > 0 ? e->vi_repeat : 1;
            e->vi_repeat = 0;

            switch (key) {
            case KEY_ENTER:
                abbr_expand_buf(&e->buf);
                vi_set_cursor_bar();
                /* Clear hint/preview before newline */
                write(STDOUT_FILENO, "\033[K", 3);
                edit_disable_raw(e);
                write(STDOUT_FILENO, "\n", 1);
                e->vi_insert = true;
                return strdup(e->buf.buf);

            case KEY_CTRL_C:
                vi_set_cursor_bar();
                write(STDOUT_FILENO, "\033[K\033[J", 6);
                edit_disable_raw(e);
                write(STDOUT_FILENO, "^C\n", 3);
                e->vi_insert = true;
                return strdup("");

            case KEY_CTRL_D:
                if (e->buf.len == 0) {
                    vi_set_cursor_bar();
                    edit_disable_raw(e);
                    e->vi_insert = true;
                    return NULL;
                }
                break;

            case 'h':
            case KEY_LEFT:
                for (int n = 0; n < count; n++) cursor_left(&e->buf);
                break;

            case 'l':
            case KEY_RIGHT:
                for (int n = 0; n < count; n++) cursor_right(&e->buf);
                break;

            case 'k':
            case KEY_UP:
                for (int n = 0; n < count; n++) history_browse_up(e);
                break;

            case 'j':
            case KEY_DOWN:
                for (int n = 0; n < count; n++) history_browse_down(e);
                break;

            case 'w':
                for (int n = 0; n < count; n++) cursor_word_right(&e->buf);
                break;

            case 'W':
                for (int n = 0; n < count; n++) cursor_WORD_right(&e->buf);
                break;

            case 'b':
                for (int n = 0; n < count; n++) cursor_word_left(&e->buf);
                break;

            case 'B':
                for (int n = 0; n < count; n++) cursor_WORD_left(&e->buf);
                break;

            case 'e':
                for (int n = 0; n < count; n++) cursor_word_end(&e->buf);
                break;

            case 'E':
                for (int n = 0; n < count; n++) cursor_WORD_end(&e->buf);
                break;

            case '0':
            case KEY_HOME:
                cursor_home(&e->buf);
                break;

            case '^':
                cursor_home(&e->buf);
                while (e->buf.pos < e->buf.len && e->buf.buf[e->buf.pos] == ' ')
                    e->buf.pos++;
                break;

            case '$':
            case KEY_END:
                cursor_end(&e->buf);
                break;

            case 'x':
            case KEY_DELETE:
                vi_save_undo(e);
                for (int n = 0; n < count; n++) buf_delete_forward(&e->buf);
                e->vi_last_cmd = 'x';
                break;

            case 's':
                vi_save_undo(e);
                for (int n = 0; n < count; n++) buf_delete_forward(&e->buf);
                e->vi_insert = true;
                vi_set_cursor_bar();
                e->vi_last_cmd = 's';
                break;

            case 'd': {

                vi_save_undo(e);
                int key2 = read_key();
                switch (key2) {
                case 'd':
                    buf_clear(&e->buf);
                    break;
                case 'w':
                    for (int n = 0; n < count; n++) kill_word_forward(e);
                    break;
                case 'b':
                    for (int n = 0; n < count; n++) kill_word_back(e);
                    break;
                case 'e': {
                    size_t old = e->buf.pos;
                    for (int n = 0; n < count; n++) cursor_word_end(&e->buf);
                    if (e->buf.pos < e->buf.len) e->buf.pos++;
                    size_t dlen = e->buf.pos - old;
                    if (dlen > 0) {
                        kill_ring_save(e, e->buf.buf + old, dlen);
                        memmove(e->buf.buf + old, e->buf.buf + e->buf.pos,
                                e->buf.len - e->buf.pos);
                        e->buf.len -= dlen;
                        e->buf.buf[e->buf.len] = '\0';
                        e->buf.pos = old;
                    }
                    break;
                }
                case '$':
                    kill_to_end(e);
                    break;
                case '0':
                    kill_to_start(e);
                    break;
                default:
                    break;
                }
                e->vi_last_cmd = 'd';
                e->vi_last_cmd2 = key2;
                break;
            }

            case 'D':
                vi_save_undo(e);
                kill_to_end(e);
                e->vi_last_cmd = 'D';
                break;

            case 'c': {

                vi_save_undo(e);
                int key2 = read_key();
                switch (key2) {
                case 'c':
                    buf_clear(&e->buf);
                    break;
                case 'w':
                    for (int n = 0; n < count; n++) kill_word_forward(e);
                    break;
                case 'e': {
                    size_t old = e->buf.pos;
                    for (int n = 0; n < count; n++) cursor_word_end(&e->buf);
                    if (e->buf.pos < e->buf.len) e->buf.pos++;
                    size_t dlen = e->buf.pos - old;
                    if (dlen > 0) {
                        memmove(e->buf.buf + old, e->buf.buf + e->buf.pos,
                                e->buf.len - e->buf.pos);
                        e->buf.len -= dlen;
                        e->buf.buf[e->buf.len] = '\0';
                        e->buf.pos = old;
                    }
                    break;
                }
                case '$':
                    kill_to_end(e);
                    break;
                case 'b':
                    for (int n = 0; n < count; n++) kill_word_back(e);
                    break;
                case '0':
                    kill_to_start(e);
                    break;
                default:
                    break;
                }
                e->vi_insert = true;
                vi_set_cursor_bar();
                e->vi_last_cmd = 'c';
                e->vi_last_cmd2 = key2;
                break;
            }

            case 'C':
                vi_save_undo(e);
                kill_to_end(e);
                e->vi_insert = true;
                vi_set_cursor_bar();
                e->vi_last_cmd = 'C';
                break;

            case 'S':
                vi_save_undo(e);
                buf_clear(&e->buf);
                e->vi_insert = true;
                vi_set_cursor_bar();
                e->vi_last_cmd = 'S';
                break;

            case 'i':
                vi_save_undo(e);
                e->vi_insert = true;
                vi_set_cursor_bar();
                break;

            case 'a':
                vi_save_undo(e);
                if (e->buf.pos < e->buf.len) cursor_right(&e->buf);
                e->vi_insert = true;
                vi_set_cursor_bar();
                break;

            case 'A':
                vi_save_undo(e);
                cursor_end(&e->buf);
                e->vi_insert = true;
                vi_set_cursor_bar();
                break;

            case 'I':
                vi_save_undo(e);
                cursor_home(&e->buf);
                e->vi_insert = true;
                vi_set_cursor_bar();
                break;

            case 'r': {
                int key2 = read_key();
                if (key2 >= 32 && key2 < 127 && e->buf.pos < e->buf.len) {
                    vi_save_undo(e);
                    for (int n = 0; n < count && e->buf.pos + (size_t)n < e->buf.len; n++)
                        e->buf.buf[e->buf.pos + (size_t)n] = (char)key2;
                    e->vi_last_cmd = 'r';
                    e->vi_last_cmd2 = key2;
                }
                break;
            }

            case '~':
                if (e->buf.pos < e->buf.len) {
                    vi_save_undo(e);
                    for (int n = 0; n < count && e->buf.pos < e->buf.len; n++) {
                        char c = e->buf.buf[e->buf.pos];
                        if (c >= 'a' && c <= 'z') e->buf.buf[e->buf.pos] = c - 32;
                        else if (c >= 'A' && c <= 'Z') e->buf.buf[e->buf.pos] = c + 32;
                        e->buf.pos++;
                    }
                    e->vi_last_cmd = '~';
                }
                break;

            case 'u':
                if (e->undo_valid) {

                    char *tmp = strndup(e->buf.buf, e->buf.len);
                    size_t tlen = e->buf.len, tpos = e->buf.pos;

                    buf_set(&e->buf, e->undo_buf);
                    e->buf.pos = e->undo_pos < e->buf.len ? e->undo_pos : e->buf.len;

                    free(e->undo_buf);
                    e->undo_buf = tmp;
                    e->undo_len = tlen;
                    e->undo_pos = tpos;
                }
                break;

            case '.':
                if (e->vi_last_cmd) {
                    vi_save_undo(e);
                    switch (e->vi_last_cmd) {
                    case 'x':
                        for (int n = 0; n < count; n++) buf_delete_forward(&e->buf);
                        break;
                    case 's':
                        for (int n = 0; n < count; n++) buf_delete_forward(&e->buf);
                        e->vi_insert = true;
                        vi_set_cursor_bar();
                        break;
                    case 'D':
                        kill_to_end(e);
                        break;
                    case 'C':
                        kill_to_end(e);
                        e->vi_insert = true;
                        vi_set_cursor_bar();
                        break;
                    case 'S':
                        buf_clear(&e->buf);
                        e->vi_insert = true;
                        vi_set_cursor_bar();
                        break;
                    case '~':
                        if (e->buf.pos < e->buf.len) {
                            char c = e->buf.buf[e->buf.pos];
                            if (c >= 'a' && c <= 'z') e->buf.buf[e->buf.pos] = c - 32;
                            else if (c >= 'A' && c <= 'Z') e->buf.buf[e->buf.pos] = c + 32;
                            e->buf.pos++;
                        }
                        break;
                    case 'd':
                        switch (e->vi_last_cmd2) {
                        case 'd': buf_clear(&e->buf); break;
                        case 'w': kill_word_forward(e); break;
                        case 'b': kill_word_back(e); break;
                        case '$': kill_to_end(e); break;
                        case '0': kill_to_start(e); break;
                        }
                        break;
                    case 'c':
                        switch (e->vi_last_cmd2) {
                        case 'c': buf_clear(&e->buf); break;
                        case 'w': kill_word_forward(e); break;
                        case 'b': kill_word_back(e); break;
                        case '$': kill_to_end(e); break;
                        case '0': kill_to_start(e); break;
                        }
                        e->vi_insert = true;
                        vi_set_cursor_bar();
                        break;
                    case 'r':
                        if (e->vi_last_cmd2 >= 32 && e->buf.pos < e->buf.len)
                            e->buf.buf[e->buf.pos] = (char)e->vi_last_cmd2;
                        break;
                    }
                }
                break;

            case 'y': {
                int key2 = read_key();
                switch (key2) {
                case 'y':
                    kill_ring_save(e, e->buf.buf, e->buf.len);
                    break;
                case 'w': {
                    size_t old = e->buf.pos;
                    for (int n = 0; n < count; n++) cursor_word_right(&e->buf);
                    if (e->buf.pos > old)
                        kill_ring_save(e, e->buf.buf + old, e->buf.pos - old);
                    e->buf.pos = old;
                    break;
                }
                case 'e': {
                    size_t old = e->buf.pos;
                    for (int n = 0; n < count; n++) cursor_word_end(&e->buf);
                    if (e->buf.pos >= old) {
                        size_t end = e->buf.pos < e->buf.len ? e->buf.pos + 1 : e->buf.pos;
                        kill_ring_save(e, e->buf.buf + old, end - old);
                    }
                    e->buf.pos = old;
                    break;
                }
                case '$': {
                    if (e->buf.pos < e->buf.len)
                        kill_ring_save(e, e->buf.buf + e->buf.pos, e->buf.len - e->buf.pos);
                    break;
                }
                case '0': {
                    if (e->buf.pos > 0)
                        kill_ring_save(e, e->buf.buf, e->buf.pos);
                    break;
                }
                default:
                    break;
                }
                break;
            }

            case 'p':
                if (e->kill_ring && e->kill_ring_len > 0) {
                    vi_save_undo(e);
                    if (e->buf.pos < e->buf.len) cursor_right(&e->buf);
                    for (int n = 0; n < count; n++)
                        buf_insert(&e->buf, e->kill_ring, e->kill_ring_len);
                }
                break;

            case 'P':
                if (e->kill_ring && e->kill_ring_len > 0) {
                    vi_save_undo(e);
                    for (int n = 0; n < count; n++)
                        buf_insert(&e->buf, e->kill_ring, e->kill_ring_len);
                }
                break;

            case 'f': {
                int ch = read_key();
                if (ch >= 32) {
                    e->vi_last_find_cmd = 'f';
                    e->vi_last_find_ch = ch;
                    for (int n = 0; n < count; n++) {
                        for (size_t i = e->buf.pos + 1; i < e->buf.len; i++) {
                            if (e->buf.buf[i] == (char)ch) {
                                e->buf.pos = i;
                                break;
                            }
                        }
                    }
                }
                break;
            }

            case 'F': {
                int ch = read_key();
                if (ch >= 32) {
                    e->vi_last_find_cmd = 'F';
                    e->vi_last_find_ch = ch;
                    for (int n = 0; n < count; n++) {
                        if (e->buf.pos > 0) {
                            for (size_t i = e->buf.pos; i > 0; i--) {
                                if (e->buf.buf[i - 1] == (char)ch) {
                                    e->buf.pos = i - 1;
                                    break;
                                }
                            }
                        }
                    }
                }
                break;
            }

            case 't': {
                int ch = read_key();
                if (ch >= 32) {
                    e->vi_last_find_cmd = 't';
                    e->vi_last_find_ch = ch;
                    for (size_t i = e->buf.pos + 1; i < e->buf.len; i++) {
                        if (e->buf.buf[i] == (char)ch) {
                            e->buf.pos = i > 0 ? i - 1 : 0;
                            break;
                        }
                    }
                }
                break;
            }

            case 'T': {
                int ch = read_key();
                if (ch >= 32 && e->buf.pos > 0) {
                    e->vi_last_find_cmd = 'T';
                    e->vi_last_find_ch = ch;
                    for (size_t i = e->buf.pos; i > 0; i--) {
                        if (e->buf.buf[i - 1] == (char)ch) {
                            e->buf.pos = i;
                            break;
                        }
                    }
                }
                break;
            }

            case ';': {
                if (e->vi_last_find_ch) {
                    int ch = e->vi_last_find_ch;
                    for (int n = 0; n < count; n++) {
                        if (e->vi_last_find_cmd == 'f') {
                            for (size_t i = e->buf.pos + 1; i < e->buf.len; i++)
                                if (e->buf.buf[i] == (char)ch) { e->buf.pos = i; break; }
                        } else if (e->vi_last_find_cmd == 'F') {
                            for (size_t i = e->buf.pos; i > 0; i--)
                                if (e->buf.buf[i-1] == (char)ch) { e->buf.pos = i-1; break; }
                        } else if (e->vi_last_find_cmd == 't') {
                            for (size_t i = e->buf.pos + 1; i < e->buf.len; i++)
                                if (e->buf.buf[i] == (char)ch) { e->buf.pos = i > 0 ? i-1 : 0; break; }
                        } else if (e->vi_last_find_cmd == 'T') {
                            for (size_t i = e->buf.pos; i > 0; i--)
                                if (e->buf.buf[i-1] == (char)ch) { e->buf.pos = i; break; }
                        }
                    }
                }
                break;
            }

            case ',': {
                if (e->vi_last_find_ch) {
                    int ch = e->vi_last_find_ch;
                    for (int n = 0; n < count; n++) {
                        if (e->vi_last_find_cmd == 'f') {

                            for (size_t i = e->buf.pos; i > 0; i--)
                                if (e->buf.buf[i-1] == (char)ch) { e->buf.pos = i-1; break; }
                        } else if (e->vi_last_find_cmd == 'F') {
                            for (size_t i = e->buf.pos + 1; i < e->buf.len; i++)
                                if (e->buf.buf[i] == (char)ch) { e->buf.pos = i; break; }
                        } else if (e->vi_last_find_cmd == 't') {
                            for (size_t i = e->buf.pos; i > 0; i--)
                                if (e->buf.buf[i-1] == (char)ch) { e->buf.pos = i; break; }
                        } else if (e->vi_last_find_cmd == 'T') {
                            for (size_t i = e->buf.pos + 1; i < e->buf.len; i++)
                                if (e->buf.buf[i] == (char)ch) { e->buf.pos = i > 0 ? i-1 : 0; break; }
                        }
                    }
                }
                break;
            }

            case '/':
                if (e->history.count > 0) {
                    edit_disable_raw(e);
                    char **items = malloc(e->history.count * sizeof(char *));
                    for (size_t i = 0; i < e->history.count; i++)
                        items[i] = e->history.entries[e->history.count - 1 - i];
                    char *selected = filter_select(items, e->history.count);
                    free(items);
                    if (selected) {
                        buf_set(&e->buf, selected);
                        free(selected);
                    }
                    edit_enable_raw(e);
                    vi_set_cursor_block();
                }
                break;

            case KEY_CTRL_L:
                clear_screen();
                break;

            case KEY_ESC:

                break;

            default:
                break;
            }

            render(e);
            continue;
        }

        {
            bool handled = false;
            for (size_t bi = 0; bi < e->binding_count; bi++) {
                if (e->bindings[bi].key == key) {

                    edit_disable_raw(e);

                    setenv("VEX_LINE", e->buf.buf, 1);

                    free(e->saved_input);
                    e->saved_input = strdup(e->buf.buf);
                    e->saved_input_pos = e->buf.pos;

                    write(STDOUT_FILENO, "\n", 1);

                    free(e->buf.buf);
                    e->buf.buf = strdup(e->bindings[bi].command);
                    e->buf.len = strlen(e->buf.buf);
                    e->buf.cap = e->buf.len + 1;
                    e->buf.pos = e->buf.len;
                    if (e->vi_mode) vi_set_cursor_bar();
                    if (e->vi_mode) e->vi_insert = true;
                    return strdup(e->buf.buf);
                }
            }
            if (handled) { render(e); continue; }
        }

        switch (key) {
        case KEY_ENTER:
            abbr_expand_buf(&e->buf);
            if (e->vi_mode) vi_set_cursor_bar();
            /* Clear hint/preview before newline */
            write(STDOUT_FILENO, "\033[K\033[J", 6);
            edit_disable_raw(e);
            write(STDOUT_FILENO, "\n", 1);
            if (e->vi_mode) e->vi_insert = true;
            return strdup(e->buf.buf);

        case KEY_CTRL_D:
            if (e->buf.len == 0) {
                if (e->vi_mode) vi_set_cursor_bar();
                edit_disable_raw(e);
                return NULL;
            }
            buf_delete_forward(&e->buf);
            break;

        case KEY_CTRL_C:
            if (e->vi_mode) vi_set_cursor_bar();
            write(STDOUT_FILENO, "\033[K\033[J", 6);
            edit_disable_raw(e);
            write(STDOUT_FILENO, "^C\n", 3);
            if (e->vi_mode) e->vi_insert = true;
            return strdup("");

        case KEY_BACKSPACE:
        case KEY_CTRL_H:
            buf_delete_back(&e->buf);
            break;

        case KEY_DELETE:
            buf_delete_forward(&e->buf);
            break;

        case KEY_LEFT:
        case KEY_CTRL_B:
            cursor_left(&e->buf);
            break;

        case KEY_RIGHT:
        case KEY_CTRL_F:
            if (e->buf.pos >= e->buf.len) {

                const char *hint = find_history_hint(e);
                if (hint) {
                    buf_insert(&e->buf, hint, strlen(hint));
                }
            } else {
                cursor_right(&e->buf);
            }
            break;

        case KEY_UP:
        case KEY_CTRL_P:
            history_browse_up(e);
            break;

        case KEY_DOWN:
        case KEY_CTRL_N:
            history_browse_down(e);
            break;

        case KEY_HOME:
        case KEY_CTRL_A:
            cursor_home(&e->buf);
            break;

        case KEY_END:
        case KEY_CTRL_E:
            cursor_end(&e->buf);
            break;

        case KEY_CTRL_LEFT:
            cursor_word_left(&e->buf);
            break;

        case KEY_CTRL_RIGHT:
            if (e->buf.pos >= e->buf.len) {

                const char *hint = find_history_hint(e);
                if (hint) {
                    const char *p = hint;

                    while (*p == ' ' || *p == '\t') p++;

                    while (*p && *p != ' ' && *p != '\t') p++;
                    size_t word_len = (size_t)(p - hint);
                    if (word_len > 0) {
                        buf_insert(&e->buf, hint, word_len);
                    }
                }
            } else {
                cursor_word_right(&e->buf);
            }
            break;

        case KEY_CTRL_K:
            kill_to_end(e);
            break;

        case KEY_CTRL_U:
            kill_to_start(e);
            break;

        case KEY_CTRL_W:
            kill_word_back(e);
            break;

        case KEY_CTRL_Y:
            yank(e);
            break;

        case KEY_CTRL_T:
            swap_chars(&e->buf);
            break;

        case KEY_CTRL_L:
            clear_screen();
            break;

        case KEY_CTRL_R:
            if (e->history.count > 0) {
                reverse_search(e);
            }
            break;

        case KEY_CTRL_Z:

            edit_disable_raw(e);
            signal(SIGTSTP, SIG_DFL);
            raise(SIGTSTP);

            signal(SIGTSTP, SIG_IGN);
            edit_enable_raw(e);
            edit_get_term_size(e);
            break;

        case KEY_TAB:
            do_complete(e);
            break;

        case KEY_SHIFT_TAB:
            if (e->completing && e->comp_count > 1) {

                if (e->comp_idx == 0)
                    e->comp_idx = e->comp_count - 1;
                else
                    e->comp_idx--;

                const char *match = e->comp_matches[e->comp_idx];
                size_t match_len = strlen(match);
                size_t tail_start = e->comp_word_start + e->comp_word_len;
                size_t tail_len = e->buf.len > tail_start ? e->buf.len - tail_start : 0;
                size_t new_len = e->comp_word_start + match_len + tail_len;
                buf_grow(&e->buf, new_len);
                if (tail_len > 0) {
                    memmove(e->buf.buf + e->comp_word_start + match_len,
                            e->buf.buf + tail_start, tail_len);
                }
                memcpy(e->buf.buf + e->comp_word_start, match, match_len);
                e->buf.len = new_len;
                e->buf.pos = e->comp_word_start + match_len;
                e->buf.buf[e->buf.len] = '\0';
                e->comp_word_len = match_len;
            }
            break;

        case KEY_CTRL_X: {
            int next = read_key();
            if (next == KEY_CTRL_E) {

                edit_disable_raw(e);

                char tmppath[] = "/tmp/vex_edit_XXXXXX";
                int fd = mkstemp(tmppath);
                if (fd < 0) {
                    edit_enable_raw(e);
                    break;
                }

                if (e->buf.len > 0)
                    write(fd, e->buf.buf, e->buf.len);
                write(fd, "\n", 1);
                close(fd);

                const char *editor = getenv("VISUAL");
                if (!editor) editor = getenv("EDITOR");
                if (!editor) editor = "vi";

                char cmd[4352];
                snprintf(cmd, sizeof(cmd), "%s %s", editor, tmppath);
                int rc = system(cmd);

                if (rc == 0) {

                    FILE *f = fopen(tmppath, "r");
                    if (f) {
                        fseek(f, 0, SEEK_END);
                        long size = ftell(f);
                        fseek(f, 0, SEEK_SET);

                        if (size > 0) {
                            char *content = malloc((size_t)size + 1);
                            if (content) {
                                size_t nread = fread(content, 1, (size_t)size, f);
                                content[nread] = '\0';

                                while (nread > 0 && (content[nread-1] == '\n' || content[nread-1] == '\r'))
                                    content[--nread] = '\0';

                                buf_set(&e->buf, content);
                                free(content);
                            }
                        }
                        fclose(f);
                    }
                }

                unlink(tmppath);
                edit_enable_raw(e);
            }
            break;
        }

        case KEY_ESC:
            if (e->vi_mode) {

                e->vi_insert = false;
                vi_set_cursor_block();

                if (e->buf.pos > 0) cursor_left(&e->buf);
            }

            break;

        default:

            if (key >= 32) {
                char utf8_buf[4];
                if (key < 128) {
                    buf_insert_char(&e->buf, (char)key);
                } else {
                    int n = utf8_encode(utf8_buf, key);
                    if (n > 0) buf_insert(&e->buf, utf8_buf, (size_t)n);
                }
            }
            break;
        }

        render(e);
    }
}
