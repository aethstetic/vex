#include "vex.h"
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define SCORE_GAP_LEADING  -0.005
#define SCORE_GAP_TRAILING -0.005
#define SCORE_GAP_INNER    -0.01
#define SCORE_MATCH_CONSECUTIVE 1.0
#define SCORE_MATCH_SLASH   0.9
#define SCORE_MATCH_WORD    0.8
#define SCORE_MATCH_DOT     0.6
#define SCORE_MATCH_CAPITAL 0.7

static double char_bonus(char prev, char ch) {
    if (prev == '/' || prev == '\\') return SCORE_MATCH_SLASH;
    if (prev == '-' || prev == '_' || prev == ' ') return SCORE_MATCH_WORD;
    if (prev == '.') return SCORE_MATCH_DOT;
    if (prev >= 'a' && prev <= 'z' && ch >= 'A' && ch <= 'Z') return SCORE_MATCH_CAPITAL;
    return 0.0;
}

static char lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

double filter_score(const char *query, const char *candidate) {
    size_t qlen = strlen(query);
    size_t clen = strlen(candidate);

    if (qlen == 0) return 0.0;
    if (qlen > clen) return -1e9;

    {
        size_t qi = 0;
        for (size_t ci = 0; ci < clen && qi < qlen; ci++) {
            if (lower(candidate[ci]) == lower(query[qi])) qi++;
        }
        if (qi < qlen) return -1e9;
    }

    if (qlen > 128 || clen > 1024) return -1e9;

    static double D[128][1024];
    static double M[128][1024];

    for (size_t i = 0; i < qlen; i++) {
        double prev_score = -1e9;
        for (size_t j = 0; j < clen; j++) {
            double score = -1e9;
            if (lower(query[i]) == lower(candidate[j])) {
                double bonus = (j > 0) ? char_bonus(candidate[j-1], candidate[j]) : SCORE_MATCH_SLASH;
                if (i == 0) {
                    score = bonus + (double)j * SCORE_GAP_LEADING;
                } else if (j > 0) {
                    double m_prev = M[i-1][j-1];
                    double d_prev = D[i-1][j-1];
                    score = (m_prev > d_prev ? m_prev : d_prev) + bonus;

                    if (m_prev + SCORE_MATCH_CONSECUTIVE > score)
                        score = m_prev + SCORE_MATCH_CONSECUTIVE;
                }
            }
            M[i][j] = score;
            D[i][j] = (j > 0) ? ((prev_score + SCORE_GAP_INNER) > D[i][j-1] + SCORE_GAP_INNER ?
                         prev_score + SCORE_GAP_INNER : D[i][j-1] + SCORE_GAP_INNER) : -1e9;
            if (M[i][j] > D[i][j]) D[i][j] = M[i][j];
            prev_score = D[i][j];
        }
    }

    double best = -1e9;
    for (size_t j = 0; j < clen; j++) {
        double s = D[qlen-1][j] + (double)(clen - j - 1) * SCORE_GAP_TRAILING;
        if (s > best) best = s;
    }
    return best;
}

typedef struct {
    char **items;
    size_t count;
    double *scores;
    size_t *sorted;
    size_t n_matches;
    char query[512];
    size_t query_len;
    size_t cursor;
    int term_rows;
    int term_cols;
    bool multi;
    bool *selected;
} FilterState;

static void filter_get_term_size(FilterState *f) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        f->term_cols = ws.ws_col;
        f->term_rows = ws.ws_row;
    } else {
        f->term_cols = 80;
        f->term_rows = 24;
    }
}

static void sort_indices(size_t *arr, size_t n, double *scores) {
    for (size_t i = 1; i < n; i++) {
        size_t key = arr[i];
        double ks = scores[key];
        size_t j = i;
        while (j > 0 && scores[arr[j-1]] < ks) {
            arr[j] = arr[j-1];
            j--;
        }
        arr[j] = key;
    }
}

static void filter_update_matches(FilterState *f) {
    f->n_matches = 0;
    if (f->query_len == 0) {

        for (size_t i = 0; i < f->count; i++) {
            f->scores[i] = 0.0;
            f->sorted[f->n_matches++] = i;
        }
    } else {
        for (size_t i = 0; i < f->count; i++) {
            double s = filter_score(f->query, f->items[i]);
            f->scores[i] = s;
            if (s > -1e8) {
                f->sorted[f->n_matches++] = i;
            }
        }
        sort_indices(f->sorted, f->n_matches, f->scores);
    }
    if (f->cursor >= f->n_matches && f->n_matches > 0)
        f->cursor = f->n_matches - 1;
}

static void filter_render(FilterState *f) {
    VexStr out = vstr_empty();

    vstr_append_cstr(&out, "\033[H");

    vstr_append_cstr(&out, "\033[1m> \033[0m");
    vstr_append(&out, f->query, f->query_len);
    vstr_append_cstr(&out, "\033[K\n");

    char info[64];
    snprintf(info, sizeof(info), "  %zu/%zu\033[K\n", f->n_matches, f->count);
    vstr_append_cstr(&out, info);

    size_t max_visible = (size_t)(f->term_rows - 3);
    size_t start = 0;
    if (f->cursor >= max_visible) start = f->cursor - max_visible + 1;

    for (size_t i = 0; i < max_visible; i++) {
        size_t idx = start + i;
        if (idx < f->n_matches) {
            size_t item_idx = f->sorted[idx];
            bool is_sel = (idx == f->cursor);
            bool is_marked = f->multi && f->selected[item_idx];

            if (is_sel)
                vstr_append_cstr(&out, "\033[7m");
            if (is_marked)
                vstr_append_cstr(&out, "\033[32m* \033[0m");
            else
                vstr_append_cstr(&out, "  ");

            const char *item = f->items[item_idx];
            size_t ilen = strlen(item);
            size_t max_w = (size_t)(f->term_cols - 3);
            if (ilen > max_w) ilen = max_w;
            vstr_append(&out, item, ilen);

            if (is_sel)
                vstr_append_cstr(&out, "\033[0m");
        }
        vstr_append_cstr(&out, "\033[K\n");
    }

    char move[32];
    snprintf(move, sizeof(move), "\033[1;%zuH", f->query_len + 3);
    vstr_append_cstr(&out, move);

    write(STDOUT_FILENO, vstr_data(&out), vstr_len(&out));
    vstr_free(&out);
}

static int filter_read_key(void) {
    char c;
    if (read(STDIN_FILENO, &c, 1) != 1) return -1;

    if (c == '\033') {
        char seq[3];
        if (read(STDIN_FILENO, seq, 1) != 1) return 27;
        if (read(STDIN_FILENO, seq + 1, 1) != 1) return 27;
        if (seq[0] == '[') {
            switch (seq[1]) {
            case 'A': return 1000;
            case 'B': return 1001;
            }
        }
        return 27;
    }
    return (unsigned char)c;
}

int filter_run(char **items, size_t count, bool multi, bool *selected_out) {
    if (count == 0) return -1;

    write(STDOUT_FILENO, "\033[?1049h", 8);
    write(STDOUT_FILENO, "\033[?25h", 6);

    struct termios orig, raw;
    if (tcgetattr(STDIN_FILENO, &orig) == -1) {
        write(STDOUT_FILENO, "\033[?1049l", 8);
        return -1;
    }
    raw = orig;
    raw.c_iflag &= ~(unsigned)(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_oflag &= ~(unsigned)(OPOST);
    raw.c_cflag |= (unsigned)(CS8);
    raw.c_lflag &= ~(unsigned)(ECHO | ICANON | IEXTEN | ISIG);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);

    struct termios out_mode;
    tcgetattr(STDOUT_FILENO, &out_mode);
    out_mode.c_oflag |= (unsigned)OPOST;
    tcsetattr(STDOUT_FILENO, TCSAFLUSH, &out_mode);

    FilterState f = {0};
    f.items = items;
    f.count = count;
    f.multi = multi;
    f.scores = malloc(count * sizeof(double));
    f.sorted = malloc(count * sizeof(size_t));
    if (multi) {
        f.selected = calloc(count, sizeof(bool));
    }
    filter_get_term_size(&f);
    filter_update_matches(&f);
    filter_render(&f);

    int result = -1;

    for (;;) {
        int key = filter_read_key();
        if (key == -1) break;

        switch (key) {
        case 13:
            if (multi) {

                if (selected_out) memcpy(selected_out, f.selected, count * sizeof(bool));

                if (selected_out && f.n_matches > 0) {
                    bool any = false;
                    for (size_t i = 0; i < count; i++) {
                        if (selected_out[i]) { any = true; break; }
                    }
                    if (!any) selected_out[f.sorted[f.cursor]] = true;
                }
                result = 0;
            } else {
                result = (f.n_matches > 0) ? (int)f.sorted[f.cursor] : -1;
            }
            goto done;

        case 27:
        case 3:
            result = -1;
            goto done;

        case 1000:
        case 16:
            if (f.cursor > 0) f.cursor--;
            break;

        case 1001:
        case 14:
            if (f.cursor + 1 < f.n_matches) f.cursor++;
            break;

        case 9:
            if (multi && f.n_matches > 0) {
                size_t idx = f.sorted[f.cursor];
                f.selected[idx] = !f.selected[idx];
                if (f.cursor + 1 < f.n_matches) f.cursor++;
            }
            break;

        case 127:
        case 8:
            if (f.query_len > 0) {
                f.query_len--;
                f.query[f.query_len] = '\0';
                f.cursor = 0;
                filter_update_matches(&f);
            }
            break;

        case 21:
            f.query_len = 0;
            f.query[0] = '\0';
            f.cursor = 0;
            filter_update_matches(&f);
            break;

        default:
            if (key >= 32 && key < 127 && f.query_len < sizeof(f.query) - 1) {
                f.query[f.query_len++] = (char)key;
                f.query[f.query_len] = '\0';
                f.cursor = 0;
                filter_update_matches(&f);
            }
            break;
        }

        filter_render(&f);
    }

done:
    free(f.scores);
    free(f.sorted);
    free(f.selected);

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig);
    write(STDOUT_FILENO, "\033[?1049l", 8);

    return result;
}

char *filter_select(char **items, size_t count) {
    int idx = filter_run(items, count, false, NULL);
    if (idx >= 0 && (size_t)idx < count)
        return strdup(items[idx]);
    return NULL;
}
