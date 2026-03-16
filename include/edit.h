#ifndef VEX_EDIT_H
#define VEX_EDIT_H

#define VEX_EDIT_HISTORY_MAX 1000
#define VEX_EDIT_BUF_INIT    256

enum {
    KEY_NULL    = 0,
    KEY_CTRL_A  = 1,
    KEY_CTRL_B  = 2,
    KEY_CTRL_C  = 3,
    KEY_CTRL_D  = 4,
    KEY_CTRL_E  = 5,
    KEY_CTRL_F  = 6,
    KEY_CTRL_G  = 7,
    KEY_CTRL_H  = 8,
    KEY_TAB     = 9,
    KEY_CTRL_K  = 11,
    KEY_CTRL_L  = 12,
    KEY_ENTER   = 13,
    KEY_CTRL_N  = 14,
    KEY_CTRL_P  = 16,
    KEY_CTRL_R  = 18,
    KEY_CTRL_S  = 19,
    KEY_CTRL_T  = 20,
    KEY_CTRL_U  = 21,
    KEY_CTRL_W  = 23,
    KEY_CTRL_X  = 24,
    KEY_CTRL_Y  = 25,
    KEY_CTRL_Z  = 26,
    KEY_ESC     = 27,
    KEY_BACKSPACE = 127,

    KEY_UP      = 1000,
    KEY_DOWN,
    KEY_RIGHT,
    KEY_LEFT,
    KEY_HOME,
    KEY_END,
    KEY_DELETE,
    KEY_PAGE_UP,
    KEY_PAGE_DOWN,
    KEY_SHIFT_TAB,
    KEY_CTRL_LEFT,
    KEY_CTRL_RIGHT,
    KEY_PASTE_START,
    KEY_PASTE_END,
};

/* Gap-less editing buffer for one input line. */
typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    size_t pos;
} EditBuf;

typedef struct {
    char **entries;
    size_t count;
    size_t cap;
    size_t browse_pos;
    char *saved_line;
} EditHistory;

/* Full line-editor state: buffer, history, completion, vi mode, etc. */
typedef struct {
    EditBuf buf;
    EditHistory history;

    int term_cols;
    int term_rows;
    bool raw_mode;

    char *hint;
    bool hint_active;

    char *prompt;
    size_t prompt_width;

    size_t old_row_count;

    bool completing;
    size_t comp_idx;
    char **comp_matches;
    char **comp_descs;
    size_t comp_count;
    size_t comp_word_start;
    size_t comp_word_len;
    size_t comp_menu_rows;

    bool in_paste;

    bool vi_mode;
    bool vi_insert;
    int vi_repeat;
    int vi_last_find_ch;
    int vi_last_find_cmd;
    int vi_last_cmd;
    int vi_last_cmd2;

    char *rprompt;
    size_t rprompt_width;

    bool searching;
    char search_query[256];
    size_t search_len;
    ssize_t search_match_idx;
    size_t search_match_pos;

    char *kill_ring;
    size_t kill_ring_len;

    char *undo_buf;
    size_t undo_len;
    size_t undo_pos;
    bool undo_valid;

    struct {
        int key;
        char *command;
    } bindings[32];
    size_t binding_count;

    char *saved_input;
    size_t saved_input_pos;

    char **paste_queue;
    size_t paste_queue_count;
    size_t paste_queue_cap;
} EditState;

void edit_init(EditState *e);
void edit_free(EditState *e);

char *edit_readline(EditState *e, const char *prompt);

void edit_history_add(EditState *e, const char *line);
void edit_history_load(EditState *e, const char *path);
void edit_history_save(EditState *e, const char *path);

bool edit_enable_raw(EditState *e);
void edit_disable_raw(EditState *e);

void edit_get_term_size(EditState *e);

#endif
