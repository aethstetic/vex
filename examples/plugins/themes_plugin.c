#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct VexValue VexValue;

typedef VexValue *(*VexPluginCommandFn)(void *api_ptr, VexValue *input,
                                        VexValue **args, size_t argc);

typedef struct {
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

    void (*register_completion)(const char *cmd, const char *const *words);
    void (*eval_string)(void *ctx, const char *code);

    void (*register_prompt)(VexPluginCommandFn fn);
    void (*register_rprompt)(VexPluginCommandFn fn);
    VexValue *(*get_shell_state)(void);

    VexValue *(*new_string_cstr)(const char *s);
    VexValue *(*record_keys)(VexValue *rec);
    bool      (*list_remove)(VexValue *list, size_t i);
    bool      (*record_remove)(VexValue *rec, const char *key);
    const char *(*get_env)(const char *name);
    void      (*set_env)(const char *name, const char *value);
    void      (*register_hook)(const char *event, VexPluginCommandFn fn);
} VexPluginAPI;

typedef struct {
    const char *name;
    const char *keyword;
    const char *builtin;
    const char *string;
    const char *number;
    const char *operator_;
    const char *comment;
    const char *variable;
    const char *error;
    const char *pipe;
    const char *bool_;
} Theme;

static Theme themes[] = {
    {
        .name      = "catppuccin",
        .keyword   = "#cba6f7",
        .builtin   = "#89b4fa",
        .string    = "#a6e3a1",
        .number    = "#f9e2af",
        .operator_ = "#9399b2",
        .comment   = "#6c7086",
        .variable  = "#89dceb",
        .error     = "#f38ba8",
        .pipe      = "#74c7ec",
        .bool_     = "#fab387",
    },
    {
        .name      = "gruvbox",
        .keyword   = "#fb4934",
        .builtin   = "#83a598",
        .string    = "#b8bb26",
        .number    = "#d3869b",
        .operator_ = "#d5c4a1",
        .comment   = "#928374",
        .variable  = "#8ec07c",
        .error     = "#fb4934",
        .pipe      = "#83a598",
        .bool_     = "#fabd2f",
    },
    {
        .name      = "tokyonight",
        .keyword   = "#bb9af7",
        .builtin   = "#7aa2f7",
        .string    = "#9ece6a",
        .number    = "#ff9e64",
        .operator_ = "#89ddff",
        .comment   = "#565f89",
        .variable  = "#73daca",
        .error     = "#f7768e",
        .pipe      = "#7dcfff",
        .bool_     = "#ff9e64",
    },
    {
        .name      = "dracula",
        .keyword   = "#ff79c6",
        .builtin   = "#8be9fd",
        .string    = "#f1fa8c",
        .number    = "#bd93f9",
        .operator_ = "#f8f8f2",
        .comment   = "#6272a4",
        .variable  = "#50fa7b",
        .error     = "#ff5555",
        .pipe      = "#8be9fd",
        .bool_     = "#bd93f9",
    },
    {
        .name      = "nord",
        .keyword   = "#81a1c1",
        .builtin   = "#88c0d0",
        .string    = "#a3be8c",
        .number    = "#b48ead",
        .operator_ = "#d8dee9",
        .comment   = "#616e88",
        .variable  = "#8fbcbb",
        .error     = "#bf616a",
        .pipe      = "#81a1c1",
        .bool_     = "#d08770",
    },
    {
        .name      = "solarized",
        .keyword   = "#b58900",
        .builtin   = "#268bd2",
        .string    = "#2aa198",
        .number    = "#d33682",
        .operator_ = "#839496",
        .comment   = "#586e75",
        .variable  = "#6c71c4",
        .error     = "#dc322f",
        .pipe      = "#268bd2",
        .bool_     = "#cb4b16",
    },
    {
        .name      = "rosepine",
        .keyword   = "#c4a7e7",
        .builtin   = "#9ccfd8",
        .string    = "#f6c177",
        .number    = "#ea9a97",
        .operator_ = "#908caa",
        .comment   = "#6e6a86",
        .variable  = "#9ccfd8",
        .error     = "#eb6f92",
        .pipe      = "#c4a7e7",
        .bool_     = "#f6c177",
    },
    { .name = NULL }
};

static VexPluginAPI *g_api = NULL;

static VexValue *cmd_theme_list(void *api_ptr, VexValue *input,
                                VexValue **args, size_t argc) {
    VexPluginAPI *api = api_ptr;
    (void)input; (void)args; (void)argc;

    VexValue *list = api->new_list();
    for (int i = 0; themes[i].name; i++) {
        VexValue *rec = api->new_record();
        VexValue *name = api->new_string_cstr(themes[i].name);

        char preview[256];
        snprintf(preview, sizeof(preview),
                 "\033[38;2;%s\033[0mkey \033[38;2;%s\033[0mstr \033[38;2;%s\033[0mnum \033[38;2;%s\033[0mvar",
                 themes[i].keyword + 1,
                 themes[i].string + 1,
                 themes[i].number + 1,
                 themes[i].variable + 1);

        api->record_set(rec, "name", name);
        api->release(name);
        api->list_push(list, rec);
        api->release(rec);
    }

    printf("Available themes:\n");
    for (int i = 0; themes[i].name; i++) {
        printf("  %-14s", themes[i].name);

        unsigned int r, g, b;
        sscanf(themes[i].keyword + 1, "%02x%02x%02x", &r, &g, &b);
        printf(" \033[38;2;%d;%d;%dmbool\033[0m", r, g, b);

        sscanf(themes[i].string + 1, "%02x%02x%02x", &r, &g, &b);
        printf(" \033[38;2;%d;%d;%dm\"string\"\033[0m", r, g, b);

        sscanf(themes[i].number + 1, "%02x%02x%02x", &r, &g, &b);
        printf(" \033[38;2;%d;%d;%dm42\033[0m", r, g, b);

        sscanf(themes[i].variable + 1, "%02x%02x%02x", &r, &g, &b);
        printf(" \033[38;2;%d;%d;%dm$var\033[0m", r, g, b);

        sscanf(themes[i].comment + 1, "%02x%02x%02x", &r, &g, &b);
        printf(" \033[38;2;%d;%d;%dm# comment\033[0m", r, g, b);

        printf("\n");
    }

    return list;
}

static VexValue *cmd_theme_apply(void *api_ptr, VexValue *input,
                                 VexValue **args, size_t argc) {
    VexPluginAPI *api = api_ptr;
    (void)input;

    if (argc == 0)
        return api->new_error("theme-apply: expected theme name");

    size_t name_len;
    const char *name = api->get_string(args[0], &name_len);

    Theme *found = NULL;
    for (int i = 0; themes[i].name; i++) {
        if (strcmp(themes[i].name, name) == 0) {
            found = &themes[i];
            break;
        }
    }

    if (!found) {
        char msg[128];
        snprintf(msg, sizeof(msg), "theme-apply: unknown theme '%s'", name);
        return api->new_error(msg);
    }

    api->set_env("VEX_COLOR_KEYWORD", found->keyword);
    api->set_env("VEX_COLOR_BUILTIN", found->builtin);
    api->set_env("VEX_COLOR_STRING", found->string);
    api->set_env("VEX_COLOR_NUMBER", found->number);
    api->set_env("VEX_COLOR_OPERATOR", found->operator_);
    api->set_env("VEX_COLOR_COMMENT", found->comment);
    api->set_env("VEX_COLOR_VARIABLE", found->variable);
    api->set_env("VEX_COLOR_ERROR", found->error);
    api->set_env("VEX_COLOR_PIPE", found->pipe);
    api->set_env("VEX_COLOR_BOOL", found->bool_);

    printf("Applied theme: %s\n", found->name);
    printf("Add to ~/.config/vex/config.vex to persist:\n");
    printf("  export VEX_COLOR_KEYWORD \"%s\"\n", found->keyword);
    printf("  export VEX_COLOR_BUILTIN \"%s\"\n", found->builtin);
    printf("  export VEX_COLOR_STRING \"%s\"\n", found->string);
    printf("  export VEX_COLOR_NUMBER \"%s\"\n", found->number);
    printf("  export VEX_COLOR_OPERATOR \"%s\"\n", found->operator_);
    printf("  export VEX_COLOR_COMMENT \"%s\"\n", found->comment);
    printf("  export VEX_COLOR_VARIABLE \"%s\"\n", found->variable);
    printf("  export VEX_COLOR_ERROR \"%s\"\n", found->error);
    printf("  export VEX_COLOR_PIPE \"%s\"\n", found->pipe);
    printf("  export VEX_COLOR_BOOL \"%s\"\n", found->bool_);

    return api->new_null();
}

static const char *theme_names[] = {
    "catppuccin", "gruvbox", "tokyonight", "dracula",
    "nord", "solarized", "rosepine", NULL
};

uint32_t vex_plugin_api_version = 5;

void vex_plugin_init(VexPluginAPI *api) {
    g_api = api;
    api->register_command("theme-list", cmd_theme_list,
                          "theme-list", "List available color themes");
    api->register_command("theme-apply", cmd_theme_apply,
                          "theme-apply <name>", "Apply a color theme");
    api->register_completion("theme-apply", theme_names);
}
