# vex

> vex is a modern shell with structured data pipelines, typed values, and 400+ builtins — written in C.

# Installation

**From source:**
```
git clone https://github.com/aethstetic/vex.git
cd vex
make
sudo make install
```

**Arch Linux (AUR):**
```
yay -S vex-shell-git
paru -S vex-shell-git
```

**Nix/NixOS:**
```
nix run github:aethstetic/vex
nix profile install github:aethstetic/vex
```

**Set as login shell:**
```
echo /usr/local/bin/vex | sudo tee -a /etc/shells
chsh -s /usr/local/bin/vex
```

# Features

- Typed values: strings, integers, floats, booleans, lists, records, closures, ranges
- Dual pipelines: `|` for structured data, `|>` for raw bytes
- 400+ builtin commands covering data, strings, math, networking, dates, files
- Built-in format parsers for JSON, CSV, TSV, YAML, TOML, XML, INI
- First-class closures with lexical scoping
- try/catch error handling and `?` propagation operator
- Pattern matching via match statements
- Emacs and Vi line editing modes with tab completion and autosuggestions
- Auto-generated flag completions from `--help` output
- Inline command preview for destructive commands (rm, mv, cp)
- Command undo system (rm moves to trash, undo restores)
- Syntax highlighting with configurable hex colors
- Smart cd with frecency-based directory jumping
- Prompt customization with git integration
- Config auto-reload on save
- Shell hooks: preexec, precmd, chpwd
- Full job control with fg/bg/jobs/disown
- C plugin system (API v5) via shared libraries
- OSC 133 shell integration for modern terminals
- POSIX script bridge (auto-detects and delegates .sh scripts)
- macOS support

# Configuration

On first launch vex creates `~/.config/vex/config.vex` with a starter configuration.

**File locations:**
```
~/.config/vex/config.vex       # main config (auto-reloads on save)
~/.config/vex/history           # command history
~/.config/vex/plugins/          # plugin autoload directory
~/.config/vex/themes/           # user themes
~/.local/share/vex/trash/       # undo trash (for rm)
```

**Environment variables:**
```
export VEX_PROMPT "%{bold,blue}%D%{reset} %{green}%g%{reset} %# "
export VEX_EDIT_MODE "vi"
export VEX_HISTSIZE "5000"
```

**Syntax colors (ANSI codes, hex #rrggbb, or 256-color):**
```
export VEX_COLOR_BUILTIN "#89b4fa"
export VEX_COLOR_COMMAND "#a6e3a1"
export VEX_COLOR_STRING "#a6e3a1"
export VEX_COLOR_KEYWORD "#cba6f7"
export VEX_COLOR_NUMBER "#f9e2af"
export VEX_COLOR_ERROR "#f38ba8"
export VEX_COLOR_VARIABLE "#89dceb"
export VEX_COLOR_COMMENT "#6c7086"
```

**Aliases:**
```
alias ll = ls -la
alias update = paru -Syu --noconfirm && fastfetch
alias g = git
```

# Undo

vex tracks destructive file operations. `rm` moves files to trash instead of deleting:
```
rm important.txt
undo                    # restores important.txt
undo-list               # shows recent undoable operations
```

# Plugins

Plugins are C shared libraries that extend vex with new commands.

**Autoloading:** Place plugins in `~/.config/vex/plugins/` as subdirectories with an `init.vex`:
```
~/.config/vex/plugins/myplugin/init.vex
```

**Loading manually:**
```
use plugin "path/to/plugin.so"
```

**Building:**
```
cc -shared -fPIC -o plugin.so plugin.c
```

**Plugin API (v5):**

Plugins implement a `vex_plugin_init` function receiving a `VexPluginAPI` pointer:

```c
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

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

    VexValue *(*run_command)(void *ctx, const char *cmd);
    const char *(*get_cwd)(void);
    bool      (*set_cwd)(const char *path);
    size_t    (*record_len)(VexValue *rec);
    VexValue *(*to_string)(VexValue *v);
    void      (*register_alias)(const char *name, const char *expansion);
} VexPluginAPI;

static VexValue *cmd_hello(void *api_ptr, VexValue *input,
                           VexValue **args, size_t argc) {
    VexPluginAPI *api = api_ptr;
    (void)input;

    const char *name = "world";
    size_t name_len = 5;
    if (argc > 0) {
        name = api->get_string(args[0], &name_len);
    }

    char buf[256];
    int n = snprintf(buf, sizeof(buf), "Hello, %s!", name);
    return api->new_string(buf, (size_t)n);
}

void vex_plugin_init(VexPluginAPI *api) {
    api->register_command("hello", cmd_hello, "hello [name]", "Say hello");
}
```

**Script-level commands:**
```
def-cmd "greet" "greet <name>" "Say hello" { |input, name|
    "Hello, " + $name + "!"
}
```

**Example themes plugin included at `examples/plugins/themes_plugin.c` with 7 color schemes:**
catppuccin, gruvbox, tokyonight, dracula, nord, solarized, rosepine.

**Package manager:**
```
pkg install https://github.com/user/vex-plugin.git
pkg list
pkg update plugin-name
pkg remove plugin-name
```
