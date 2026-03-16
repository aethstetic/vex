# vex                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                             
  What is vex?                                                                                                                                                                                                                               
  >vex is a modern shell with structured data pipelines, typed values, and 400+ builtins — written in C.                                                                                                                                     
                                                                                                                                                                                                                                             
  # Installation
  ```
  git clone https://github.com/aethstetic/vex.git 
  cd vex
  make
  sudo make install
  ```
  To use as your login shell:
  ```
  echo /usr/local/bin/vex | sudo tee -a /etc/shells
  chsh -s /usr/local/bin/vex
  ```
  
 # Features
 -  The current features of vex are:
 -  Typed values: strings, integers, floats, booleans, lists, records, closures, ranges
 -  Dual pipelines: | for structured data, |> for raw bytes
 -  400+ builtin commands covering data, strings, math, networking, dates, files
 -  Built-in format parsers for JSON, CSV, TSV, YAML, TOML, XML, INI
 -  First-class closures with lexical scoping
 -  try/catch error handling and ? propagation operator
 -  Pattern matching via match statements
 -  Emacs and Vi line editing modes with tab completion and autosuggestions
 -  Prompt customization with git integration and built-in themes
 -  Shell hooks: preexec, precmd, chpwd
 -  Full job control with fg/bg/jobs/disown
 -  C plugin system via shared libraries
 -  Package manager for community plugins

  # Information

  On first launch vex creates `~/.config/vex/config.vex` with a starter configuration.

  All configuration lives under `~/.config/vex/` and data under `~/.local/share/vex/`.

  vex also supports a few environment variables for customization:
  ```
  `export VEX_PROMPT "%{bold,blue}%D%{reset} %{green}%g%{reset} %# "`
  `export VEX_EDIT_MODE "vi"`
  `export VEX_HISTSIZE "5000"`
  ```
  ### Writing a plugin

  Plugins implement a `vex_plugin_init` function that receives a `VexPluginAPI` pointer. There's no header to include — you redeclare the API struct in your plugin to match the layout Vex expects:

  ```
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

  Building a plugin

  cc -shared -fPIC -o hello_plugin.so hello_plugin.c

  Loading a plugin

  In your config or interactively:

  use plugin "path/to/hello_plugin.so"

  For auto-loading, place the .so in ~/.local/share/vex/plugins/my_plugin/ with an init.vex that loads it:

  use plugin "hello_plugin.so"

  ### Script-level commands

  You can also extend Vex without C using def-cmd:

  def-cmd "greet" "greet <name>" "Say hello" { |input, name|
      "Hello, " + $name + "!"
  }

  Package manager
  ```
  pkg install https://github.com/user/vex-plugin.git
  pkg list
  pkg update plugin-name
  pkg remove plugin-name
  ```
