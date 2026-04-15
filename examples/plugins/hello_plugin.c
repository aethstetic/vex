/*
 * Example Vex Plugin: hello
 *
 * Build: cc -shared -fPIC -o hello_plugin.so hello_plugin.c
 * Usage: use plugin "hello_plugin.so"
 *        hello "world"     => "Hello, world!"
 *        greet             => {greeting: "Hello from plugin!", version: 1}
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

/* Forward declarations — matches vex's VexValue */
typedef struct VexValue VexValue;

/* Plugin command function signature */
typedef VexValue *(*VexPluginCommandFn)(void *api_ptr, VexValue *input,
                                        VexValue **args, size_t argc);

/* The API struct — must match vex's VexPluginAPI layout */
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

/* ---- Plugin commands ---- */

static VexValue *cmd_hello(void *api_ptr, VexValue *input, VexValue **args, size_t argc) {
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

static VexValue *cmd_greet(void *api_ptr, VexValue *input, VexValue **args, size_t argc) {
    VexPluginAPI *api = api_ptr;
    (void)input; (void)args; (void)argc;

    VexValue *rec = api->new_record();
    VexValue *msg = api->new_string("Hello from plugin!", 18);
    VexValue *ver = api->new_int(1);

    api->record_set(rec, "greeting", msg);
    api->record_set(rec, "version", ver);

    api->release(msg);
    api->release(ver);

    return rec;
}

/* ---- Plugin entry point ---- */

uint32_t vex_plugin_api_version = 5;

void vex_plugin_init(VexPluginAPI *api) {
    api->log("hello plugin loaded (API v%d)", api->api_version);

    api->register_command("hello", cmd_hello,
                          "hello [name]", "Say hello");
    api->register_command("greet", cmd_greet,
                          "greet", "Return a greeting record");
}
