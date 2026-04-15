#ifndef VEX_EVAL_H
#define VEX_EVAL_H

typedef enum {
    FLOW_NONE,
    FLOW_BREAK,
    FLOW_CONTINUE,
    FLOW_RETURN,
} FlowSignal;

#define VEX_MAX_CALL_DEPTH 1000

/* Interpreter state threaded through all eval calls. */
struct EvalCtx {
    Scope *global;
    Scope *current;
    VexArena *arena;
    VexValue *pipeline_input;
    bool had_error;
    bool in_pipeline;
    int last_exit_code;
    FlowSignal flow;
    VexValue *flow_value;
    int call_depth;
};

EvalCtx  eval_ctx_new(void);
void     eval_ctx_free(EvalCtx *ctx);

VexValue *eval(EvalCtx *ctx, ASTNode *node);

VexValue *eval_pipeline(EvalCtx *ctx, ASTNode *node);

int exec_external(const char *name, char **argv, int in_fd, int out_fd);

char *find_in_path(const char *name);

int exec_external_bg(const char *name, char **argv, const char *cmd_str);

VexValue *eval_call_closure(EvalCtx *ctx, VexValue *closure,
                            VexValue **args, size_t argc);

VexValue *exec_external_capture(const char *name, char **argv, int in_fd);

void path_cache_clear(void);
size_t path_cache_list(const char ***names_out, const char ***paths_out);

#endif
