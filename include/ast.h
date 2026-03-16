#ifndef VEX_AST_H
#define VEX_AST_H

/* Discriminator for every AST node variant. */
typedef enum {
    AST_LITERAL,
    AST_IDENT,
    AST_UNARY,
    AST_BINARY,
    AST_PIPELINE,
    AST_BYTE_PIPELINE,
    AST_CALL,
    AST_EXTERNAL_CALL,
    AST_LET,
    AST_MUT,
    AST_ASSIGN,
    AST_IF,
    AST_FOR,
    AST_WHILE,
    AST_LOOP,
    AST_BREAK,
    AST_CONTINUE,
    AST_RETURN,
    AST_FN,
    AST_CLOSURE,
    AST_BLOCK,
    AST_LIST,
    AST_RECORD,
    AST_FIELD_ACCESS,
    AST_INDEX,
    AST_TRY_CATCH,
    AST_ERROR_PROPAGATE,
    AST_STRING_INTERP,
    AST_MATCH,
    AST_RANGE,
    AST_SPREAD,
    AST_USE,
    AST_FLAG,
    AST_BACKGROUND,
    AST_COND_CHAIN,
    AST_CMD_SUBST,
    AST_PROC_SUBST,
    AST_SUBSHELL,
    AST_PARAM_EXPAND,
} ASTKind;

enum {
    PEXP_DEFAULT    = 0,
    PEXP_ASSIGN     = 1,
    PEXP_ERROR      = 2,
    PEXP_ALTVAL     = 3,
    PEXP_TRIM_L     = 4,
    PEXP_TRIM_LL    = 5,
    PEXP_TRIM_R     = 6,
    PEXP_TRIM_RR    = 7,
    PEXP_REPLACE    = 8,
    PEXP_REPLACE_ALL= 9,
    PEXP_LENGTH     = 10,
    PEXP_UPPER      = 11,
    PEXP_LOWER      = 12,
    PEXP_SLICE      = 13,
};

typedef struct {
    char *stdout_file;
    char *stdin_file;
    char *stderr_file;
    char *stdin_string;
    bool stdout_append;
    bool stderr_append;
    bool stderr_to_stdout;
} Redirect;

typedef struct {
    char *name;
    char *type_hint;
    ASTNode *default_val;
    bool is_rest;
} Param;

/* Tagged union representing a single node in the syntax tree. */
struct ASTNode {
    ASTKind kind;
    Token token;
    union {

        VexValue *literal;

        char *name;

        struct { TokenType op; ASTNode *operand; } unary;

        struct { TokenType op; ASTNode *left; ASTNode *right; } binary;

        struct { ASTNode **stages; size_t count; } pipeline;

        struct {
            char *cmd_name;
            ASTNode **args;
            size_t arg_count;
            Redirect redir;
        } call;

        struct { char *var_name; char *type_hint; ASTNode *init; } binding;

        struct { ASTNode *target; ASTNode *value; } assign;

        struct { ASTNode *cond; ASTNode *then_block; ASTNode *else_block; } if_stmt;

        struct { char *var_name; ASTNode *iter; ASTNode *body; } for_stmt;

        struct { ASTNode *cond; ASTNode *body; } loop_stmt;

        struct {
            char *fn_name;
            Param *params;
            size_t param_count;
            char *return_type;
            ASTNode *body;
        } fn;

        struct {
            Param *params;
            size_t param_count;
            ASTNode *body;
        } closure;

        struct { ASTNode **stmts; size_t count; } block;

        struct { ASTNode **items; size_t count; } list;

        struct {
            char **keys;
            ASTNode **values;
            size_t count;
        } record;

        struct { ASTNode *object; char *field; } field;

        struct { ASTNode *object; ASTNode *index; } index_expr;

        struct {
            ASTNode *try_block;
            char *catch_var;
            ASTNode *catch_block;
        } try_catch;

        ASTNode *propagate_expr;

        struct { ASTNode **parts; size_t count; } interp;

        ASTNode *ret_val;

        struct { ASTNode *start; ASTNode *end; bool exclusive; } range;

        ASTNode *spread_expr;

        struct { char *path; bool is_plugin; } use_stmt;

        ASTNode *bg_stmt;

        struct {
            ASTNode **cmds;
            TokenType *ops;
            size_t cmd_count;
        } cond_chain;

        ASTNode *subst_cmd;

        struct {
            char *var_name;
            int expand_op;
            char *operand;
        } param_expand;
    };
};

ASTNode *ast_alloc(VexArena *arena, ASTKind kind, Token tok);
void     ast_print(ASTNode *node, int indent);

#endif
