#include "vex.h"

static ASTNode *parse_expression(Parser *p);
static ASTNode *parse_statement(Parser *p);
static ASTNode *parse_command(Parser *p);
static ASTNode *parse_pipeline(Parser *p);
static ASTNode *parse_primary(Parser *p);
static ASTNode *parse_binary(Parser *p, int min_prec);
static ASTNode *parse_block(Parser *p);
static ASTNode *parse_external_arg(Parser *p);
static ASTNode *parse_match(Parser *p);
static ASTNode *parse_try(Parser *p);
static void parse_redirects(Parser *p, Redirect *r);
static ASTNode *parse_cond_chain(Parser *p);
static ASTNode *try_parse_param_expand(Parser *p, const char *content,
                                        size_t len);

static bool is_alnum(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

static void parser_advance(Parser *p) {
    p->previous = p->current;
    for (;;) {
        p->current = lexer_next(&p->lexer);
        if (p->current.type != TOK_ERROR) break;

        vex_err("%.*s", p->current.length, p->current.start);
        p->had_error = true;
    }
}

static bool check(Parser *p, TokenType type) {
    return p->current.type == type;
}

static bool parser_match(Parser *p, TokenType type) {
    if (!check(p, type)) return false;
    parser_advance(p);
    return true;
}

static void expect(Parser *p, TokenType type, const char *msg) {
    if (check(p, type)) {
        parser_advance(p);
        return;
    }
    vex_err("expected %s, got '%s'", msg, token_type_name(p->current.type));
    p->had_error = true;
}

static void skip_newlines(Parser *p) {
    while (check(p, TOK_NEWLINE)) parser_advance(p);
}

static bool is_cmd_name_token(TokenType t) {
    return t == TOK_IDENT || t == TOK_TRUE || t == TOK_FALSE || t == TOK_NULL ||
           t == TOK_LET || t == TOK_MUT || t == TOK_FN || t == TOK_IF ||
           t == TOK_ELSE || t == TOK_FOR || t == TOK_IN || t == TOK_WHILE ||
           t == TOK_LOOP || t == TOK_BREAK || t == TOK_CONTINUE ||
           t == TOK_RETURN || t == TOK_MATCH || t == TOK_TRY || t == TOK_CATCH ||
           t == TOK_USE || t == TOK_ERROR_KW;
}

static bool is_stderr_redirect(Parser *p) {
    if (p->current.type == TOK_INT && p->current.length == 1 &&
        p->current.start[0] == '2') {
        const char *after = p->current.start + 1;
        return (*after == '>');
    }
    return false;
}

static void expect_cmd_name(Parser *p) {
    if (is_cmd_name_token(p->current.type)) {
        parser_advance(p);
        return;
    }
    vex_err("expected command name, got '%s'", token_type_name(p->current.type));
    p->had_error = true;
}

static ASTNode *node_new(Parser *p, ASTKind kind) {
    ASTNode *n = arena_alloc(p->arena, sizeof(ASTNode));
    memset(n, 0, sizeof(ASTNode));
    n->kind = kind;
    n->token = p->previous;
    return n;
}

static bool is_bare_word_token(TokenType t) {
    switch (t) {
    case TOK_IDENT: case TOK_INT: case TOK_FLOAT:
    case TOK_DOT: case TOK_SLASH: case TOK_STAR:
    case TOK_MINUS: case TOK_COLON: case TOK_QUESTION:
    case TOK_PERCENT: case TOK_PLUS: case TOK_CARET:
    case TOK_NOT: case TOK_TILDE:
    case TOK_LBRACE: case TOK_RBRACE: case TOK_COMMA:
        return true;
    default:
        return false;
    }
}

static ASTNode *parse_external_arg(Parser *p) {

    if (check(p, TOK_STRING) || check(p, TOK_RAW_STRING)) {
        return parse_primary(p);
    }

    if (check(p, TOK_LPAREN)) {
        return parse_primary(p);
    }

    if (check(p, TOK_LBRACKET)) {
        return parse_primary(p);
    }

    if (check(p, TOK_TRUE) || check(p, TOK_FALSE) || check(p, TOK_NULL)) {
        return parse_primary(p);
    }

    if (is_bare_word_token(p->current.type)) {
        const char *start = p->current.start;
        const char *end = start + p->current.length;
        parser_advance(p);

        while (is_bare_word_token(p->current.type) &&
               p->current.start == end) {
            end = p->current.start + p->current.length;
            parser_advance(p);
        }

        ASTNode *n = node_new(p, AST_LITERAL);
        n->literal = vval_string(vstr_newn(start, (size_t)(end - start)));
        return n;
    }

    return parse_primary(p);
}

static ASTNode *parse_number(Parser *p) {
    ASTNode *n = node_new(p, AST_LITERAL);
    char *text = token_text(&p->previous);
    if (p->previous.type == TOK_INT) {
        n->literal = vval_int(strtol(text, NULL, 10));
    } else {
        n->literal = vval_float(strtod(text, NULL));
    }
    free(text);
    return n;
}

static size_t process_escapes(const char *src, size_t len, char *dst) {
    size_t out = 0;
    for (size_t i = 0; i < len; i++) {
        if (src[i] == '\\' && i + 1 < len) {
            i++;
            switch (src[i]) {
            case 'n':  dst[out++] = '\n'; break;
            case 't':  dst[out++] = '\t'; break;
            case 'r':  dst[out++] = '\r'; break;
            case 'a':  dst[out++] = '\a'; break;
            case 'b':  dst[out++] = '\b'; break;
            case 'e':  dst[out++] = '\033'; break;
            case '\\': dst[out++] = '\\'; break;
            case '"':  dst[out++] = '"';  break;
            case '0':  dst[out++] = '\0'; break;
            case '$':  dst[out++] = '$';  break;
            case 'x': {

                unsigned int val = 0;
                int digits = 0;
                while (digits < 2 && i + 1 < len) {
                    char c = src[i + 1];
                    unsigned int nibble;
                    if (c >= '0' && c <= '9') nibble = (unsigned)(c - '0');
                    else if (c >= 'a' && c <= 'f') nibble = (unsigned)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') nibble = (unsigned)(c - 'A' + 10);
                    else break;
                    val = (val << 4) | nibble;
                    i++;
                    digits++;
                }
                if (digits > 0) dst[out++] = (char)val;
                break;
            }
            case 'u': {

                unsigned int cp = 0;
                int digits = 0;
                while (digits < 4 && i + 1 < len) {
                    char c = src[i + 1];
                    unsigned int nibble;
                    if (c >= '0' && c <= '9') nibble = (unsigned)(c - '0');
                    else if (c >= 'a' && c <= 'f') nibble = (unsigned)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') nibble = (unsigned)(c - 'A' + 10);
                    else break;
                    cp = (cp << 4) | nibble;
                    i++;
                    digits++;
                }
                if (digits > 0) {

                    if (cp < 0x80) {
                        dst[out++] = (char)cp;
                    } else if (cp < 0x800) {
                        dst[out++] = (char)(0xC0 | (cp >> 6));
                        dst[out++] = (char)(0x80 | (cp & 0x3F));
                    } else {
                        dst[out++] = (char)(0xE0 | (cp >> 12));
                        dst[out++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        dst[out++] = (char)(0x80 | (cp & 0x3F));
                    }
                }
                break;
            }
            case 'U': {

                unsigned int cp = 0;
                int digits = 0;
                while (digits < 8 && i + 1 < len) {
                    char c = src[i + 1];
                    unsigned int nibble;
                    if (c >= '0' && c <= '9') nibble = (unsigned)(c - '0');
                    else if (c >= 'a' && c <= 'f') nibble = (unsigned)(c - 'a' + 10);
                    else if (c >= 'A' && c <= 'F') nibble = (unsigned)(c - 'A' + 10);
                    else break;
                    cp = (cp << 4) | nibble;
                    i++;
                    digits++;
                }
                if (digits > 0) {
                    if (cp < 0x80) {
                        dst[out++] = (char)cp;
                    } else if (cp < 0x800) {
                        dst[out++] = (char)(0xC0 | (cp >> 6));
                        dst[out++] = (char)(0x80 | (cp & 0x3F));
                    } else if (cp < 0x10000) {
                        dst[out++] = (char)(0xE0 | (cp >> 12));
                        dst[out++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        dst[out++] = (char)(0x80 | (cp & 0x3F));
                    } else if (cp < 0x110000) {
                        dst[out++] = (char)(0xF0 | (cp >> 18));
                        dst[out++] = (char)(0x80 | ((cp >> 12) & 0x3F));
                        dst[out++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        dst[out++] = (char)(0x80 | (cp & 0x3F));
                    }
                }
                break;
            }
            default:   dst[out++] = '\\'; dst[out++] = src[i]; break;
            }
        } else {
            dst[out++] = src[i];
        }
    }
    dst[out] = '\0';
    return out;
}

static bool has_interpolation(const char *start, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (start[i] == '\\') { i++; continue; }
        if (start[i] == '$') return true;
    }
    return false;
}

static ASTNode *parse_string_literal(Parser *p) {

    const char *start = p->previous.start + 1;
    size_t len = p->previous.length - 2;
    bool is_raw = (p->previous.type == TOK_RAW_STRING);

    if (is_raw) {
        ASTNode *n = node_new(p, AST_LITERAL);
        n->literal = vval_string_cstr(arena_strndup(p->arena, start, len));
        return n;
    }

    if (!has_interpolation(start, len)) {
        ASTNode *n = node_new(p, AST_LITERAL);
        char *buf = arena_alloc(p->arena, len + 1);
        size_t out = process_escapes(start, len, buf);
        n->literal = vval_string(vstr_newn(buf, out));
        return n;
    }

    ASTNode *n = node_new(p, AST_STRING_INTERP);
    VEX_VEC(ASTNode *) parts;
    vvec_init(parts);

    size_t seg_start = 0;
    for (size_t i = 0; i < len; ) {
        if (start[i] == '\\' && i + 1 < len) {
            i += 2;
            continue;
        }
        if (start[i] == '$') {

            if (i > seg_start) {
                char *buf = arena_alloc(p->arena, i - seg_start + 1);
                size_t slen = process_escapes(start + seg_start, i - seg_start, buf);
                ASTNode *lit = arena_alloc(p->arena, sizeof(ASTNode));
                memset(lit, 0, sizeof(ASTNode));
                lit->kind = AST_LITERAL;
                lit->literal = vval_string(vstr_newn(buf, slen));
                vvec_push(parts, lit);
            }

            i++;
            if (i + 1 < len && start[i] == '(' && start[i + 1] == '(') {

                i += 2;
                size_t expr_start = i;

                int depth = 1;
                while (i < len) {
                    if (i + 1 < len && start[i] == '(' && start[i + 1] == '(') {
                        depth++; i += 2;
                    } else if (i + 1 < len && start[i] == ')' && start[i + 1] == ')') {
                        depth--;
                        if (depth == 0) break;
                        i += 2;
                    } else {
                        i++;
                    }
                }
                char *expr_src = arena_strndup(p->arena, start + expr_start, i - expr_start);
                Parser sub = parser_init(expr_src, p->arena);
                ASTNode *expr = parse_expression(&sub);
                vvec_push(parts, expr);
                if (i < len) i += 2;
            } else if (i < len && start[i] == '(') {

                i++;
                size_t expr_start = i;
                int depth = 1;
                while (i < len && depth > 0) {
                    if (start[i] == '(') depth++;
                    else if (start[i] == ')') depth--;
                    if (depth > 0) i++;
                }
                char *cmd_src = arena_strndup(p->arena, start + expr_start, i - expr_start);
                Parser sub = parser_init(cmd_src, p->arena);
                ASTNode *cmd = parse_pipeline(&sub);
                ASTNode *subst = arena_alloc(p->arena, sizeof(ASTNode));
                memset(subst, 0, sizeof(ASTNode));
                subst->kind = AST_CMD_SUBST;
                subst->subst_cmd = cmd;
                vvec_push(parts, subst);
                if (i < len) i++;
            } else if (i < len && start[i] == '{') {

                i++;
                size_t expr_start = i;
                int depth = 1;
                while (i < len && depth > 0) {
                    if (start[i] == '{') depth++;
                    else if (start[i] == '}') depth--;
                    if (depth > 0) i++;
                }
                size_t expr_len = i - expr_start;
                char *content = arena_strndup(p->arena,
                                              start + expr_start,
                                              expr_len);

                ASTNode *pnode = try_parse_param_expand(p, content,
                                                        expr_len);
                if (pnode) {
                    vvec_push(parts, pnode);
                } else {

                    Parser sub = parser_init(content, p->arena);
                    ASTNode *expr = parse_pipeline(&sub);
                    vvec_push(parts, expr);
                }
                if (i < len) i++;
            } else {

                size_t id_start = i;
                while (i < len && (is_alnum(start[i]) || start[i] == '_')) i++;
                if (i > id_start) {
                    ASTNode *ident = arena_alloc(p->arena, sizeof(ASTNode));
                    memset(ident, 0, sizeof(ASTNode));
                    ident->kind = AST_IDENT;
                    ident->name = arena_strndup(p->arena, start + id_start, i - id_start);
                    vvec_push(parts, ident);
                }
            }
            seg_start = i;
        } else {
            i++;
        }
    }

    if (seg_start < len) {
        char *buf = arena_alloc(p->arena, len - seg_start + 1);
        size_t slen = process_escapes(start + seg_start, len - seg_start, buf);
        ASTNode *lit = arena_alloc(p->arena, sizeof(ASTNode));
        memset(lit, 0, sizeof(ASTNode));
        lit->kind = AST_LITERAL;
        lit->literal = vval_string(vstr_newn(buf, slen));
        vvec_push(parts, lit);
    }

    n->interp.count = parts.len;
    n->interp.parts = arena_alloc(p->arena, parts.len * sizeof(ASTNode *));
    memcpy(n->interp.parts, parts.data, parts.len * sizeof(ASTNode *));
    vvec_free(parts);
    return n;
}

static ASTNode *try_parse_param_expand(Parser *p, const char *content,
                                        size_t len) {
    if (len == 0) return NULL;

    if (content[0] == '#') {
        ASTNode *n = arena_alloc(p->arena, sizeof(ASTNode));
        memset(n, 0, sizeof(ASTNode));
        n->kind = AST_PARAM_EXPAND;
        n->param_expand.var_name = arena_strndup(p->arena, content + 1,
                                                  len - 1);
        n->param_expand.expand_op = PEXP_LENGTH;
        n->param_expand.operand = NULL;
        return n;
    }

    size_t vi = 0;
    while (vi < len && (is_alnum(content[vi]) || content[vi] == '_')) vi++;
    if (vi == 0 || vi == len) return NULL;

    char *var = arena_strndup(p->arena, content, vi);
    const char *rest = content + vi;
    size_t rest_len = len - vi;

    ASTNode *n = arena_alloc(p->arena, sizeof(ASTNode));
    memset(n, 0, sizeof(ASTNode));
    n->kind = AST_PARAM_EXPAND;
    n->param_expand.var_name = var;

    if (rest_len >= 2 && rest[0] == ':' && rest[1] == '-') {
        n->param_expand.expand_op = PEXP_DEFAULT;
        n->param_expand.operand = arena_strndup(p->arena, rest + 2,
                                                 rest_len - 2);
    } else if (rest_len >= 2 && rest[0] == ':' && rest[1] == '=') {
        n->param_expand.expand_op = PEXP_ASSIGN;
        n->param_expand.operand = arena_strndup(p->arena, rest + 2,
                                                 rest_len - 2);
    } else if (rest_len >= 2 && rest[0] == ':' && rest[1] == '?') {
        n->param_expand.expand_op = PEXP_ERROR;
        n->param_expand.operand = arena_strndup(p->arena, rest + 2,
                                                 rest_len - 2);
    } else if (rest_len >= 2 && rest[0] == ':' && rest[1] == '+') {
        n->param_expand.expand_op = PEXP_ALTVAL;
        n->param_expand.operand = arena_strndup(p->arena, rest + 2,
                                                 rest_len - 2);
    } else if (rest_len >= 2 && rest[0] == '#' && rest[1] == '#') {
        n->param_expand.expand_op = PEXP_TRIM_LL;
        n->param_expand.operand = arena_strndup(p->arena, rest + 2,
                                                 rest_len - 2);
    } else if (rest_len >= 1 && rest[0] == '#') {
        n->param_expand.expand_op = PEXP_TRIM_L;
        n->param_expand.operand = arena_strndup(p->arena, rest + 1,
                                                 rest_len - 1);
    } else if (rest_len >= 2 && rest[0] == '%' && rest[1] == '%') {
        n->param_expand.expand_op = PEXP_TRIM_RR;
        n->param_expand.operand = arena_strndup(p->arena, rest + 2,
                                                 rest_len - 2);
    } else if (rest_len >= 1 && rest[0] == '%') {
        n->param_expand.expand_op = PEXP_TRIM_R;
        n->param_expand.operand = arena_strndup(p->arena, rest + 1,
                                                 rest_len - 1);
    } else if (rest_len >= 2 && rest[0] == '/' && rest[1] == '/') {
        n->param_expand.expand_op = PEXP_REPLACE_ALL;
        n->param_expand.operand = arena_strndup(p->arena, rest + 2,
                                                 rest_len - 2);
    } else if (rest_len >= 1 && rest[0] == '/') {
        n->param_expand.expand_op = PEXP_REPLACE;
        n->param_expand.operand = arena_strndup(p->arena, rest + 1,
                                                 rest_len - 1);
    } else if (rest_len >= 2 && rest[0] == '^' && rest[1] == '^') {
        n->param_expand.expand_op = PEXP_UPPER;
        n->param_expand.operand = NULL;
    } else if (rest_len >= 2 && rest[0] == ',' && rest[1] == ',') {
        n->param_expand.expand_op = PEXP_LOWER;
        n->param_expand.operand = NULL;
    } else if (rest_len >= 1 && rest[0] == ':') {
        n->param_expand.expand_op = PEXP_SLICE;
        n->param_expand.operand = arena_strndup(p->arena, rest + 1,
                                                 rest_len - 1);
    } else {
        return NULL;
    }

    return n;
}

static ASTNode *parse_list(Parser *p) {
    ASTNode *n = node_new(p, AST_LIST);
    VEX_VEC(ASTNode *) items;
    vvec_init(items);

    skip_newlines(p);
    while (!check(p, TOK_RBRACKET) && !check(p, TOK_EOF)) {
        vvec_push(items, parse_expression(p));
        skip_newlines(p);
        parser_match(p, TOK_COMMA);
        skip_newlines(p);
    }
    expect(p, TOK_RBRACKET, "]");

    n->list.count = items.len;
    n->list.items = arena_alloc(p->arena, items.len * sizeof(ASTNode *));
    memcpy(n->list.items, items.data, items.len * sizeof(ASTNode *));
    vvec_free(items);
    return n;
}

static ASTNode *parse_record(Parser *p) {

    ASTNode *n = node_new(p, AST_RECORD);
    VEX_VEC(char *) keys;
    VEX_VEC(ASTNode *) values;
    vvec_init(keys);
    vvec_init(values);

    skip_newlines(p);
    while (!check(p, TOK_RBRACE) && !check(p, TOK_EOF)) {
        expect(p, TOK_IDENT, "field name");
        char *key = arena_strndup(p->arena, p->previous.start, p->previous.length);
        expect(p, TOK_COLON, ":");
        ASTNode *val = parse_expression(p);

        vvec_push(keys, key);
        vvec_push(values, val);

        skip_newlines(p);
        parser_match(p, TOK_COMMA);
        skip_newlines(p);
    }
    expect(p, TOK_RBRACE, "}");

    n->record.count = keys.len;
    n->record.keys = arena_alloc(p->arena, keys.len * sizeof(char *));
    n->record.values = arena_alloc(p->arena, values.len * sizeof(ASTNode *));
    memcpy(n->record.keys, keys.data, keys.len * sizeof(char *));
    memcpy(n->record.values, values.data, values.len * sizeof(ASTNode *));
    vvec_free(keys);
    vvec_free(values);
    return n;
}

static ASTNode *parse_primary(Parser *p) {

    if (parser_match(p, TOK_INT) || parser_match(p, TOK_FLOAT)) {
        return parse_number(p);
    }

    if (parser_match(p, TOK_STRING) || parser_match(p, TOK_RAW_STRING)) {
        return parse_string_literal(p);
    }

    if (parser_match(p, TOK_TRUE)) {
        ASTNode *n = node_new(p, AST_LITERAL);
        n->literal = vval_bool(true);
        return n;
    }
    if (parser_match(p, TOK_FALSE)) {
        ASTNode *n = node_new(p, AST_LITERAL);
        n->literal = vval_bool(false);
        return n;
    }
    if (parser_match(p, TOK_NULL)) {
        ASTNode *n = node_new(p, AST_LITERAL);
        n->literal = vval_null();
        return n;
    }

    if (parser_match(p, TOK_DOLLAR)) {
        if (parser_match(p, TOK_IDENT)) {
            ASTNode *n = node_new(p, AST_IDENT);
            n->name = arena_strndup(p->arena, p->previous.start, p->previous.length);
            return n;
        }

        if (parser_match(p, TOK_INT)) {
            ASTNode *n = node_new(p, AST_IDENT);
            n->name = arena_strndup(p->arena, p->previous.start, p->previous.length);
            return n;
        }

        if (parser_match(p, TOK_QUESTION)) {
            ASTNode *n = node_new(p, AST_IDENT);
            n->name = arena_strndup(p->arena, "?", 1);
            return n;
        }

        if (parser_match(p, TOK_DOLLAR)) {
            ASTNode *n = node_new(p, AST_IDENT);
            n->name = arena_strndup(p->arena, "$", 1);
            return n;
        }

        if (parser_match(p, TOK_STAR)) {
            ASTNode *n = node_new(p, AST_IDENT);
            n->name = arena_strndup(p->arena, "@", 1);
            return n;
        }

        /* $in: treat the 'in' keyword as an identifier after $ */
        if (parser_match(p, TOK_IN)) {
            ASTNode *n = node_new(p, AST_IDENT);
            n->name = arena_strndup(p->arena, "in", 2);
            return n;
        }

        vex_err("expected variable name after $");
        p->had_error = true;
        return node_new(p, AST_LITERAL);
    }

    if (parser_match(p, TOK_IDENT)) {
        ASTNode *n = node_new(p, AST_IDENT);
        n->name = arena_strndup(p->arena, p->previous.start, p->previous.length);
        return n;
    }

    if (parser_match(p, TOK_LBRACKET)) {
        return parse_list(p);
    }

    if (parser_match(p, TOK_LPAREN)) {

        Lexer paren_saved = p->lexer;
        Token paren_cur = p->current;
        Token paren_prev = p->previous;

        bool is_subshell = false;
        int depth = 1;
        while (depth > 0 && !check(p, TOK_EOF)) {
            if (check(p, TOK_LPAREN)) depth++;
            else if (check(p, TOK_RPAREN)) { depth--; if (depth == 0) break; }
            else if (depth == 1 && (check(p, TOK_SEMI) || check(p, TOK_NEWLINE))) {
                is_subshell = true;
                break;
            }
            parser_advance(p);
        }

        p->lexer = paren_saved;
        p->current = paren_cur;
        p->previous = paren_prev;

        if (is_subshell) {
            ASTNode *n = node_new(p, AST_SUBSHELL);
            VEX_VEC(ASTNode *) stmts;
            vvec_init(stmts);
            while (!check(p, TOK_RPAREN) && !check(p, TOK_EOF)) {
                skip_newlines(p);
                if (check(p, TOK_RPAREN)) break;
                ASTNode *stmt = parse_cond_chain(p);
                if (stmt) vvec_push(stmts, stmt);
                if (!parser_match(p, TOK_SEMI)) skip_newlines(p);
            }
            expect(p, TOK_RPAREN, ")");
            n->block.count = stmts.len;
            n->block.stmts = arena_alloc(p->arena, stmts.len * sizeof(ASTNode *));
            memcpy(n->block.stmts, stmts.data, stmts.len * sizeof(ASTNode *));
            vvec_free(stmts);
            return n;
        } else {
            /* Parens use parse_cond_chain so pipes/&& work inside (expr) */
            ASTNode *expr = parse_cond_chain(p);
            expect(p, TOK_RPAREN, ")");
            return expr;
        }
    }

    if (parser_match(p, TOK_LBRACE)) {
        /* Empty braces {} produce an empty record, not a block */
        if (check(p, TOK_RBRACE)) {
            parser_advance(p);
            return node_new(p, AST_RECORD);
        }

        Lexer saved = p->lexer;
        Token saved_cur = p->current;
        bool is_rec = false;

        skip_newlines(p);
        if (check(p, TOK_IDENT)) {
            parser_advance(p);
            if (check(p, TOK_COLON)) is_rec = true;
        }

        p->lexer = saved;
        p->current = saved_cur;

        if (is_rec) return parse_record(p);

        if (check(p, TOK_PIPE)) {
            parser_advance(p);
            ASTNode *n = node_new(p, AST_FN);
            n->fn.fn_name = NULL;
            VEX_VEC(Param) params;
            vvec_init(params);
            while (!check(p, TOK_PIPE) && !check(p, TOK_EOF)) {
                expect(p, TOK_IDENT, "parameter name");
                Param param = {0};
                param.name = arena_strndup(p->arena, p->previous.start,
                                           p->previous.length);
                vvec_push(params, param);
                parser_match(p, TOK_COMMA);
            }
            expect(p, TOK_PIPE, "|");
            n->fn.params = arena_alloc(p->arena, params.len * sizeof(Param));
            memcpy(n->fn.params, params.data, params.len * sizeof(Param));
            n->fn.param_count = params.len;
            vvec_free(params);
            n->fn.body = parse_block(p);
            return n;
        }

        return parse_block(p);
    }

    if (parser_match(p, TOK_CARET)) {
        expect_cmd_name(p);
        ASTNode *n = node_new(p, AST_EXTERNAL_CALL);
        n->call.cmd_name = arena_strndup(p->arena, p->previous.start, p->previous.length);

        VEX_VEC(ASTNode *) args;
        vvec_init(args);

        while (!check(p, TOK_NEWLINE) && !check(p, TOK_PIPE) &&
               !check(p, TOK_BYTE_PIPE) && !check(p, TOK_SEMI) &&
               !check(p, TOK_EOF) && !check(p, TOK_RPAREN) &&
               !check(p, TOK_RBRACE) && !check(p, TOK_AMPERSAND) &&
               !check(p, TOK_AND_AND) && !check(p, TOK_OR_OR) &&
               !check(p, TOK_GT) && !check(p, TOK_APPEND) && !check(p, TOK_LT) &&
               !check(p, TOK_HEREDOC) && !check(p, TOK_HEREDOC_STRING) &&
               !is_stderr_redirect(p)) {
            vvec_push(args, parse_external_arg(p));
        }
        n->call.arg_count = args.len;
        n->call.args = arena_alloc(p->arena, args.len * sizeof(ASTNode *));
        memcpy(n->call.args, args.data, args.len * sizeof(ASTNode *));
        vvec_free(args);
        parse_redirects(p, &n->call.redir);
        return n;
    }

    if (parser_match(p, TOK_DOLLAR_LPAREN)) {
        ASTNode *n = node_new(p, AST_CMD_SUBST);
        n->subst_cmd = parse_pipeline(p);
        expect(p, TOK_RPAREN, ")");
        return n;
    }

    if (parser_match(p, TOK_LT_LPAREN)) {
        ASTNode *n = node_new(p, AST_PROC_SUBST);
        n->subst_cmd = parse_pipeline(p);
        expect(p, TOK_RPAREN, ")");
        return n;
    }

    if (parser_match(p, TOK_TILDE)) {
        ASTNode *n = node_new(p, AST_LITERAL);
        const char *home = getenv("HOME");
        n->literal = vval_string_cstr(home ? home : "~");
        return n;
    }

    if (parser_match(p, TOK_MINUS) || parser_match(p, TOK_NOT)) {
        TokenType op = p->previous.type;
        ASTNode *operand = parse_primary(p);
        ASTNode *n = node_new(p, AST_UNARY);
        n->unary.op = op;
        n->unary.operand = operand;
        return n;
    }

    vex_err("unexpected token: '%s'", token_type_name(p->current.type));
    p->had_error = true;
    parser_advance(p);
    return node_new(p, AST_LITERAL);
}

static int prefix_bp(TokenType t) {
    switch (t) {
    case TOK_NOT: case TOK_MINUS: return 15;
    default: return -1;
    }
}

static int infix_bp(TokenType t) {
    switch (t) {
    case TOK_OR:                                    return 2;
    case TOK_AND:                                   return 3;
    case TOK_DOTDOT: case TOK_DOTDOTLT:             return 4;
    case TOK_EQ: case TOK_NEQ: case TOK_REGEX_MATCH: return 5;
    case TOK_LT: case TOK_GT: case TOK_LTE: case TOK_GTE: return 6;
    case TOK_PLUS: case TOK_MINUS:                  return 8;
    case TOK_STAR: case TOK_SLASH: case TOK_PERCENT: return 9;
    case TOK_DOT:                                   return 12;
    default: return -1;
    }
}

static ASTNode *parse_binary(Parser *p, int min_prec) {
    ASTNode *left = parse_primary(p);

    for (;;) {

        if (check(p, TOK_LBRACKET)) {
            parser_advance(p);
            ASTNode *idx = parse_expression(p);
            expect(p, TOK_RBRACKET, "]");
            ASTNode *n = node_new(p, AST_INDEX);
            n->index_expr.object = left;
            n->index_expr.index = idx;
            left = n;
            continue;
        }

        if (check(p, TOK_QUESTION)) {
            parser_advance(p);
            ASTNode *n = node_new(p, AST_ERROR_PROPAGATE);
            n->propagate_expr = left;
            left = n;
            continue;
        }

        if (check(p, TOK_LPAREN) && left->kind == AST_IDENT) {
            parser_advance(p);
            ASTNode *n = node_new(p, AST_CALL);
            n->call.cmd_name = left->name;
            VEX_VEC(ASTNode *) args;
            vvec_init(args);
            while (!check(p, TOK_RPAREN) && !check(p, TOK_EOF)) {
                vvec_push(args, parse_expression(p));
                parser_match(p, TOK_COMMA);
            }
            expect(p, TOK_RPAREN, ")");
            n->call.arg_count = args.len;
            n->call.args = arena_alloc(p->arena, args.len * sizeof(ASTNode *));
            memcpy(n->call.args, args.data, args.len * sizeof(ASTNode *));
            vvec_free(args);
            left = n;
            continue;
        }

        int prec = infix_bp(p->current.type);
        if (prec < min_prec) break;

        TokenType op = p->current.type;
        parser_advance(p);

        if (op == TOK_DOT) {

            expect(p, TOK_IDENT, "field name");
            ASTNode *n = node_new(p, AST_FIELD_ACCESS);
            n->field.object = left;
            n->field.field = arena_strndup(p->arena, p->previous.start,
                                           p->previous.length);
            left = n;
            continue;
        }

        if (op == TOK_DOTDOT || op == TOK_DOTDOTLT) {
            ASTNode *right = parse_binary(p, prec + 1);
            ASTNode *n = node_new(p, AST_RANGE);
            n->range.start = left;
            n->range.end = right;
            n->range.exclusive = (op == TOK_DOTDOTLT);
            left = n;
            continue;
        }

        ASTNode *right = parse_binary(p, prec + 1);
        ASTNode *n = node_new(p, AST_BINARY);
        n->binary.op = op;
        n->binary.left = left;
        n->binary.right = right;
        left = n;
    }

    return left;
}

/* Top-level expression: delegates to pratt parser with min precedence 0 */
static ASTNode *parse_expression(Parser *p) {
    return parse_binary(p, 0);
}

static ASTNode *parse_cmd_arg_expr(Parser *p) {
    return parse_binary(p, 7);
}

static char *parse_redir_path(Parser *p) {
    if (parser_match(p, TOK_STRING) || parser_match(p, TOK_RAW_STRING)) {

        return arena_strndup(p->arena, p->previous.start + 1,
                             p->previous.length - 2);
    }

    const char *start = p->current.start;
    const char *end = start;
    while (!check(p, TOK_NEWLINE) && !check(p, TOK_PIPE) &&
           !check(p, TOK_BYTE_PIPE) && !check(p, TOK_SEMI) &&
           !check(p, TOK_EOF) && !check(p, TOK_AMPERSAND) &&
           !check(p, TOK_AND_AND) && !check(p, TOK_OR_OR) &&
           !check(p, TOK_GT) && !check(p, TOK_APPEND) && !check(p, TOK_LT) &&
           !check(p, TOK_HEREDOC_STRING) &&
           !check(p, TOK_RPAREN) && !check(p, TOK_RBRACE)) {
        end = p->current.start + p->current.length;
        parser_advance(p);
    }
    if (end > start) {
        return arena_strndup(p->arena, start, (size_t)(end - start));
    }
    vex_err("expected file path");
    p->had_error = true;
    return NULL;
}

/* Parse >, >>, <, <<, <<<, and 2> redirect operators into Redirect struct */
static void parse_redirects(Parser *p, Redirect *r) {
    memset(r, 0, sizeof(Redirect));
    for (;;) {

        if (check(p, TOK_INT) && p->current.length == 1 && p->current.start[0] == '2') {

            const char *after_2 = p->current.start + 1;
            if (*after_2 == '>') {
                parser_advance(p);
                if (parser_match(p, TOK_GT)) {

                    if (check(p, TOK_AMPERSAND)) {
                        const char *amp_end = p->current.start + p->current.length;
                        if (*amp_end == '1' || (check(p, TOK_AMPERSAND) &&
                            p->current.start + p->current.length <= p->lexer.current)) {
                            parser_advance(p);
                            if (parser_match(p, TOK_INT)) {  }
                            r->stderr_to_stdout = true;
                            continue;
                        }
                    }
                    r->stderr_append = false;
                    r->stderr_file = parse_redir_path(p);
                } else if (parser_match(p, TOK_APPEND)) {
                    r->stderr_append = true;
                    r->stderr_file = parse_redir_path(p);
                }
                continue;
            }
            break;
        }
        if (parser_match(p, TOK_GT)) {
            r->stdout_append = false;
            r->stdout_file = parse_redir_path(p);
        } else if (parser_match(p, TOK_APPEND)) {
            r->stdout_append = true;
            r->stdout_file = parse_redir_path(p);
        } else if (parser_match(p, TOK_HEREDOC)) {

            if (!is_cmd_name_token(p->current.type)) {
                vex_err("expected delimiter after <<");
                p->had_error = true;
            } else {
                char *delim = arena_strndup(p->arena, p->current.start,
                                            p->current.length);
                size_t delim_len = p->current.length;

                const char *after_delim = p->current.start + p->current.length;
                parser_advance(p);

                const char *scan = after_delim;

                while (*scan && *scan != '\n') scan++;
                if (*scan == '\n') scan++;
                const char *body_start = scan;
                const char *body_end = body_start;
                bool found = false;
                while (*scan) {

                    const char *line_start = scan;
                    while (*scan && *scan != '\n') scan++;
                    size_t line_len = (size_t)(scan - line_start);
                    if (line_len == delim_len &&
                        memcmp(line_start, delim, delim_len) == 0) {
                        body_end = line_start;
                        if (*scan == '\n') scan++;
                        found = true;
                        break;
                    }
                    if (*scan == '\n') scan++;
                }
                if (!found) {
                    vex_err("unterminated heredoc (expected '%s')", delim);
                    p->had_error = true;
                } else {
                    r->stdin_string = arena_strndup(p->arena, body_start,
                                                    (size_t)(body_end - body_start));

                    p->lexer.current = scan;
                    p->lexer.start = scan;

                    parser_advance(p);
                }
            }
        } else if (parser_match(p, TOK_HEREDOC_STRING)) {

            if (parser_match(p, TOK_STRING)) {
                r->stdin_string = arena_strndup(p->arena, p->previous.start + 1,
                                                p->previous.length - 2);
            } else if (parser_match(p, TOK_RAW_STRING)) {
                r->stdin_string = arena_strndup(p->arena, p->previous.start + 1,
                                                p->previous.length - 2);
            } else if (parser_match(p, TOK_IDENT)) {
                r->stdin_string = arena_strndup(p->arena, p->previous.start,
                                                p->previous.length);
            } else {
                vex_err("expected string after <<<");
                p->had_error = true;
            }
        } else if (parser_match(p, TOK_LT)) {
            r->stdin_file = parse_redir_path(p);
        } else {
            break;
        }
    }
}

/* Build a command call node; decides builtin vs external arg parsing */
static ASTNode *parse_command(Parser *p) {

    ASTNode *n = node_new(p, AST_CALL);
    n->call.cmd_name = arena_strndup(p->arena, p->previous.start, p->previous.length);

    char *ext_path = find_in_path(n->call.cmd_name);
    bool in_path = (ext_path != NULL);
    free(ext_path);
    bool is_builtin = builtin_exists(n->call.cmd_name) ||
                      plugin_cmd_exists(n->call.cmd_name) ||
                      !in_path;

    if (strcmp(n->call.cmd_name, "ls") == 0 ||
        strcmp(n->call.cmd_name, "cd") == 0 ||
        strcmp(n->call.cmd_name, "complete") == 0 ||
        strcmp(n->call.cmd_name, "alias") == 0 ||
        strcmp(n->call.cmd_name, "export") == 0 ||
        strcmp(n->call.cmd_name, "pushd") == 0 ||
        strcmp(n->call.cmd_name, "trap") == 0 ||
        strcmp(n->call.cmd_name, "read") == 0 ||
        strcmp(n->call.cmd_name, "time") == 0 ||
        strcmp(n->call.cmd_name, "test") == 0 ||
        strcmp(n->call.cmd_name, "mkdir") == 0 ||
        strcmp(n->call.cmd_name, "rm") == 0 ||
        strcmp(n->call.cmd_name, "cp") == 0 ||
        strcmp(n->call.cmd_name, "mv") == 0 ||
        strcmp(n->call.cmd_name, "basename") == 0 ||
        strcmp(n->call.cmd_name, "dirname") == 0 ||
        strcmp(n->call.cmd_name, "getopts") == 0 ||
        strcmp(n->call.cmd_name, "set") == 0 ||
        strcmp(n->call.cmd_name, "select-menu") == 0 ||
        strcmp(n->call.cmd_name, "bindkey") == 0 ||
        strcmp(n->call.cmd_name, "exec") == 0 ||
        strcmp(n->call.cmd_name, "printf") == 0 ||
        strcmp(n->call.cmd_name, "date") == 0 ||
        strcmp(n->call.cmd_name, "unset") == 0 ||
        strcmp(n->call.cmd_name, "unalias") == 0 ||
        strcmp(n->call.cmd_name, "command") == 0 ||
        strcmp(n->call.cmd_name, "touch") == 0 ||
        strcmp(n->call.cmd_name, "umask") == 0 ||
        strcmp(n->call.cmd_name, "cal") == 0 ||
        strcmp(n->call.cmd_name, "which-all") == 0 ||
        strcmp(n->call.cmd_name, "ansi") == 0 ||
        strcmp(n->call.cmd_name, "char") == 0 ||
        strcmp(n->call.cmd_name, "fill") == 0 ||
        strcmp(n->call.cmd_name, "error-make") == 0 ||
        strcmp(n->call.cmd_name, "du") == 0 ||
        strcmp(n->call.cmd_name, "watch") == 0 ||
        strcmp(n->call.cmd_name, "config") == 0 ||
        strcmp(n->call.cmd_name, "load-env") == 0 ||
        strcmp(n->call.cmd_name, "open-url") == 0 ||
        strcmp(n->call.cmd_name, "input-confirm") == 0 ||
        strcmp(n->call.cmd_name, "mktemp") == 0 ||
        strcmp(n->call.cmd_name, "realpath") == 0 ||
        strcmp(n->call.cmd_name, "ln") == 0 ||
        strcmp(n->call.cmd_name, "readlink") == 0 ||
        strcmp(n->call.cmd_name, "chmod") == 0 ||
        strcmp(n->call.cmd_name, "defer") == 0 ||
        strcmp(n->call.cmd_name, "http-get") == 0 ||
        strcmp(n->call.cmd_name, "http-post") == 0 ||
        strcmp(n->call.cmd_name, "http-put") == 0 ||
        strcmp(n->call.cmd_name, "http-delete") == 0 ||
        strcmp(n->call.cmd_name, "http-head") == 0 ||
        strcmp(n->call.cmd_name, "disown") == 0 ||
        strcmp(n->call.cmd_name, "rename") == 0 ||
        strcmp(n->call.cmd_name, "date-format") == 0 ||
        strcmp(n->call.cmd_name, "seq-date") == 0 ||
        strcmp(n->call.cmd_name, "path-exists") == 0 ||
        strcmp(n->call.cmd_name, "path-type") == 0 ||
        strcmp(n->call.cmd_name, "df") == 0 ||
        strcmp(n->call.cmd_name, "date-parse") == 0 ||
        strcmp(n->call.cmd_name, "env-get") == 0 ||
        strcmp(n->call.cmd_name, "env-set") == 0 ||
        strcmp(n->call.cmd_name, "gzip") == 0 ||
        strcmp(n->call.cmd_name, "gunzip") == 0 ||
        strcmp(n->call.cmd_name, "tar-list") == 0 ||
        strcmp(n->call.cmd_name, "path-is-absolute") == 0 ||
        strcmp(n->call.cmd_name, "path-normalize") == 0 ||
        strcmp(n->call.cmd_name, "path-with-ext") == 0 ||
        strcmp(n->call.cmd_name, "ulimit") == 0 ||
        strcmp(n->call.cmd_name, "tar-extract") == 0 ||
        strcmp(n->call.cmd_name, "tar-create") == 0 ||
        strcmp(n->call.cmd_name, "env-remove") == 0 ||
        strcmp(n->call.cmd_name, "command-type") == 0 ||
        strcmp(n->call.cmd_name, "abbr") == 0 ||
        strcmp(n->call.cmd_name, "source") == 0 ||
        strcmp(n->call.cmd_name, ".") == 0 ||
        strcmp(n->call.cmd_name, "eval") == 0 ||
        strcmp(n->call.cmd_name, "echo") == 0 ||
        strcmp(n->call.cmd_name, "wc") == 0 ||
        strcmp(n->call.cmd_name, "uname") == 0 ||
        strcmp(n->call.cmd_name, "ps") == 0 ||
        strcmp(n->call.cmd_name, "free") == 0 ||
        strcmp(n->call.cmd_name, "id") == 0 ||
        strcmp(n->call.cmd_name, "sort") == 0 ||
        strcmp(n->call.cmd_name, "tac") == 0 ||
        strcmp(n->call.cmd_name, "find") == 0 ||
        strcmp(n->call.cmd_name, "kill") == 0 ||
        strcmp(n->call.cmd_name, "assert") == 0 ||
        strcmp(n->call.cmd_name, "shift") == 0 ||
        strcmp(n->call.cmd_name, "ssh-exec") == 0 ||
        strcmp(n->call.cmd_name, "scp-get") == 0 ||
        strcmp(n->call.cmd_name, "scp-put") == 0 ||
        strcmp(n->call.cmd_name, "ssh") == 0 ||
        strcmp(n->call.cmd_name, "pkg") == 0 ||
        strcmp(n->call.cmd_name, "theme") == 0)
        is_builtin = false;

    VEX_VEC(ASTNode *) args;
    vvec_init(args);

    while (!check(p, TOK_NEWLINE) && !check(p, TOK_PIPE) &&
           !check(p, TOK_BYTE_PIPE) && !check(p, TOK_SEMI) &&
           !check(p, TOK_EOF) && !check(p, TOK_RPAREN) &&
           !check(p, TOK_RBRACE) && !check(p, TOK_AMPERSAND) &&
           !check(p, TOK_AND_AND) && !check(p, TOK_OR_OR) &&
           !check(p, TOK_GT) && !check(p, TOK_APPEND) && !check(p, TOK_LT) &&
               !check(p, TOK_HEREDOC) && !check(p, TOK_HEREDOC_STRING) &&
               !is_stderr_redirect(p)) {
        vvec_push(args, is_builtin ? parse_cmd_arg_expr(p) : parse_external_arg(p));
    }

    n->call.arg_count = args.len;
    n->call.args = arena_alloc(p->arena, args.len * sizeof(ASTNode *));
    memcpy(n->call.args, args.data, args.len * sizeof(ASTNode *));
    vvec_free(args);

    parse_redirects(p, &n->call.redir);
    return n;
}

static ASTNode *parse_block(Parser *p) {

    ASTNode *n = node_new(p, AST_BLOCK);
    VEX_VEC(ASTNode *) stmts;
    vvec_init(stmts);

    skip_newlines(p);
    while (!check(p, TOK_RBRACE) && !check(p, TOK_EOF)) {
        vvec_push(stmts, parse_cond_chain(p));
        skip_newlines(p);
        parser_match(p, TOK_SEMI);
        skip_newlines(p);
    }
    expect(p, TOK_RBRACE, "}");

    n->block.count = stmts.len;
    n->block.stmts = arena_alloc(p->arena, stmts.len * sizeof(ASTNode *));
    memcpy(n->block.stmts, stmts.data, stmts.len * sizeof(ASTNode *));
    vvec_free(stmts);
    return n;
}

static ASTNode *parse_let(Parser *p) {
    bool is_mut = (p->previous.type == TOK_MUT);
    ASTNode *n = node_new(p, is_mut ? AST_MUT : AST_LET);

    expect(p, TOK_IDENT, "variable name");
    n->binding.var_name = arena_strndup(p->arena, p->previous.start,
                                        p->previous.length);
    n->binding.type_hint = NULL;

    if (parser_match(p, TOK_COLON)) {
        expect(p, TOK_IDENT, "type name");
        n->binding.type_hint = arena_strndup(p->arena, p->previous.start,
                                             p->previous.length);
    }

    expect(p, TOK_ASSIGN, "=");
    n->binding.init = parse_expression(p);
    return n;
}

static ASTNode *parse_if(Parser *p) {
    ASTNode *n = node_new(p, AST_IF);
    n->if_stmt.cond = parse_expression(p);
    expect(p, TOK_LBRACE, "{");
    n->if_stmt.then_block = parse_block(p);

    if (parser_match(p, TOK_ELSE)) {
        if (parser_match(p, TOK_IF)) {
            n->if_stmt.else_block = parse_if(p);
        } else {
            expect(p, TOK_LBRACE, "{");
            n->if_stmt.else_block = parse_block(p);
        }
    } else {
        n->if_stmt.else_block = NULL;
    }
    return n;
}

static ASTNode *parse_for(Parser *p) {
    ASTNode *n = node_new(p, AST_FOR);
    expect(p, TOK_IDENT, "variable name");
    n->for_stmt.var_name = arena_strndup(p->arena, p->previous.start,
                                         p->previous.length);
    expect(p, TOK_IN, "in");
    n->for_stmt.iter = parse_expression(p);
    expect(p, TOK_LBRACE, "{");
    n->for_stmt.body = parse_block(p);
    return n;
}

static ASTNode *parse_while(Parser *p) {
    ASTNode *n = node_new(p, AST_WHILE);
    n->loop_stmt.cond = parse_expression(p);
    expect(p, TOK_LBRACE, "{");
    n->loop_stmt.body = parse_block(p);
    return n;
}

static ASTNode *parse_fn(Parser *p) {
    ASTNode *n = node_new(p, AST_FN);
    expect(p, TOK_IDENT, "function name");
    n->fn.fn_name = arena_strndup(p->arena, p->previous.start,
                                   p->previous.length);

    expect(p, TOK_LPAREN, "(");
    VEX_VEC(Param) params;
    vvec_init(params);

    while (!check(p, TOK_RPAREN) && !check(p, TOK_EOF)) {
        Param param = {0};
        if (parser_match(p, TOK_SPREAD)) {
            param.is_rest = true;
        }
        expect(p, TOK_IDENT, "parameter name");
        param.name = arena_strndup(p->arena, p->previous.start,
                                   p->previous.length);
        if (parser_match(p, TOK_COLON)) {
            expect(p, TOK_IDENT, "type");
            param.type_hint = arena_strndup(p->arena, p->previous.start,
                                            p->previous.length);
        }
        if (parser_match(p, TOK_ASSIGN)) {
            param.default_val = parse_expression(p);
        }
        vvec_push(params, param);
        parser_match(p, TOK_COMMA);
    }
    expect(p, TOK_RPAREN, ")");

    n->fn.param_count = params.len;
    n->fn.params = arena_alloc(p->arena, params.len * sizeof(Param));
    memcpy(n->fn.params, params.data, params.len * sizeof(Param));
    vvec_free(params);

    n->fn.return_type = NULL;
    if (parser_match(p, TOK_ARROW)) {
        expect(p, TOK_IDENT, "return type");
        n->fn.return_type = arena_strndup(p->arena, p->previous.start,
                                          p->previous.length);
    }

    expect(p, TOK_LBRACE, "{");
    n->fn.body = parse_block(p);
    return n;
}

static ASTNode *parse_match(Parser *p) {
    ASTNode *n = node_new(p, AST_MATCH);
    ASTNode *subject = parse_expression(p);
    expect(p, TOK_LBRACE, "{");
    skip_newlines(p);

    VEX_VEC(ASTNode *) patterns;
    VEX_VEC(ASTNode *) bodies;
    vvec_init(patterns);
    vvec_init(bodies);

    while (!check(p, TOK_RBRACE) && !check(p, TOK_EOF)) {

        ASTNode *pat;
        if (check(p, TOK_IDENT) && p->current.length == 1 && p->current.start[0] == '_') {
            parser_advance(p);
            pat = node_new(p, AST_LITERAL);
            pat->literal = NULL;
        } else {
            pat = parse_expression(p);
        }
        expect(p, TOK_FAT_ARROW, "=>");
        skip_newlines(p);

        ASTNode *body;
        if (check(p, TOK_LBRACE)) {
            parser_advance(p);
            body = parse_block(p);
        } else {
            body = parse_expression(p);
        }

        vvec_push(patterns, pat);
        vvec_push(bodies, body);

        skip_newlines(p);
        parser_match(p, TOK_COMMA);
        skip_newlines(p);
    }
    expect(p, TOK_RBRACE, "}");

    size_t arm_count = patterns.len;
    size_t total = 1 + arm_count * 2;
    n->pipeline.stages = arena_alloc(p->arena, total * sizeof(ASTNode *));
    n->pipeline.stages[0] = subject;
    for (size_t i = 0; i < arm_count; i++) {
        n->pipeline.stages[1 + i * 2] = patterns.data[i];
        n->pipeline.stages[1 + i * 2 + 1] = bodies.data[i];
    }
    n->pipeline.count = total;
    vvec_free(patterns);
    vvec_free(bodies);
    return n;
}

static ASTNode *parse_try(Parser *p) {

    ASTNode *n = node_new(p, AST_TRY_CATCH);
    expect(p, TOK_LBRACE, "{");
    n->try_catch.try_block = parse_block(p);
    expect(p, TOK_CATCH, "catch");

    if (check(p, TOK_IDENT)) {
        parser_advance(p);
        n->try_catch.catch_var = arena_strndup(p->arena, p->previous.start,
                                                p->previous.length);
    } else {
        n->try_catch.catch_var = "_";
    }

    expect(p, TOK_LBRACE, "{");
    n->try_catch.catch_block = parse_block(p);
    return n;
}

/* Chain statements with | or |> into a pipeline node */
static ASTNode *parse_pipeline(Parser *p) {
    ASTNode *first = parse_statement(p);
    if (!check(p, TOK_PIPE) && !check(p, TOK_BYTE_PIPE)) return first;

    VEX_VEC(ASTNode *) stages;
    vvec_init(stages);
    vvec_push(stages, first);

    bool is_byte = false;
    while (parser_match(p, TOK_PIPE) || parser_match(p, TOK_BYTE_PIPE)) {
        if (p->previous.type == TOK_BYTE_PIPE) is_byte = true;
        skip_newlines(p);
        vvec_push(stages, parse_statement(p));
    }

    ASTNode *n = node_new(p, is_byte ? AST_BYTE_PIPELINE : AST_PIPELINE);
    n->pipeline.count = stages.len;
    n->pipeline.stages = arena_alloc(p->arena, stages.len * sizeof(ASTNode *));
    memcpy(n->pipeline.stages, stages.data, stages.len * sizeof(ASTNode *));
    vvec_free(stages);
    return n;
}

/* Link pipelines with && / || into a conditional chain */
static ASTNode *parse_cond_chain(Parser *p) {
    ASTNode *first = parse_pipeline(p);
    if (!check(p, TOK_AND_AND) && !check(p, TOK_OR_OR)) return first;

    VEX_VEC(ASTNode *) cmds;
    VEX_VEC(TokenType) ops;
    vvec_init(cmds);
    vvec_init(ops);
    vvec_push(cmds, first);

    while (parser_match(p, TOK_AND_AND) || parser_match(p, TOK_OR_OR)) {
        vvec_push(ops, p->previous.type);
        skip_newlines(p);
        vvec_push(cmds, parse_pipeline(p));
    }

    ASTNode *n = node_new(p, AST_COND_CHAIN);
    n->cond_chain.cmd_count = cmds.len;
    n->cond_chain.cmds = arena_alloc(p->arena, cmds.len * sizeof(ASTNode *));
    memcpy(n->cond_chain.cmds, cmds.data, cmds.len * sizeof(ASTNode *));
    n->cond_chain.ops = arena_alloc(p->arena, ops.len * sizeof(TokenType));
    memcpy(n->cond_chain.ops, ops.data, ops.len * sizeof(TokenType));
    vvec_free(cmds);
    vvec_free(ops);
    return n;
}

/* Dispatch keywords, assignments, commands, and fallback to expressions */
static ASTNode *parse_statement(Parser *p) {
    skip_newlines(p);

    if (parser_match(p, TOK_LET) || parser_match(p, TOK_MUT))
        return parse_let(p);

    if (parser_match(p, TOK_IF))
        return parse_if(p);

    if (parser_match(p, TOK_FOR))
        return parse_for(p);

    if (parser_match(p, TOK_WHILE))
        return parse_while(p);

    if (parser_match(p, TOK_LOOP)) {
        ASTNode *n = node_new(p, AST_LOOP);
        n->loop_stmt.cond = NULL;
        expect(p, TOK_LBRACE, "{");
        n->loop_stmt.body = parse_block(p);
        return n;
    }

    if (parser_match(p, TOK_FN))
        return parse_fn(p);

    if (parser_match(p, TOK_MATCH))
        return parse_match(p);

    if (parser_match(p, TOK_TRY))
        return parse_try(p);

    if (parser_match(p, TOK_USE)) {
        ASTNode *n = node_new(p, AST_USE);

        if (p->current.type == TOK_IDENT &&
            p->current.length == 6 && strncmp(p->current.start, "plugin", 6) == 0) {
            parser_advance(p);
            n->use_stmt.is_plugin = true;
        } else {
            n->use_stmt.is_plugin = false;
        }
        expect(p, TOK_STRING, "module path");
        const char *path = p->previous.start + 1;
        size_t len = p->previous.length - 2;
        n->use_stmt.path = arena_strndup(p->arena, path, len);
        return n;
    }

    if (parser_match(p, TOK_BREAK)) {
        return node_new(p, AST_BREAK);
    }

    if (parser_match(p, TOK_CONTINUE)) {
        return node_new(p, AST_CONTINUE);
    }

    if (parser_match(p, TOK_RETURN)) {
        ASTNode *n = node_new(p, AST_RETURN);
        if (!check(p, TOK_NEWLINE) && !check(p, TOK_SEMI) &&
            !check(p, TOK_EOF) && !check(p, TOK_RBRACE)) {
            n->ret_val = parse_expression(p);
        }
        return n;
    }

    if (parser_match(p, TOK_CARET)) {
        expect_cmd_name(p);
        ASTNode *n = node_new(p, AST_EXTERNAL_CALL);
        n->call.cmd_name = arena_strndup(p->arena, p->previous.start,
                                         p->previous.length);
        VEX_VEC(ASTNode *) args;
        vvec_init(args);
        while (!check(p, TOK_NEWLINE) && !check(p, TOK_PIPE) &&
               !check(p, TOK_BYTE_PIPE) && !check(p, TOK_SEMI) &&
               !check(p, TOK_EOF) && !check(p, TOK_RBRACE) &&
               !check(p, TOK_RPAREN) &&
               !check(p, TOK_AMPERSAND) && !check(p, TOK_AND_AND) &&
               !check(p, TOK_OR_OR) &&
               !check(p, TOK_GT) && !check(p, TOK_APPEND) && !check(p, TOK_LT) &&
               !check(p, TOK_HEREDOC) && !check(p, TOK_HEREDOC_STRING) &&
               !is_stderr_redirect(p)) {
            vvec_push(args, parse_external_arg(p));
        }
        n->call.arg_count = args.len;
        n->call.args = arena_alloc(p->arena, args.len * sizeof(ASTNode *));
        memcpy(n->call.args, args.data, args.len * sizeof(ASTNode *));
        vvec_free(args);
        parse_redirects(p, &n->call.redir);
        return n;
    }

    if (check(p, TOK_DOT) && p->current.length == 1) {

        Lexer saved_lexer = p->lexer;
        Token saved_cur = p->current;
        parser_advance(p);
        if (!check(p, TOK_NEWLINE) && !check(p, TOK_SEMI) &&
            !check(p, TOK_EOF) && !check(p, TOK_PIPE) &&
            !check(p, TOK_BYTE_PIPE) && !check(p, TOK_DOT)) {

            ASTNode *n = node_new(p, AST_CALL);
            n->call.cmd_name = arena_strndup(p->arena, ".", 1);
            VEX_VEC(ASTNode *) args;
            vvec_init(args);
            while (!check(p, TOK_NEWLINE) && !check(p, TOK_PIPE) &&
                   !check(p, TOK_BYTE_PIPE) && !check(p, TOK_SEMI) &&
                   !check(p, TOK_EOF) && !check(p, TOK_RBRACE) &&
                   !check(p, TOK_RPAREN) &&
                   !check(p, TOK_AMPERSAND) && !check(p, TOK_AND_AND) &&
                   !check(p, TOK_OR_OR) &&
                   !check(p, TOK_GT) && !check(p, TOK_APPEND) && !check(p, TOK_LT) &&
                   !check(p, TOK_HEREDOC) && !check(p, TOK_HEREDOC_STRING) &&
                   !is_stderr_redirect(p)) {
                vvec_push(args, parse_external_arg(p));
            }
            n->call.arg_count = args.len;
            n->call.args = arena_alloc(p->arena, args.len * sizeof(ASTNode *));
            memcpy(n->call.args, args.data, args.len * sizeof(ASTNode *));
            vvec_free(args);
            parse_redirects(p, &n->call.redir);
            return n;
        }

        p->lexer = saved_lexer;
        p->current = saved_cur;
    }

    if (check(p, TOK_IDENT)) {

        char *name = arena_strndup(p->arena, p->current.start, p->current.length);

        Lexer saved_lexer = p->lexer;
        Token saved_cur = p->current;
        parser_advance(p);
        if (check(p, TOK_ASSIGN)) {
            parser_advance(p);
            ASTNode *n = node_new(p, AST_ASSIGN);
            ASTNode *target = arena_alloc(p->arena, sizeof(ASTNode));
            memset(target, 0, sizeof(ASTNode));
            target->kind = AST_IDENT;
            target->name = name;
            n->assign.target = target;
            n->assign.value = parse_expression(p);
            return n;
        }

        p->lexer = saved_lexer;
        p->current = saved_cur;
        parser_advance(p);

        const char *alias_exp = alias_lookup(name);
        if (alias_exp && p->alias_depth < 16) {
            p->alias_depth++;

            size_t exp_len = strlen(alias_exp);
            const char *rest = p->lexer.current;
            size_t rest_len = strlen(rest);
            char *expanded = malloc(exp_len + 1 + rest_len + 1);
            memcpy(expanded, alias_exp, exp_len);
            expanded[exp_len] = ' ';
            memcpy(expanded + exp_len + 1, rest, rest_len);
            expanded[exp_len + 1 + rest_len] = '\0';

            char *kept = arena_strndup(p->arena, expanded, exp_len + 1 + rest_len);
            free(expanded);
            p->lexer = lexer_init(kept);
            parser_advance(p);
            return parse_statement(p);
        }

        if ((strcmp(name, "export") == 0 || strcmp(name, "alias") == 0 ||
             strcmp(name, "abbr") == 0) && check(p, TOK_IDENT)) {
            ASTNode *n = node_new(p, AST_CALL);
            n->call.cmd_name = name;
            VEX_VEC(ASTNode *) args;
            vvec_init(args);
            while (!check(p, TOK_NEWLINE) && !check(p, TOK_PIPE) &&
                   !check(p, TOK_BYTE_PIPE) && !check(p, TOK_SEMI) &&
                   !check(p, TOK_EOF) && !check(p, TOK_RPAREN) &&
                   !check(p, TOK_RBRACE) && !check(p, TOK_AMPERSAND) &&
                   !check(p, TOK_AND_AND) && !check(p, TOK_OR_OR) &&
                   !check(p, TOK_GT) && !check(p, TOK_APPEND) && !check(p, TOK_LT) &&
                   !check(p, TOK_HEREDOC) && !check(p, TOK_HEREDOC_STRING) &&
               !is_stderr_redirect(p)) {
                if (check(p, TOK_IDENT)) {

                    ASTNode *lit = node_new(p, AST_LITERAL);
                    lit->literal = vval_string(vstr_newn(p->current.start, p->current.length));
                    parser_advance(p);
                    vvec_push(args, lit);
                } else {
                    vvec_push(args, parse_external_arg(p));
                }
            }
            n->call.arg_count = args.len;
            n->call.args = arena_alloc(p->arena, args.len * sizeof(ASTNode *));
            memcpy(n->call.args, args.data, args.len * sizeof(ASTNode *));
            vvec_free(args);
            parse_redirects(p, &n->call.redir);
            return n;
        }

        if (builtin_exists(name) || plugin_cmd_exists(name) || find_in_path(name)) {
            return parse_command(p);
        }

        /* Unknown identifier followed by args: treat as command call */
        if (check(p, TOK_STRING) || check(p, TOK_RAW_STRING) ||
            check(p, TOK_INT) || check(p, TOK_FLOAT) ||
            check(p, TOK_DOLLAR) || check(p, TOK_LBRACKET) ||
            check(p, TOK_LBRACE) || check(p, TOK_TRUE) ||
            check(p, TOK_FALSE) || check(p, TOK_NULL) ||
            check(p, TOK_MINUS) || check(p, TOK_TILDE) ||
            check(p, TOK_IDENT)) {
            return parse_command(p);
        }

        p->lexer = saved_lexer;
        p->current = saved_cur;
        return parse_expression(p);
    }

    return parse_expression(p);
}

Parser parser_init(const char *source, VexArena *arena) {
    Parser p = {0};
    p.lexer = lexer_init(source);
    p.arena = arena;
    p.had_error = false;
    p.panic_mode = false;
    parser_advance(&p);
    return p;
}

ASTNode *parser_parse(Parser *p) {
    VEX_VEC(ASTNode *) stmts;
    vvec_init(stmts);

    skip_newlines(p);
    while (!check(p, TOK_EOF)) {
        ASTNode *stmt = parse_cond_chain(p);
        vvec_push(stmts, stmt);
        skip_newlines(p);
        parser_match(p, TOK_SEMI);
        skip_newlines(p);
    }

    ASTNode *block = arena_alloc(p->arena, sizeof(ASTNode));
    memset(block, 0, sizeof(ASTNode));
    block->kind = AST_BLOCK;
    block->block.count = stmts.len;
    block->block.stmts = arena_alloc(p->arena, stmts.len * sizeof(ASTNode *));
    memcpy(block->block.stmts, stmts.data, stmts.len * sizeof(ASTNode *));
    vvec_free(stmts);
    return block;
}

/* Parse a single interactive line: one cond-chain, optionally backgrounded */
ASTNode *parser_parse_line(Parser *p) {
    skip_newlines(p);
    if (check(p, TOK_EOF)) return NULL;
    ASTNode *stmt = parse_cond_chain(p);

    if (parser_match(p, TOK_AMPERSAND)) {
        ASTNode *bg = node_new(p, AST_BACKGROUND);
        bg->bg_stmt = stmt;
        stmt = bg;
    }

    skip_newlines(p);
    parser_match(p, TOK_SEMI);
    skip_newlines(p);
    return stmt;
}
