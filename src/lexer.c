#include "vex.h"

Lexer lexer_init(const char *source) {
    Lexer l = {0};
    l.source = source;
    l.current = source;
    l.start = source;
    l.line = 1;
    l.col = 0;
    l.at_eof = false;
    return l;
}

static char peek(Lexer *l) {
    return *l->current;
}

static char peek_next(Lexer *l) {
    if (*l->current == '\0') return '\0';
    return l->current[1];
}

static char advance(Lexer *l) {
    char c = *l->current++;
    l->col++;
    return c;
}

static bool at_end(Lexer *l) {
    return *l->current == '\0';
}

static bool match(Lexer *l, char expected) {
    if (at_end(l) || *l->current != expected) return false;
    l->current++;
    l->col++;
    return true;
}

static Token make_token(Lexer *l, TokenType type) {
    Token t;
    t.type = type;
    t.start = l->start;
    t.length = (uint32_t)(l->current - l->start);
    t.line = l->line;
    t.col = (uint16_t)(l->start - l->source);
    return t;
}

static Token error_token(Lexer *l, const char *msg) {
    Token t;
    t.type = TOK_ERROR;
    t.start = msg;
    t.length = (uint32_t)strlen(msg);
    t.line = l->line;
    t.col = l->col;
    return t;
}

static void skip_whitespace(Lexer *l) {
    for (;;) {
        char c = peek(l);
        switch (c) {
        case ' ':
        case '\t':
        case '\r':
            advance(l);
            break;
        case '#':

            while (peek(l) != '\n' && !at_end(l)) advance(l);
            break;
        default:
            return;
        }
    }
}

static bool is_digit(char c) { return c >= '0' && c <= '9'; }
static bool is_alpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
static bool is_alnum(char c) { return is_alpha(c) || is_digit(c); }
static bool is_ident_char(char c) { return is_alnum(c) || c == '-'; }

static TokenType check_keyword(const char *start, size_t len) {
    struct { const char *word; TokenType type; } keywords[] = {
        {"let",      TOK_LET},
        {"mut",      TOK_MUT},
        {"fn",       TOK_FN},
        {"if",       TOK_IF},
        {"else",     TOK_ELSE},
        {"for",      TOK_FOR},
        {"in",       TOK_IN},
        {"while",    TOK_WHILE},
        {"loop",     TOK_LOOP},
        {"break",    TOK_BREAK},
        {"continue", TOK_CONTINUE},
        {"return",   TOK_RETURN},
        {"match",    TOK_MATCH},
        {"try",      TOK_TRY},
        {"catch",    TOK_CATCH},
        {"use",      TOK_USE},
        {"error",    TOK_ERROR_KW},
        {"true",     TOK_TRUE},
        {"false",    TOK_FALSE},
        {"null",     TOK_NULL},
        {"and",      TOK_AND},
        {"or",       TOK_OR},
        {"not",      TOK_NOT},
        {NULL, 0}
    };

    for (int i = 0; keywords[i].word; i++) {
        if (strlen(keywords[i].word) == len &&
            memcmp(keywords[i].word, start, len) == 0) {
            return keywords[i].type;
        }
    }
    return TOK_IDENT;
}

static Token lex_number(Lexer *l) {
    while (is_digit(peek(l))) advance(l);

    if (peek(l) == '.' && is_digit(peek_next(l))) {
        advance(l);
        while (is_digit(peek(l))) advance(l);
        return make_token(l, TOK_FLOAT);
    }

    return make_token(l, TOK_INT);
}

static Token lex_string(Lexer *l) {

    while (peek(l) != '"' && !at_end(l)) {
        if (peek(l) == '\\') {
            advance(l);
            if (at_end(l)) break;
        }
        if (peek(l) == '\n') l->line++;
        advance(l);
    }

    if (at_end(l)) return error_token(l, "unterminated string");
    advance(l);
    return make_token(l, TOK_STRING);
}

static Token lex_raw_string(Lexer *l) {

    while (peek(l) != '\'' && !at_end(l)) {
        if (peek(l) == '\n') l->line++;
        advance(l);
    }

    if (at_end(l)) return error_token(l, "unterminated string");
    advance(l);
    return make_token(l, TOK_RAW_STRING);
}

static Token lex_identifier(Lexer *l) {

    while (is_ident_char(peek(l))) advance(l);

    size_t len = (size_t)(l->current - l->start);
    TokenType type = check_keyword(l->start, len);
    return make_token(l, type);
}

Token lexer_next(Lexer *l) {
    skip_whitespace(l);
    l->start = l->current;

    if (at_end(l)) {
        l->at_eof = true;
        return make_token(l, TOK_EOF);
    }

    char c = advance(l);

    if (is_digit(c)) return lex_number(l);

    if (is_alpha(c)) return lex_identifier(l);

    if (c == '"') return lex_string(l);
    if (c == '\'') return lex_raw_string(l);

    switch (c) {
    case '\n':
        l->line++;
        l->col = 0;
        return make_token(l, TOK_NEWLINE);

    case '|':
        if (match(l, '>')) return make_token(l, TOK_BYTE_PIPE);
        if (match(l, '|')) return make_token(l, TOK_OR_OR);
        return make_token(l, TOK_PIPE);

    case '.':
        if (match(l, '.')) {
            if (match(l, '<')) return make_token(l, TOK_DOTDOTLT);
            if (match(l, '.')) return make_token(l, TOK_SPREAD);
            return make_token(l, TOK_DOTDOT);
        }
        return make_token(l, TOK_DOT);

    case '+': return make_token(l, TOK_PLUS);
    case '*': return make_token(l, TOK_STAR);
    case '/': return make_token(l, TOK_SLASH);
    case '%': return make_token(l, TOK_PERCENT);
    case '~': return make_token(l, TOK_TILDE);
    case '^': return make_token(l, TOK_CARET);
    case '$':
        if (match(l, '(')) return make_token(l, TOK_DOLLAR_LPAREN);
        return make_token(l, TOK_DOLLAR);
    case '?': return make_token(l, TOK_QUESTION);
    case '(': return make_token(l, TOK_LPAREN);
    case ')': return make_token(l, TOK_RPAREN);
    case '{': return make_token(l, TOK_LBRACE);
    case '}': return make_token(l, TOK_RBRACE);
    case '[': return make_token(l, TOK_LBRACKET);
    case ']': return make_token(l, TOK_RBRACKET);
    case ',': return make_token(l, TOK_COMMA);
    case ':': return make_token(l, TOK_COLON);
    case ';': return make_token(l, TOK_SEMI);

    case '-':
        if (match(l, '>')) return make_token(l, TOK_ARROW);

        if (peek(l) == '-' || is_alpha(peek(l))) {

        }
        return make_token(l, TOK_MINUS);

    case '=':
        if (match(l, '=')) return make_token(l, TOK_EQ);
        if (match(l, '~')) return make_token(l, TOK_REGEX_MATCH);
        if (match(l, '>')) return make_token(l, TOK_FAT_ARROW);
        return make_token(l, TOK_ASSIGN);

    case '!':
        if (match(l, '=')) return make_token(l, TOK_NEQ);
        return make_token(l, TOK_NOT);

    case '<':
        if (match(l, '=')) return make_token(l, TOK_LTE);
        if (match(l, '(')) return make_token(l, TOK_LT_LPAREN);
        if (match(l, '<')) {
            if (match(l, '<')) return make_token(l, TOK_HEREDOC_STRING);
            return make_token(l, TOK_HEREDOC);
        }
        return make_token(l, TOK_LT);

    case '>':
        if (match(l, '=')) return make_token(l, TOK_GTE);
        if (match(l, '>')) return make_token(l, TOK_APPEND);
        return make_token(l, TOK_GT);

    case '&':
        if (match(l, '&')) return make_token(l, TOK_AND_AND);
        return make_token(l, TOK_AMPERSAND);
    }

    return error_token(l, "unexpected character");
}

Token lexer_peek(Lexer *l) {
    Lexer saved = *l;
    Token t = lexer_next(l);
    *l = saved;
    return t;
}

const char *token_type_name(TokenType t) {
    switch (t) {
    case TOK_INT:        return "integer";
    case TOK_FLOAT:      return "float";
    case TOK_STRING:     return "string";
    case TOK_RAW_STRING: return "raw_string";
    case TOK_TRUE:       return "true";
    case TOK_FALSE:      return "false";
    case TOK_NULL:       return "null";
    case TOK_IDENT:      return "identifier";
    case TOK_LET:        return "let";
    case TOK_MUT:        return "mut";
    case TOK_FN:         return "fn";
    case TOK_IF:         return "if";
    case TOK_ELSE:       return "else";
    case TOK_FOR:        return "for";
    case TOK_IN:         return "in";
    case TOK_WHILE:      return "while";
    case TOK_LOOP:       return "loop";
    case TOK_BREAK:      return "break";
    case TOK_CONTINUE:   return "continue";
    case TOK_RETURN:     return "return";
    case TOK_MATCH:      return "match";
    case TOK_TRY:        return "try";
    case TOK_CATCH:      return "catch";
    case TOK_USE:        return "use";
    case TOK_ERROR_KW:   return "error";
    case TOK_PIPE:       return "|";
    case TOK_BYTE_PIPE:  return "|>";
    case TOK_DOT:        return ".";
    case TOK_DOTDOT:     return "..";
    case TOK_DOTDOTLT:   return "..<";
    case TOK_SPREAD:     return "...";
    case TOK_PLUS:       return "+";
    case TOK_MINUS:      return "-";
    case TOK_STAR:       return "*";
    case TOK_SLASH:      return "/";
    case TOK_PERCENT:    return "%";
    case TOK_EQ:         return "==";
    case TOK_NEQ:        return "!=";
    case TOK_LT:         return "<";
    case TOK_GT:         return ">";
    case TOK_LTE:        return "<=";
    case TOK_GTE:        return ">=";
    case TOK_REGEX_MATCH: return "=~";
    case TOK_AND:        return "and";
    case TOK_OR:         return "or";
    case TOK_NOT:        return "not/!";
    case TOK_ASSIGN:     return "=";
    case TOK_QUESTION:   return "?";
    case TOK_CARET:      return "^";
    case TOK_DOLLAR:     return "$";
    case TOK_FAT_ARROW:  return "=>";
    case TOK_ARROW:      return "->";
    case TOK_AMPERSAND:  return "&";
    case TOK_AND_AND:    return "&&";
    case TOK_OR_OR:      return "||";
    case TOK_APPEND:     return ">>";
    case TOK_TILDE:      return "~";
    case TOK_DOLLAR_LPAREN: return "$(";
    case TOK_LT_LPAREN: return "<(";
    case TOK_HEREDOC:        return "<<";
    case TOK_HEREDOC_STRING: return "<<<";
    case TOK_LPAREN:     return "(";
    case TOK_RPAREN:     return ")";
    case TOK_LBRACE:     return "{";
    case TOK_RBRACE:     return "}";
    case TOK_LBRACKET:   return "[";
    case TOK_RBRACKET:   return "]";
    case TOK_COMMA:      return ",";
    case TOK_COLON:      return ":";
    case TOK_SEMI:       return ";";
    case TOK_NEWLINE:    return "newline";
    case TOK_EOF:        return "EOF";
    case TOK_ERROR:      return "error";
    }
    return "?";
}

char *token_text(const Token *t) {
    char *s = malloc(t->length + 1);
    memcpy(s, t->start, t->length);
    s[t->length] = '\0';
    return s;
}
