#ifndef VEX_LEXER_H
#define VEX_LEXER_H

typedef enum {

    TOK_INT, TOK_FLOAT, TOK_STRING, TOK_RAW_STRING,
    TOK_TRUE, TOK_FALSE, TOK_NULL,

    TOK_IDENT,
    TOK_LET, TOK_MUT, TOK_FN,
    TOK_IF, TOK_ELSE,
    TOK_FOR, TOK_IN, TOK_WHILE, TOK_LOOP,
    TOK_BREAK, TOK_CONTINUE, TOK_RETURN,
    TOK_MATCH, TOK_TRY, TOK_CATCH,
    TOK_USE, TOK_ERROR_KW,

    TOK_PIPE,
    TOK_BYTE_PIPE,
    TOK_DOT,
    TOK_DOTDOT,
    TOK_DOTDOTLT,
    TOK_SPREAD,
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH, TOK_PERCENT,
    TOK_EQ, TOK_NEQ, TOK_LT, TOK_GT, TOK_LTE, TOK_GTE,
    TOK_REGEX_MATCH,
    TOK_AND, TOK_OR, TOK_NOT,
    TOK_ASSIGN,
    TOK_QUESTION,
    TOK_CARET,
    TOK_DOLLAR,
    TOK_FAT_ARROW,
    TOK_ARROW,
    TOK_AMPERSAND,
    TOK_AND_AND,
    TOK_OR_OR,
    TOK_APPEND,
    TOK_TILDE,
    TOK_AT,
    TOK_DOLLAR_LPAREN,
    TOK_LT_LPAREN,
    TOK_HEREDOC,
    TOK_HEREDOC_STRING,

    TOK_LPAREN, TOK_RPAREN,
    TOK_LBRACE, TOK_RBRACE,
    TOK_LBRACKET, TOK_RBRACKET,
    TOK_COMMA, TOK_COLON, TOK_SEMI,
    TOK_NEWLINE,

    TOK_EOF,
    TOK_ERROR,
} TokenType;

struct Token {
    TokenType type;
    const char *start;
    uint32_t length;
    uint32_t line;
    uint16_t col;
};

struct Lexer {
    const char *source;
    const char *current;
    const char *start;
    uint32_t line;
    uint16_t col;
    bool at_eof;
};

Lexer  lexer_init(const char *source);
Token  lexer_next(Lexer *l);
Token  lexer_peek(Lexer *l);

const char *token_type_name(TokenType t);

char *token_text(const Token *t);

#endif
