#ifndef VEX_PARSER_H
#define VEX_PARSER_H

struct Parser {
    Lexer lexer;
    Token current;
    Token previous;
    VexArena *arena;
    bool had_error;
    bool panic_mode;
    char *error_msg;
    int alias_depth;
};

Parser  parser_init(const char *source, VexArena *arena);
ASTNode *parser_parse(Parser *p);
ASTNode *parser_parse_line(Parser *p);

#endif
