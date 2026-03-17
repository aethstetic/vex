/* Master include: forward declarations and all vex headers. */
#ifndef VEX_H
#define VEX_H

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

typedef struct VexArena VexArena;
typedef struct VexStr VexStr;
typedef struct VexMap VexMap;
typedef struct VexValue VexValue;
typedef struct ASTNode ASTNode;
typedef struct Scope Scope;
typedef struct EvalCtx EvalCtx;
typedef struct Token Token;
typedef struct Lexer Lexer;
typedef struct Parser Parser;

#include "arena.h"
#include "str.h"
#include "vec.h"
#include "utf8.h"
#include "map.h"
#include "error.h"
#include "value.h"
#include "lexer.h"
#include "ast.h"
#include "parser.h"
#include "env.h"
#include "builtin.h"
#include "undo.h"
#include "eval.h"
#include "format.h"
#include "filter.h"
#include "frecency.h"
#include "plugin.h"
#include "job.h"
#include "edit.h"

#endif
