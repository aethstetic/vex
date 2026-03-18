CC      = cc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -D_POSIX_C_SOURCE=200809L -Iinclude \
          -Wno-format-truncation -Wno-unused-function -Wno-unused-parameter -Wno-stringop-truncation
LDFLAGS = -ldl -lm

SRC = src/main.c \
      src/arena.c \
      src/str.c \
      src/vec.c \
      src/map.c \
      src/utf8.c \
      src/error.c \
      src/value.c \
      src/lexer.c \
      src/parser.c \
      src/env.c \
      src/eval.c \
      src/builtin.c \
      src/edit.c \
      src/format.c \
      src/filter.c \
      src/frecency.c \
      src/plugin.c \
      src/job.c \
      src/undo.c \
      src/help_parse.c

OBJ = $(SRC:.c=.o)
BIN = vex

# Release build
all: CFLAGS += -O2 -DNDEBUG
all: $(BIN)

# Debug build with sanitizers
debug: CFLAGS += -O0 -g -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN)

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
MANDIR  ?= $(PREFIX)/share/man

install: all
	install -Dm755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	@if [ -f doc/vex.1 ]; then \
		install -Dm644 doc/vex.1 $(DESTDIR)$(MANDIR)/man1/vex.1; \
	fi
	@install -dm755 $(DESTDIR)/etc/vex
	@echo ""
	@echo "Installed vex to $(DESTDIR)$(BINDIR)/$(BIN)"
	@echo ""
	@echo "To use as your login shell:"
	@echo "  echo $(DESTDIR)$(BINDIR)/$(BIN) | sudo tee -a /etc/shells"
	@echo "  chsh -s $(DESTDIR)$(BINDIR)/$(BIN)"
	@echo ""

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	rm -f $(DESTDIR)$(MANDIR)/man1/vex.1

test: all
	@./tests/run.sh $(FILTER)

.PHONY: all debug clean install uninstall test
