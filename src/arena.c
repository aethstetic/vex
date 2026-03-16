#include "vex.h"

static ArenaBlock *block_new(size_t cap) {
    ArenaBlock *b = malloc(sizeof(ArenaBlock) + cap);
    if (!b) {
        fprintf(stderr, "vex: out of memory\n");
        exit(1);
    }
    b->next = NULL;
    b->used = 0;
    b->cap = cap;
    return b;
}

VexArena *arena_create(void) {
    VexArena *a = malloc(sizeof(VexArena));
    if (!a) {
        fprintf(stderr, "vex: out of memory\n");
        exit(1);
    }
    a->head = block_new(VEX_ARENA_BLOCK_SIZE);
    a->current = a->head;
    return a;
}

void *arena_alloc(VexArena *a, size_t size) {

    size = (size + 7) & ~(size_t)7;

    if (a->current->used + size > a->current->cap) {
        size_t cap = size > VEX_ARENA_BLOCK_SIZE ? size : VEX_ARENA_BLOCK_SIZE;
        ArenaBlock *b = block_new(cap);
        a->current->next = b;
        a->current = b;
    }
    void *ptr = a->current->data + a->current->used;
    a->current->used += size;
    return ptr;
}

char *arena_strdup(VexArena *a, const char *s) {
    size_t len = strlen(s);
    char *dup = arena_alloc(a, len + 1);
    memcpy(dup, s, len + 1);
    return dup;
}

char *arena_strndup(VexArena *a, const char *s, size_t n) {
    char *dup = arena_alloc(a, n + 1);
    memcpy(dup, s, n);
    dup[n] = '\0';
    return dup;
}

void arena_reset(VexArena *a) {
    ArenaBlock *b = a->head;
    while (b) {
        b->used = 0;
        b = b->next;
    }
    a->current = a->head;
}

void arena_destroy(VexArena *a) {
    ArenaBlock *b = a->head;
    while (b) {
        ArenaBlock *next = b->next;
        free(b);
        b = next;
    }
    free(a);
}
