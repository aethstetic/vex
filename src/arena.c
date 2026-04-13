#include "vex.h"

void *vex_xmalloc(size_t size) {
    void *p = malloc(size);
    if (!p) { fprintf(stderr, "vex: out of memory\n"); exit(1); }
    return p;
}

void *vex_xrealloc(void *ptr, size_t size) {
    void *p = realloc(ptr, size);
    if (!p) { fprintf(stderr, "vex: out of memory\n"); exit(1); }
    return p;
}

void *vex_xcalloc(size_t nmemb, size_t size) {
    void *p = calloc(nmemb, size);
    if (!p) { fprintf(stderr, "vex: out of memory\n"); exit(1); }
    return p;
}

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
    a->tracked_vals = NULL;
    a->tracked_count = 0;
    a->tracked_cap = 0;
    return a;
}

VexValue *arena_track_value(VexArena *a, VexValue *v) {
    if (!v) return v;
    if (a->tracked_count >= a->tracked_cap) {
        size_t new_cap = a->tracked_cap ? a->tracked_cap * 2 : 32;
        VexValue **n = realloc(a->tracked_vals, new_cap * sizeof(VexValue *));
        if (!n) {
            fprintf(stderr, "vex: out of memory\n");
            exit(1);
        }
        a->tracked_vals = n;
        a->tracked_cap = new_cap;
    }
    a->tracked_vals[a->tracked_count++] = v;
    return v;
}

static void arena_release_tracked(VexArena *a) {
    for (size_t i = 0; i < a->tracked_count; i++) {
        vval_release(a->tracked_vals[i]);
    }
    a->tracked_count = 0;
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
    arena_release_tracked(a);
    ArenaBlock *b = a->head;
    while (b) {
        b->used = 0;
        b = b->next;
    }
    a->current = a->head;
}

void arena_destroy(VexArena *a) {
    arena_release_tracked(a);
    free(a->tracked_vals);
    ArenaBlock *b = a->head;
    while (b) {
        ArenaBlock *next = b->next;
        free(b);
        b = next;
    }
    free(a);
}
