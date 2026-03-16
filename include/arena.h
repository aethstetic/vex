#ifndef VEX_ARENA_H
#define VEX_ARENA_H

#define VEX_ARENA_BLOCK_SIZE (64 * 1024)

typedef struct ArenaBlock {
    struct ArenaBlock *next;
    size_t used;
    size_t cap;
    char data[];
} ArenaBlock;

struct VexArena {
    ArenaBlock *head;
    ArenaBlock *current;
};

VexArena *arena_create(void);
void     *arena_alloc(VexArena *a, size_t size);
char     *arena_strdup(VexArena *a, const char *s);
char     *arena_strndup(VexArena *a, const char *s, size_t n);
void      arena_reset(VexArena *a);
void      arena_destroy(VexArena *a);

#endif
