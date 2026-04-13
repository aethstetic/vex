#ifndef VEX_ARENA_H
#define VEX_ARENA_H

#define VEX_ARENA_BLOCK_SIZE (64 * 1024)

typedef struct ArenaBlock {
    struct ArenaBlock *next;
    size_t used;
    size_t cap;
    char data[];
} ArenaBlock;

struct VexValue;

struct VexArena {
    ArenaBlock *head;
    ArenaBlock *current;
    struct VexValue **tracked_vals;
    size_t tracked_count;
    size_t tracked_cap;
};

VexArena *arena_create(void);
void     *arena_alloc(VexArena *a, size_t size);
char     *arena_strdup(VexArena *a, const char *s);
char     *arena_strndup(VexArena *a, const char *s, size_t n);
void      arena_reset(VexArena *a);
void      arena_destroy(VexArena *a);
struct VexValue *arena_track_value(VexArena *a, struct VexValue *v);

void *vex_xmalloc(size_t size);
void *vex_xrealloc(void *ptr, size_t size);
void *vex_xcalloc(size_t nmemb, size_t size);

#endif
