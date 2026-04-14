#ifndef VEX_UNDO_H
#define VEX_UNDO_H

#include <time.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    UNDO_RM,
    UNDO_MV,
    UNDO_CP,
} UndoKind;

typedef struct {
    UndoKind kind;
    char *original_path;
    char *trash_path;
    char *dest_path;
    time_t timestamp;
} UndoEntry;

#define UNDO_STACK_MAX 64

void undo_init(void);
void undo_free(void);
void undo_push_rm(const char *original, const char *trash, time_t ts);
void undo_push_mv(const char *src, const char *dst, time_t ts);
void undo_push_cp(const char *dst, time_t ts);
bool undo_pop(char *msg, size_t msg_len);
size_t undo_count(void);
const UndoEntry *undo_get(size_t i);
const char *undo_get_trash_dir(void);

#define UNDO_TRASH_RETENTION_SECS (7 * 24 * 60 * 60)

size_t undo_purge_trash(time_t cutoff);
size_t undo_empty_trash(void);

typedef struct {
    char *name;
    char *full_path;
    time_t deleted_at;
    off_t size;
    bool is_dir;
} TrashItem;

size_t     undo_list_trash(TrashItem **out);
void       undo_free_trash_list(TrashItem *items, size_t n);

#endif
