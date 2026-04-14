#include "vex.h"
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

static bool undo_copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) return false;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return false; }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0)
        fwrite(buf, 1, n, out);
    fclose(in);
    fclose(out);
    return true;
}

static UndoEntry undo_stack[UNDO_STACK_MAX];
static size_t undo_cnt = 0;
static char trash_dir[4096];
static bool trash_dir_ready = false;

void undo_init(void) {
    undo_cnt = 0;
    trash_dir_ready = false;
    time_t now = time(NULL);
    undo_purge_trash(now - UNDO_TRASH_RETENTION_SECS);
}

void undo_free(void) {
    for (size_t i = 0; i < undo_cnt; i++) {
        free(undo_stack[i].original_path);
        free(undo_stack[i].trash_path);
        free(undo_stack[i].dest_path);
    }
    undo_cnt = 0;
}

const char *undo_get_trash_dir(void) {
    if (trash_dir_ready) return trash_dir;

    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(trash_dir, sizeof(trash_dir), "%s/.local/share/vex/trash", home);

    char tmp[4096];
    snprintf(tmp, sizeof(tmp), "%s/.local", home);
    mkdir(tmp, 0755);
    snprintf(tmp, sizeof(tmp), "%s/.local/share", home);
    mkdir(tmp, 0755);
    snprintf(tmp, sizeof(tmp), "%s/.local/share/vex", home);
    mkdir(tmp, 0755);
    mkdir(trash_dir, 0755);

    trash_dir_ready = true;
    return trash_dir;
}

static void evict_oldest(void) {
    if (undo_stack[0].kind == UNDO_RM && undo_stack[0].trash_path) {
        unlink(undo_stack[0].trash_path);
    }
    free(undo_stack[0].original_path);
    free(undo_stack[0].trash_path);
    free(undo_stack[0].dest_path);
    memmove(undo_stack, undo_stack + 1, (undo_cnt - 1) * sizeof(UndoEntry));
    undo_cnt--;
}

static void push_entry(UndoEntry *e) {
    if (undo_cnt >= UNDO_STACK_MAX) evict_oldest();
    undo_stack[undo_cnt++] = *e;
}

void undo_push_rm(const char *original, const char *trash, time_t ts) {
    UndoEntry e = {0};
    e.kind = UNDO_RM;
    e.original_path = strdup(original);
    e.trash_path = strdup(trash);
    e.timestamp = ts;
    push_entry(&e);
}

void undo_push_mv(const char *src, const char *dst, time_t ts) {
    UndoEntry e = {0};
    e.kind = UNDO_MV;
    e.original_path = strdup(src);
    e.dest_path = strdup(dst);
    e.timestamp = ts;
    push_entry(&e);
}

void undo_push_cp(const char *dst, time_t ts) {
    UndoEntry e = {0};
    e.kind = UNDO_CP;
    e.dest_path = strdup(dst);
    e.timestamp = ts;
    push_entry(&e);
}

bool undo_pop(char *msg, size_t msg_len) {
    if (undo_cnt == 0) {
        snprintf(msg, msg_len, "nothing to undo");
        return false;
    }

    UndoEntry *e = &undo_stack[undo_cnt - 1];
    time_t group_ts = e->timestamp;
    bool ok = true;
    size_t restored = 0;
    msg[0] = '\0';

    /* Grouped: pop all entries with same timestamp */
    while (undo_cnt > 0 && undo_stack[undo_cnt - 1].timestamp == group_ts) {
        e = &undo_stack[undo_cnt - 1];

        switch (e->kind) {
        case UNDO_RM: {
            struct stat st;
            if (stat(e->original_path, &st) == 0) {
                snprintf(msg, msg_len, "undo: %s already exists, not overwriting",
                         e->original_path);
                ok = false;
                goto done;
            }
            if (rename(e->trash_path, e->original_path) != 0) {
                if (errno == EXDEV) {
                    /* EXDEV: cross-device fallback */
                    if (!undo_copy_file(e->trash_path, e->original_path)) {
                        snprintf(msg, msg_len, "undo: failed to restore %s: %s",
                                 e->original_path, strerror(errno));
                        ok = false;
                        goto done;
                    }
                    unlink(e->trash_path);
                } else {
                    snprintf(msg, msg_len, "undo: failed to restore %s: %s",
                             e->original_path, strerror(errno));
                    ok = false;
                    goto done;
                }
            }
            if (restored == 0)
                snprintf(msg, msg_len, "restored %s", e->original_path);
            restored++;
            break;
        }
        case UNDO_MV: {
            if (rename(e->dest_path, e->original_path) != 0) {
                if (errno == EXDEV) {
                    if (!undo_copy_file(e->dest_path, e->original_path)) {
                        snprintf(msg, msg_len, "undo: failed to move %s back: %s",
                                 e->dest_path, strerror(errno));
                        ok = false;
                        goto done;
                    }
                    unlink(e->dest_path);
                } else {
                    snprintf(msg, msg_len, "undo: failed to move %s back to %s: %s",
                             e->dest_path, e->original_path, strerror(errno));
                    ok = false;
                    goto done;
                }
            }
            snprintf(msg, msg_len, "undo: moved %s back to %s",
                     e->dest_path, e->original_path);
            restored++;
            break;
        }
        case UNDO_CP: {
            if (unlink(e->dest_path) != 0) {
                snprintf(msg, msg_len, "undo: failed to remove copy %s: %s",
                         e->dest_path, strerror(errno));
                ok = false;
                goto done;
            }
            snprintf(msg, msg_len, "undo: removed copy %s", e->dest_path);
            restored++;
            break;
        }
        }

        free(e->original_path);
        free(e->trash_path);
        free(e->dest_path);
        e->original_path = NULL;
        e->trash_path = NULL;
        e->dest_path = NULL;
        undo_cnt--;
    }

    if (restored > 1) {
        snprintf(msg, msg_len, "undo: restored %zu files", restored);
    }

done:
    return ok;
}

size_t undo_count(void) {
    return undo_cnt;
}

const UndoEntry *undo_get(size_t i) {
    if (i >= undo_cnt) return NULL;
    return &undo_stack[i];
}

static bool remove_path_recursive(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return errno == ENOENT;
    if (!S_ISDIR(st.st_mode)) {
        return unlink(path) == 0 || errno == ENOENT;
    }
    DIR *d = opendir(path);
    if (!d) return false;
    struct dirent *ent;
    bool ok = true;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) continue;
        char child[4096];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        if (!remove_path_recursive(child)) ok = false;
    }
    closedir(d);
    if (rmdir(path) != 0 && errno != ENOENT) ok = false;
    return ok;
}

static bool parse_trash_prefix(const char *name, time_t *ts_out) {
    char *end = NULL;
    long ts = strtol(name, &end, 10);
    if (end == name || *end != '_') return false;
    *ts_out = (time_t)ts;
    return true;
}

static void drop_stack_entries_matching_prefix(const char *tdir) {
    size_t w = 0;
    size_t tdir_len = strlen(tdir);
    for (size_t r = 0; r < undo_cnt; r++) {
        UndoEntry *e = &undo_stack[r];
        bool in_trash = e->kind == UNDO_RM && e->trash_path &&
                        strncmp(e->trash_path, tdir, tdir_len) == 0;
        if (in_trash) {
            free(e->original_path);
            free(e->trash_path);
            free(e->dest_path);
        } else if (w != r) {
            undo_stack[w++] = *e;
        } else {
            w++;
        }
    }
    undo_cnt = w;
}

size_t undo_purge_trash(time_t cutoff) {
    const char *tdir = undo_get_trash_dir();
    if (!tdir) return 0;
    DIR *d = opendir(tdir);
    if (!d) return 0;

    size_t removed = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        time_t ts;
        if (!parse_trash_prefix(ent->d_name, &ts)) continue;
        if (ts >= cutoff) continue;

        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", tdir, ent->d_name);
        if (remove_path_recursive(full)) removed++;
    }
    closedir(d);
    return removed;
}

size_t undo_empty_trash(void) {
    const char *tdir = undo_get_trash_dir();
    if (!tdir) return 0;
    DIR *d = opendir(tdir);
    if (!d) return 0;

    size_t removed = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", tdir, ent->d_name);
        if (remove_path_recursive(full)) removed++;
    }
    closedir(d);

    drop_stack_entries_matching_prefix(tdir);
    return removed;
}

static off_t path_size(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    if (S_ISREG(st.st_mode)) return st.st_size;
    if (!S_ISDIR(st.st_mode)) return 0;

    off_t total = 0;
    DIR *d = opendir(path);
    if (!d) return 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0'))) continue;
        char child[4096];
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        total += path_size(child);
    }
    closedir(d);
    return total;
}

size_t undo_list_trash(TrashItem **out) {
    *out = NULL;
    const char *tdir = undo_get_trash_dir();
    if (!tdir) return 0;
    DIR *d = opendir(tdir);
    if (!d) return 0;

    size_t cap = 0, cnt = 0;
    TrashItem *items = NULL;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        time_t ts;
        if (!parse_trash_prefix(ent->d_name, &ts)) continue;

        char full[4096];
        snprintf(full, sizeof(full), "%s/%s", tdir, ent->d_name);
        struct stat st;
        if (lstat(full, &st) != 0) continue;

        if (cnt >= cap) {
            cap = cap ? cap * 2 : 16;
            items = vex_xrealloc(items, cap * sizeof(TrashItem));
        }
        const char *underscore = strchr(ent->d_name, '_');
        const char *display = underscore ? underscore + 1 : ent->d_name;
        items[cnt].name = strdup(display);
        items[cnt].full_path = strdup(full);
        items[cnt].deleted_at = ts;
        items[cnt].is_dir = S_ISDIR(st.st_mode);
        items[cnt].size = items[cnt].is_dir ? path_size(full) : st.st_size;
        cnt++;
    }
    closedir(d);
    *out = items;
    return cnt;
}

void undo_free_trash_list(TrashItem *items, size_t n) {
    for (size_t i = 0; i < n; i++) {
        free(items[i].name);
        free(items[i].full_path);
    }
    free(items);
}
