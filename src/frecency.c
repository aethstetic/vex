#include "vex.h"
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define FRECENCY_MAX_ENTRIES 1000
#define FRECENCY_AGING_THRESHOLD 9000.0
#define FRECENCY_AGING_FACTOR 0.9
#define FRECENCY_STALE_DAYS 90

typedef struct {
    char *path;
    double score;
    time_t last_access;
} FrecencyEntry;

typedef struct {
    FrecencyEntry *entries;
    size_t count;
    size_t cap;
} FrecencyDB;

static char *frecency_db_path(void) {
    const char *home = getenv("HOME");
    if (!home) return NULL;

    char dir[4096];
    snprintf(dir, sizeof(dir), "%s/.local/share/vex", home);
    mkdir(dir, 0755);

    char *path = malloc(strlen(home) + 64);
    sprintf(path, "%s/.local/share/vex/frecency.db", home);
    return path;
}

static void frecency_load(FrecencyDB *db) {
    char *path = frecency_db_path();
    if (!path) return;

    FILE *f = fopen(path, "r");
    free(path);
    if (!f) return;

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';

        double score;
        long ts;
        char fpath[4096];
        if (sscanf(line, "%lf|%ld|%4095[^\n]", &score, &ts, fpath) == 3) {
            if (db->count >= db->cap) {
                db->cap = db->cap ? db->cap * 2 : 128;
                db->entries = realloc(db->entries, db->cap * sizeof(FrecencyEntry));
            }
            db->entries[db->count++] = (FrecencyEntry){
                .path = strdup(fpath),
                .score = score,
                .last_access = (time_t)ts,
            };
        }
    }
    fclose(f);
}

static void frecency_save(FrecencyDB *db) {
    char *path = frecency_db_path();
    if (!path) return;

    FILE *f = fopen(path, "w");
    free(path);
    if (!f) return;

    for (size_t i = 0; i < db->count; i++) {
        fprintf(f, "%.2f|%ld|%s\n", db->entries[i].score,
                (long)db->entries[i].last_access, db->entries[i].path);
    }
    fclose(f);
}

static void frecency_free(FrecencyDB *db) {
    for (size_t i = 0; i < db->count; i++)
        free(db->entries[i].path);
    free(db->entries);
}

static double frecency_weight(time_t last_access) {
    time_t now = time(NULL);
    double hours = difftime(now, last_access) / 3600.0;
    if (hours < 1.0) return 4.0;
    if (hours < 24.0) return 2.0;
    if (hours < 7 * 24.0) return 1.0;
    return 0.5;
}

static void frecency_age(FrecencyDB *db) {
    double total = 0;
    for (size_t i = 0; i < db->count; i++)
        total += db->entries[i].score;

    if (total > FRECENCY_AGING_THRESHOLD) {
        for (size_t i = 0; i < db->count; i++)
            db->entries[i].score *= FRECENCY_AGING_FACTOR;
    }

    time_t now = time(NULL);
    size_t write_idx = 0;
    for (size_t i = 0; i < db->count; i++) {
        double days = difftime(now, db->entries[i].last_access) / 86400.0;
        if (db->entries[i].score < 1.0 && days > FRECENCY_STALE_DAYS) {
            free(db->entries[i].path);
            continue;
        }
        db->entries[write_idx++] = db->entries[i];
    }
    db->count = write_idx;
}

void frecency_add(const char *dir) {
    FrecencyDB db = {0};
    frecency_load(&db);

    bool found = false;
    for (size_t i = 0; i < db.count; i++) {
        if (strcmp(db.entries[i].path, dir) == 0) {
            db.entries[i].score += frecency_weight(db.entries[i].last_access);
            db.entries[i].last_access = time(NULL);
            found = true;
            break;
        }
    }

    if (!found) {
        if (db.count >= db.cap) {
            db.cap = db.cap ? db.cap * 2 : 128;
            db.entries = realloc(db.entries, db.cap * sizeof(FrecencyEntry));
        }
        db.entries[db.count++] = (FrecencyEntry){
            .path = strdup(dir),
            .score = 1.0,
            .last_access = time(NULL),
        };
    }

    frecency_age(&db);
    frecency_save(&db);
    frecency_free(&db);
}

char *frecency_find(const char *query) {
    FrecencyDB db = {0};
    frecency_load(&db);

    char *terms[16];
    size_t nterms = 0;
    char *qcopy = strdup(query);
    char *tok = strtok(qcopy, " ");
    while (tok && nterms < 16) {
        terms[nterms++] = tok;
        tok = strtok(NULL, " ");
    }

    double best_score = -1;
    char *best_path = NULL;

    for (size_t i = 0; i < db.count; i++) {

        bool all_match = true;
        for (size_t t = 0; t < nterms; t++) {

            bool found = false;
            const char *hay = db.entries[i].path;
            size_t tlen = strlen(terms[t]);
            size_t hlen = strlen(hay);
            for (size_t h = 0; h + tlen <= hlen; h++) {
                bool match = true;
                for (size_t k = 0; k < tlen; k++) {
                    char a = hay[h+k], b = terms[t][k];
                    if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
                    if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
                    if (a != b) { match = false; break; }
                }
                if (match) { found = true; break; }
            }
            if (!found) { all_match = false; break; }
        }

        if (all_match) {
            double s = db.entries[i].score * frecency_weight(db.entries[i].last_access);
            if (s > best_score) {
                best_score = s;
                free(best_path);
                best_path = strdup(db.entries[i].path);
            }
        }
    }

    free(qcopy);
    frecency_free(&db);
    return best_path;
}

char **frecency_list(size_t *out_count) {
    FrecencyDB db = {0};
    frecency_load(&db);

    if (db.count == 0) {
        frecency_free(&db);
        *out_count = 0;
        return NULL;
    }

    for (size_t i = 1; i < db.count; i++) {
        FrecencyEntry key = db.entries[i];
        double ks = key.score * frecency_weight(key.last_access);
        size_t j = i;
        while (j > 0) {
            double js = db.entries[j-1].score * frecency_weight(db.entries[j-1].last_access);
            if (js >= ks) break;
            db.entries[j] = db.entries[j-1];
            j--;
        }
        db.entries[j] = key;
    }

    char **result = malloc(db.count * sizeof(char *));
    for (size_t i = 0; i < db.count; i++)
        result[i] = strdup(db.entries[i].path);
    *out_count = db.count;

    frecency_free(&db);
    return result;
}
