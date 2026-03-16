#include "vex.h"

#define MAP_INITIAL_CAP 16
#define MAP_LOAD_FACTOR 0.75

uint32_t vmap_hash(const char *key) {
    uint32_t h = 2166136261u;
    for (; *key; key++) {
        h ^= (uint8_t)*key;
        h *= 16777619u;
    }
    return h;
}

uint32_t vmap_hashn(const char *key, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)key[i];
        h *= 16777619u;
    }
    return h;
}

VexMap vmap_new(void) {
    VexMap m = {0};
    return m;
}

void vmap_free(VexMap *m) {
    if (m->entries) {
        for (size_t i = 0; i < m->cap; i++) {
            if (m->entries[i].occupied) {
                free(m->entries[i].key);
            }
        }
        free(m->entries);
    }
    m->entries = NULL;
    m->cap = 0;
    m->len = 0;
}

static void map_grow(VexMap *m);

void vmap_set(VexMap *m, const char *key, void *value) {
    if (!m->entries || (double)m->len / (double)m->cap >= MAP_LOAD_FACTOR) {
        map_grow(m);
    }

    uint32_t h = vmap_hash(key);
    size_t idx = h & (m->cap - 1);
    uint8_t dist = 0;

    char *new_key = strdup(key);
    void *new_val = value;

    for (;;) {
        MapEntry *e = &m->entries[idx];

        if (!e->occupied) {
            e->key = new_key;
            e->value = new_val;
            e->hash = h;
            e->dist = dist;
            e->occupied = true;
            m->len++;
            return;
        }

        if (e->hash == h && strcmp(e->key, new_key) == 0) {
            free(new_key);
            e->value = new_val;
            return;
        }

        if (dist > e->dist) {

            char *tmp_key = e->key;
            void *tmp_val = e->value;
            uint32_t tmp_hash = e->hash;
            uint8_t tmp_dist = e->dist;

            e->key = new_key;
            e->value = new_val;
            e->hash = h;
            e->dist = dist;

            new_key = tmp_key;
            new_val = tmp_val;
            h = tmp_hash;
            dist = tmp_dist;
        }

        idx = (idx + 1) & (m->cap - 1);
        dist++;
    }
}

void *vmap_get(const VexMap *m, const char *key) {
    if (!m->entries || m->len == 0) return NULL;

    uint32_t h = vmap_hash(key);
    size_t idx = h & (m->cap - 1);

    for (uint8_t dist = 0; ; dist++) {
        const MapEntry *e = &m->entries[idx];
        if (!e->occupied || dist > e->dist) return NULL;
        if (e->hash == h && strcmp(e->key, key) == 0) return e->value;
        idx = (idx + 1) & (m->cap - 1);
    }
}

bool vmap_has(const VexMap *m, const char *key) {
    return vmap_get(m, key) != NULL;
}

void *vmap_remove(VexMap *m, const char *key) {
    if (!m->entries || m->len == 0) return NULL;

    uint32_t h = vmap_hash(key);
    size_t idx = h & (m->cap - 1);

    for (uint8_t dist = 0; ; dist++) {
        MapEntry *e = &m->entries[idx];
        if (!e->occupied || dist > e->dist) return NULL;

        if (e->hash == h && strcmp(e->key, key) == 0) {
            void *val = e->value;
            free(e->key);

            for (;;) {
                size_t next = (idx + 1) & (m->cap - 1);
                MapEntry *ne = &m->entries[next];
                if (!ne->occupied || ne->dist == 0) {
                    m->entries[idx].occupied = false;
                    break;
                }
                m->entries[idx] = *ne;
                m->entries[idx].dist--;
                idx = next;
            }

            m->len--;
            return val;
        }
        idx = (idx + 1) & (m->cap - 1);
    }
}

static void map_grow(VexMap *m) {
    size_t old_cap = m->cap;
    MapEntry *old = m->entries;

    m->cap = old_cap ? old_cap * 2 : MAP_INITIAL_CAP;
    m->entries = calloc(m->cap, sizeof(MapEntry));
    m->len = 0;

    if (old) {
        for (size_t i = 0; i < old_cap; i++) {
            if (old[i].occupied) {

                uint32_t h = old[i].hash;
                size_t idx = h & (m->cap - 1);
                uint8_t dist = 0;

                char *ins_key = old[i].key;
                void *ins_val = old[i].value;

                for (;;) {
                    MapEntry *e = &m->entries[idx];
                    if (!e->occupied) {
                        e->key = ins_key;
                        e->value = ins_val;
                        e->hash = h;
                        e->dist = dist;
                        e->occupied = true;
                        m->len++;
                        break;
                    }
                    if (dist > e->dist) {
                        char *tk = e->key; void *tv = e->value;
                        uint32_t th = e->hash; uint8_t td = e->dist;
                        e->key = ins_key; e->value = ins_val;
                        e->hash = h; e->dist = dist;
                        ins_key = tk; ins_val = tv;
                        h = th; dist = td;
                    }
                    idx = (idx + 1) & (m->cap - 1);
                    dist++;
                }
            }
        }
        free(old);
    }
}

VexMapIter vmap_iter(const VexMap *m) {
    VexMapIter it = {m, 0};
    return it;
}

bool vmap_next(VexMapIter *it, const char **key, void **value) {
    while (it->index < it->map->cap) {
        const MapEntry *e = &it->map->entries[it->index++];
        if (e->occupied) {
            if (key) *key = e->key;
            if (value) *value = e->value;
            return true;
        }
    }
    return false;
}
