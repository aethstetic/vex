#ifndef VEX_MAP_H
#define VEX_MAP_H

typedef struct {
    char *key;
    void *value;
    uint32_t hash;
    uint8_t dist;
    bool occupied;
} MapEntry;

struct VexMap {
    MapEntry *entries;
    size_t cap;
    size_t len;
};

VexMap  vmap_new(void);
void    vmap_free(VexMap *m);

void   *vmap_get(const VexMap *m, const char *key);
bool    vmap_has(const VexMap *m, const char *key);
void    vmap_set(VexMap *m, const char *key, void *value);
void   *vmap_remove(VexMap *m, const char *key);

typedef struct {
    const VexMap *map;
    size_t index;
} VexMapIter;

VexMapIter vmap_iter(const VexMap *m);
bool       vmap_next(VexMapIter *it, const char **key, void **value);

uint32_t vmap_hash(const char *key);
uint32_t vmap_hashn(const char *key, size_t len);

#endif
