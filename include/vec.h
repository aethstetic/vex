#ifndef VEX_VEC_H
#define VEX_VEC_H

#define VEX_VEC(T) struct { T *data; size_t len; size_t cap; }

#define vvec_init(v) do { \
    (v).data = NULL; \
    (v).len = 0; \
    (v).cap = 0; \
} while(0)

#define vvec_free(v) do { \
    free((v).data); \
    (v).data = NULL; \
    (v).len = 0; \
    (v).cap = 0; \
} while(0)

#define vvec_grow(v) do { \
    (v).cap = (v).cap ? (v).cap * 2 : 8; \
    (v).data = realloc((v).data, (v).cap * sizeof(*(v).data)); \
} while(0)

#define vvec_push(v, item) do { \
    if ((v).len >= (v).cap) vvec_grow(v); \
    (v).data[(v).len++] = (item); \
} while(0)

#define vvec_get(v, i) ((v).data[(i)])
#define vvec_last(v) ((v).data[(v).len - 1])

#define vvec_pop(v) ((v).data[--(v).len])

#define vvec_clear(v) do { (v).len = 0; } while(0)

#define vvec_reserve(v, n) do { \
    while ((v).cap < (n)) vvec_grow(v); \
} while(0)

typedef struct {
    void **data;
    size_t len;
    size_t cap;
} VexVec;

void  vexvec_init(VexVec *v);
void  vexvec_free(VexVec *v);
void  vexvec_push(VexVec *v, void *item);
void *vexvec_get(VexVec *v, size_t i);
void *vexvec_pop(VexVec *v);
void  vexvec_clear(VexVec *v);

#endif
