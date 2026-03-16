#include "vex.h"

void vexvec_init(VexVec *v) {
    v->data = NULL;
    v->len = 0;
    v->cap = 0;
}

void vexvec_free(VexVec *v) {
    free(v->data);
    v->data = NULL;
    v->len = 0;
    v->cap = 0;
}

void vexvec_push(VexVec *v, void *item) {
    if (v->len >= v->cap) {
        v->cap = v->cap ? v->cap * 2 : 8;
        v->data = realloc(v->data, v->cap * sizeof(void *));
    }
    v->data[v->len++] = item;
}

void *vexvec_get(VexVec *v, size_t i) {
    if (i >= v->len) return NULL;
    return v->data[i];
}

void *vexvec_pop(VexVec *v) {
    if (v->len == 0) return NULL;
    return v->data[--v->len];
}

void vexvec_clear(VexVec *v) {
    v->len = 0;
}
