#ifndef VEX_FRECENCY_H
#define VEX_FRECENCY_H

void frecency_add(const char *dir);

char *frecency_find(const char *query);

char **frecency_list(size_t *out_count);

#endif
