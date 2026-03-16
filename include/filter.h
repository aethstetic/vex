#ifndef VEX_FILTER_H
#define VEX_FILTER_H

double filter_score(const char *query, const char *candidate);

int filter_run(char **items, size_t count, bool multi, bool *selected_out);

char *filter_select(char **items, size_t count);

#endif
