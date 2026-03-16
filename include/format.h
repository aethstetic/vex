#ifndef VEX_FORMAT_H
#define VEX_FORMAT_H

VexValue *format_from_json(const char *src, size_t len);
VexStr    format_to_json(VexValue *v, bool pretty);

VexValue *format_from_csv(const char *src, size_t len);
VexStr    format_to_csv(VexValue *v);

VexValue *format_from_toml(const char *src, size_t len);
VexStr    format_to_toml(VexValue *v);

#endif
