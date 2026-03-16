#ifndef VEX_VALUE_H
#define VEX_VALUE_H

/* Runtime type tag for VexValue. */
typedef enum {
    VEX_VAL_NULL,
    VEX_VAL_BOOL,
    VEX_VAL_INT,
    VEX_VAL_FLOAT,
    VEX_VAL_STRING,
    VEX_VAL_LIST,
    VEX_VAL_RECORD,
    VEX_VAL_CLOSURE,
    VEX_VAL_STREAM,
    VEX_VAL_BYTES,
    VEX_VAL_ERROR,
    VEX_VAL_RANGE,
} VexType;

/* Refcounted tagged union holding any vex runtime value. */
struct VexValue {
    VexType type;
    uint32_t refcount;
    union {
        bool boolean;
        int64_t integer;
        double floating;
        VexStr string;
        VexVec list;
        VexMap record;
        struct {
            ASTNode *params;
            ASTNode *body;
            Scope *env;
            size_t param_count;
        } closure;
        struct {
            uint8_t *data;
            size_t len;
        } bytes;
        VexError *error;
        struct {
            int64_t start;
            int64_t end;
            bool exclusive;
        } range;
    };
};

VexValue *vval_null(void);
VexValue *vval_bool(bool b);
VexValue *vval_int(int64_t n);
VexValue *vval_float(double f);
VexValue *vval_string(VexStr s);
VexValue *vval_string_cstr(const char *s);
VexValue *vval_list(void);
VexValue *vval_record(void);
VexValue *vval_error(const char *msg);
VexValue *vval_range(int64_t start, int64_t end, bool exclusive);

VexValue *vval_retain(VexValue *v);
void      vval_release(VexValue *v);

void      vval_list_push(VexValue *list, VexValue *item);
VexValue *vval_list_get(VexValue *list, size_t i);
size_t    vval_list_len(VexValue *list);

void      vval_record_set(VexValue *rec, const char *key, VexValue *val);
VexValue *vval_record_get(VexValue *rec, const char *key);
bool      vval_record_has(VexValue *rec, const char *key);

const char *vval_type_name(VexType t);

void vval_print(VexValue *v, FILE *out);

VexStr vval_to_str(VexValue *v);

bool vval_truthy(VexValue *v);
bool vval_equal(VexValue *a, VexValue *b);

#endif
