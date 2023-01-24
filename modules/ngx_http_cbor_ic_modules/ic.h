#ifndef IC_H
#define IC_H

#include "cb0r.h"
#include <ngx_core.h>

#define CBOR_MAGIC_LEN 3

#define CBOR_MAGIC_0 0xD9
#define CBOR_MAGIC_1 0xD9
#define CBOR_MAGIC_2 0xF7

typedef enum
{
    PARSE_OK = 0,
    PARSE_ERR,
} parse_result_t;

parse_result_t parse_str(cb0r_t in, uint skip, ngx_str_t *s);
parse_result_t parse_int(cb0r_t in, uint skip, ngx_int_t *i);
cb0r_s get_key(cb0r_t r, u_char *key);

#endif // IC_H
