#include "cb0r.h"
#include "ic.h"
#include "identifier.h"

typedef struct
{
    ngx_str_t request_type;
    ngx_str_t method_name;
    ngx_str_t canister_id;
    ngx_str_t sender;

    unsigned char done : 1;
} ngx_http_cbor_req_ic_ctx_t;

typedef enum
{
    CONSUME_OK = 0,
    CONSUME_ERR,
    CONSUME_EINFILE,
    CONSUME_EEMPTY,
} consume_result_t;

typedef struct
{
    unsigned char *start;
    unsigned char *end;
} buf_t;

void process_body(buf_t b, ngx_http_cbor_req_ic_ctx_t *ctx);
