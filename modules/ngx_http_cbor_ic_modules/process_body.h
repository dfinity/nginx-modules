#include <ngx_config.h>
#include <ngx_core.h>

typedef struct
{
    unsigned char *start;
    unsigned char *end;
} buf_t;

void process_body(buf_t b, ngx_http_cbor_req_ic_ctx_t *ctx);
