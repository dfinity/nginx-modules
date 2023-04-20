#include "ngx_http_cbor_req_ic_module.h"

static void nullify_str(ngx_str_t *s)
{
    s->data = NULL;
    s->len = 0;
}

void process_body(buf_t b, ngx_http_cbor_req_ic_ctx_t *ctx);
