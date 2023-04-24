#include <ngx_config.h>
#include <ngx_core.h>

typedef struct
{
    unsigned char *start;
    unsigned char *end;
} buf_t;

typedef enum
{
    PROCESS_OK = 0,
    PROCESS_ERR,
} process_result_t;

process_result_t process_body(buf_t b, ngx_http_cbor_req_ic_ctx_t *ctx);
