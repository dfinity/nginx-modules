#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "cb0r.h"
#include "ic.h"

typedef struct
{
    ngx_str_t status;
    ngx_str_t error_code;
    ngx_int_t reject_code;
    ngx_str_t reject_message;
} ngx_http_cbor_resp_ic_ctx_t;

static ngx_int_t ngx_http_cbor_resp_ic_output_body_filter(ngx_http_request_t *r, ngx_chain_t *in);
static ngx_int_t ngx_http_cbor_resp_ic_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_cbor_resp_ic_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_cbor_resp_ic_cbor_ic_status(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_cbor_resp_ic_cbor_ic_error_code(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_cbor_resp_ic_cbor_ic_reject_code(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_cbor_resp_ic_cbor_ic_reject_message(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_http_variable_t ngx_http_cbor_resp_ic_vars[] = {
    {ngx_string("cbor_resp_ic_status"), NULL, ngx_http_cbor_resp_ic_cbor_ic_status, 0, 0, 0},
    {ngx_string("cbor_resp_ic_error_code"), NULL, ngx_http_cbor_resp_ic_cbor_ic_error_code, 0, 0, 0},
    {ngx_string("cbor_resp_ic_reject_code"), NULL, ngx_http_cbor_resp_ic_cbor_ic_reject_code, 0, 0, 0},
    {ngx_string("cbor_resp_ic_reject_message"), NULL, ngx_http_cbor_resp_ic_cbor_ic_reject_message, 0, 0, 0},
    ngx_http_null_variable};

static ngx_http_module_t ngx_http_cbor_resp_ic_ctx = {
    ngx_http_cbor_resp_ic_add_variables, /* preconfiguration */
    ngx_http_cbor_resp_ic_init,          /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

ngx_module_t ngx_http_cbor_resp_ic_module = {
    NGX_MODULE_V1,
    &ngx_http_cbor_resp_ic_ctx, /* module context */
    NULL,                       /* module directives */
    NGX_HTTP_MODULE,            /* module type */
    NULL,                       /* init master */
    NULL,                       /* init module */
    NULL,                       /* init process */
    NULL,                       /* init thread */
    NULL,                       /* exit thread */
    NULL,                       /* exit process */
    NULL,                       /* exit master */
    NGX_MODULE_V1_PADDING};

typedef struct
{
    u_char *start;
    u_char *end;
} buf_t;

typedef enum
{
    PROCESS_OK = 0,
    PROCESS_ERR,
} process_result_t;

// process_body extracts relevant CBOR fields from the given body
//
// schema {
//     "status": str,
//     "error_code": str,
//     "reject_code": int,
//     "reject_message": str
// }
static process_result_t
process_body(buf_t b, ngx_http_cbor_resp_ic_ctx_t *ctx)
{
    // Skip magic number
    if ((b.end - b.start) > CBOR_MAGIC_LEN && (b.start[0] == CBOR_MAGIC_0 &&
                                               b.start[1] == CBOR_MAGIC_1 &&
                                               b.start[2] == CBOR_MAGIC_2))
    {
        b.start += CBOR_MAGIC_LEN;
    }

    // Root
    cb0r_s s = {
        .type = CB0R_DATA,
        .start = b.start,
        .end = b.end,
        .length = b.end - b.start};

    cb0r_s root = {0};
    cb0r(
        s.start + s.header, // start
        s.end,              // stop
        0,                  // skip
        &root               // result
    );

    // Status
    cb0r_s status_c = get_key(&root, "status");
    if (status_c.type != CB0R_UTF8)
        return PROCESS_ERR;

    ngx_str_t status;
    if (parse_str(&status_c, 0, &status) != PARSE_OK)
        return PROCESS_ERR;

    ctx->status = status;

    // Error code
    cb0r_s error_code_c = get_key(&root, "error_code");
    if (error_code_c.type != CB0R_UTF8)
        return PROCESS_ERR;

    ngx_str_t error_code;
    if (parse_str(&error_code_c, 0, &error_code) != PARSE_OK)
        return PROCESS_ERR;

    ctx->error_code = error_code;

    // Reject code
    cb0r_s reject_code_c = get_key(&root, "reject_code");
    if (reject_code_c.type != CB0R_INT)
        return PROCESS_ERR;

    ngx_int_t reject_code;
    if (parse_int(&reject_code_c, 0, &reject_code) != PARSE_OK)
        return PROCESS_ERR;

    ctx->reject_code = reject_code;

    // Reject message
    cb0r_s reject_message_c = get_key(&root, "reject_message");
    if (reject_message_c.type != CB0R_UTF8)
        return PROCESS_ERR;

    ngx_str_t reject_message;
    if (parse_str(&reject_message_c, 0, &reject_message) != PARSE_OK)
        return PROCESS_ERR;

    ctx->reject_message = reject_message;

    return PROCESS_OK;
}

typedef enum
{
    CONSUME_OK = 0,
    CONSUME_ERR,
    CONSUME_EINFILE,
    CONSUME_EEMPTY,
} consume_result_t;

static consume_result_t
consume_body(ngx_pool_t *p, ngx_chain_t *bufs, buf_t *buf)
{
    // Skip in-file buffers
    if (bufs->buf->in_file)
        return CONSUME_EINFILE;

    // Skip empty buffers
    if (ngx_buf_size(bufs->buf) == 0)
        return CONSUME_EEMPTY;

    // Case 1 - Single buffer
    if (bufs->next == NULL)
    {
        // Set buffer
        buf->start = bufs->buf->pos;
        buf->end = bufs->buf->last;

        return CONSUME_OK;
    }

    // Case 2 - Multiple buffers
    // Get content-length
    size_t len = 0;
    for (ngx_chain_t *c = bufs; c; c = c->next)
        len += ngx_buf_size(c->buf);

    u_char *b = ngx_palloc(p, len);
    if (b == NULL)
        return CONSUME_ERR;

    // Copy body to single buffer
    u_char *ptr = b;
    for (ngx_chain_t *c = bufs; c; c = c->next)
    {
        ptr = ngx_copy(
            ptr,                 // dst
            c->buf->pos,         // src
            ngx_buf_size(c->buf) // n
        );
    }

    // Set buffer
    buf->start = b;
    buf->end = b + len;

    return CONSUME_OK;
}

static void nullify_str(ngx_str_t *s)
{
    s->data = NULL;
    s->len = 0;
}

static ngx_http_cbor_resp_ic_ctx_t *mk_ctx(ngx_http_request_t *r)
{
    ngx_http_cbor_resp_ic_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_cbor_resp_ic_module);

    if (ctx == NULL)
    {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_cbor_resp_ic_ctx_t));
        if (ctx == NULL)
            return NULL;

        nullify_str(&ctx->status);
        nullify_str(&ctx->error_code);
        ctx->reject_code = 0;
        nullify_str(&ctx->reject_message);

        ngx_http_set_ctx(r, ctx, ngx_http_cbor_resp_ic_module);
    }

    return ctx;
}

static void
process_response(ngx_http_request_t *r, ngx_chain_t *in)
{
    buf_t b;
    if (consume_body(
            r->pool,
            in,
            &b) != CONSUME_OK)
        return;

    ngx_http_cbor_resp_ic_ctx_t *ctx = mk_ctx(r);
    if (ctx == NULL)
        return;

    if (process_body(b, ctx) != PROCESS_OK)
        return;
}

static ngx_http_output_body_filter_pt ngx_http_next_output_body_filter;

static ngx_int_t
ngx_http_cbor_resp_ic_output_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    process_response(r, in);
    return ngx_http_next_output_body_filter(r, in);
}

static ngx_int_t
ngx_http_cbor_resp_ic_cbor_ic_status(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cbor_resp_ic_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_cbor_resp_ic_module);
    if (ctx == NULL)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->status.data;
    v->len = ctx->status.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_cbor_resp_ic_cbor_ic_error_code(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cbor_resp_ic_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_cbor_resp_ic_module);
    if (ctx == NULL)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->error_code.data;
    v->len = ctx->error_code.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_cbor_resp_ic_cbor_ic_reject_code(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cbor_resp_ic_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_cbor_resp_ic_module);
    if (ctx == NULL)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    u_char *p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL)
        return NGX_ERROR;

    v->data = p;
    v->len = ngx_sprintf(p, "%i", ctx->reject_code) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_cbor_resp_ic_cbor_ic_reject_message(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cbor_resp_ic_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_cbor_resp_ic_module);
    if (ctx == NULL)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->reject_message.data;
    v->len = ctx->reject_message.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_cbor_resp_ic_add_variables(ngx_conf_t *cf)
{
    for (ngx_http_variable_t *v = ngx_http_cbor_resp_ic_vars; v->name.len; v++)
    {
        ngx_http_variable_t *vv = ngx_http_add_variable(cf, &v->name, NGX_HTTP_VAR_CHANGEABLE);
        if (vv == NULL)
            return NGX_ERROR;

        vv->get_handler = v->get_handler;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_cbor_resp_ic_init(ngx_conf_t *cf)
{
    ngx_http_next_output_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_cbor_resp_ic_output_body_filter;

    return NGX_OK;
}