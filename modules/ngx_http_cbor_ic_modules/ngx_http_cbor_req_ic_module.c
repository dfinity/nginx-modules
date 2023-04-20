#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "cb0r.h"
#include "ic.h"
#include "identifier.h"
#include "ngx_http_cbor_req_ic_module.h"
#include "process_body.h"

static ngx_int_t ngx_http_cbor_req_ic_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_cbor_req_ic_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_cbor_req_ic_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_cbor_req_ic_cbor_ic_request_type(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_cbor_req_ic_cbor_ic_method_name(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_cbor_req_ic_cbor_ic_canister_id(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_cbor_req_ic_cbor_ic_sender(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_http_variable_t ngx_http_cbor_req_ic_vars[] = {
    {ngx_string("cbor_req_ic_request_type"), NULL, ngx_http_cbor_req_ic_cbor_ic_request_type, 0, 0, 0},
    {ngx_string("cbor_req_ic_sender"), NULL, ngx_http_cbor_req_ic_cbor_ic_sender, 0, 0, 0},
    {ngx_string("cbor_req_ic_method_name"), NULL, ngx_http_cbor_req_ic_cbor_ic_method_name, 0, 0, 0},
    {ngx_string("cbor_req_ic_canister_id"), NULL, ngx_http_cbor_req_ic_cbor_ic_canister_id, 0, 0, 0},
    ngx_http_null_variable};

static ngx_http_module_t ngx_http_cbor_req_ic_ctx = {
    ngx_http_cbor_req_ic_add_variables, /* preconfiguration */
    ngx_http_cbor_req_ic_init,          /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

ngx_module_t ngx_http_cbor_req_ic_module = {
    NGX_MODULE_V1,
    &ngx_http_cbor_req_ic_ctx, /* module context */
    NULL,                      /* module directives */
    NGX_HTTP_MODULE,           /* module type */
    NULL,                      /* init master */
    NULL,                      /* init module */
    NULL,                      /* init process */
    NULL,                      /* init thread */
    NULL,                      /* exit thread */
    NULL,                      /* exit process */
    NULL,                      /* exit master */
    NGX_MODULE_V1_PADDING};

void nullify_str(ngx_str_t *s)
{
    s->data = NULL;
    s->len = 0;
}

static consume_result_t
consume_body(ngx_pool_t *p, ngx_chain_t *bufs, buf_t *buf)
{
    // Skip when no body is present
    if (bufs == NULL || bufs->buf == NULL)
        return CONSUME_EEMPTY;

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

static ngx_http_cbor_req_ic_ctx_t *mk_ctx(ngx_http_request_t *r)
{
    ngx_http_cbor_req_ic_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_cbor_req_ic_module);

    if (ctx == NULL)
    {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_cbor_req_ic_ctx_t));
        if (ctx == NULL)
            return NULL;

        // These are pointers to the request body and do not need separate allocation
        nullify_str(&ctx->method_name);
        nullify_str(&ctx->request_type);

        // These are dynamically generated from CBOR BLOBs and need to be allocated
        nullify_str(&ctx->canister_id);
        nullify_str(&ctx->sender);

        ctx->canister_id.data = ngx_pcalloc(r->pool, 64);
        if (ctx->canister_id.data == NULL)
            return NULL;

        ctx->sender.data = ngx_pcalloc(r->pool, 64);
        if (ctx->sender.data == NULL)
            return NULL;

        ctx->done = 0;

        ngx_http_set_ctx(r, ctx, ngx_http_cbor_req_ic_module);
    }

    return ctx;
}

static void
process_request(ngx_http_request_t *r)
{
    buf_t b;
    if (consume_body(
            r->pool,
            r->request_body->bufs,
            &b) != CONSUME_OK)
        return;

    ngx_http_cbor_req_ic_ctx_t *ctx = mk_ctx(r);
    if (ctx == NULL)
        return;

    // We don't really care for the result for now
    process_body(b, ctx);
}

void ngx_http_cbor_req_ic_body_init(ngx_http_request_t *r)
{
    process_request(r);

    ngx_http_cbor_req_ic_ctx_t *ctx = mk_ctx(r);
    if (ctx != NULL)
        ctx->done = 1;

    r->main->count--;

    ngx_http_core_run_phases(r);
}

static ngx_int_t
ngx_http_cbor_req_ic_handler(ngx_http_request_t *r)
{
    if (r->method != NGX_HTTP_POST)
        return NGX_DECLINED;

    ngx_http_cbor_req_ic_ctx_t *ctx = mk_ctx(r);
    if (ctx == NULL || ctx->done)
        return NGX_DECLINED;

    ngx_int_t rc = ngx_http_read_client_request_body(r, ngx_http_cbor_req_ic_body_init);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE)
        return rc;

    return NGX_DONE;
}

// request_type is always present
static ngx_int_t
ngx_http_cbor_req_ic_cbor_ic_request_type(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cbor_req_ic_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_cbor_req_ic_module);
    if (ctx == NULL)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->request_type.data;
    v->len = ctx->request_type.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

// sender is always present
static ngx_int_t
ngx_http_cbor_req_ic_cbor_ic_sender(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cbor_req_ic_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_cbor_req_ic_module);
    if (ctx == NULL)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->sender.data;
    v->len = ctx->sender.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

// method_name is optional
static ngx_int_t
ngx_http_cbor_req_ic_cbor_ic_method_name(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cbor_req_ic_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_cbor_req_ic_module);
    if (ctx == NULL)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->method_name.data;
    v->len = ctx->method_name.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

// canister_id is optional
static ngx_int_t
ngx_http_cbor_req_ic_cbor_ic_canister_id(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_cbor_req_ic_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_cbor_req_ic_module);
    if (ctx == NULL)
    {
        v->not_found = 1;
        return NGX_OK;
    }

    v->data = ctx->canister_id.data;
    v->len = ctx->canister_id.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_cbor_req_ic_add_variables(ngx_conf_t *cf)
{
    for (ngx_http_variable_t *v = ngx_http_cbor_req_ic_vars; v->name.len; v++)
    {
        ngx_http_variable_t *vv = ngx_http_add_variable(cf, &v->name, NGX_HTTP_VAR_CHANGEABLE);
        if (vv == NULL)
            return NGX_ERROR;

        vv->get_handler = v->get_handler;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_cbor_req_ic_init(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf =
        ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    ngx_http_handler_pt *h =
        ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_http_cbor_req_ic_handler;

    return NGX_OK;
}
