#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"
#include "cb0r.h"
#include "getvar.h"
#include "stringify.h"

#include <ndk.h>
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct
{
    unsigned used; /* :1 */
} ngx_http_cbor_input_main_conf_t;

typedef struct
{
    unsigned done : 1;
    unsigned waiting_more_body : 1;
} ngx_http_cbor_input_ctx_t;

static ngx_int_t ngx_http_set_cbor_input(ngx_http_request_t *r, ngx_str_t *res,
                                         ngx_http_variable_value_t *v);
static char *ngx_http_set_cbor_input_conf_handler(ngx_conf_t *cf,
                                                  ngx_command_t *cmd, void *conf);
static void *ngx_http_cbor_input_create_main_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_cbor_input_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_cbor_input_handler(ngx_http_request_t *r);
static void ngx_http_cbor_input_post_read(ngx_http_request_t *r);
static ngx_int_t ngx_http_cbor_input_arg(ngx_http_request_t *r, u_char *name,
                                         size_t len, ngx_str_t *value);

static ngx_command_t ngx_http_cbor_input_commands[] = {

    {ngx_string("set_cbor_input"),
     NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
     ngx_http_set_cbor_input_conf_handler,
     NGX_HTTP_LOC_CONF_OFFSET,
     0,
     NULL},

    ngx_null_command};

static ngx_http_module_t ngx_http_cbor_input_module_ctx = {
    NULL,                     /* preconfiguration */
    ngx_http_cbor_input_init, /* postconfiguration */

    ngx_http_cbor_input_create_main_conf, /* create main configuration */
    NULL,                                 /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

ngx_module_t ngx_http_cbor_input_module = {
    NGX_MODULE_V1,
    &ngx_http_cbor_input_module_ctx, /* module context */
    ngx_http_cbor_input_commands,    /* module directives */
    NGX_HTTP_MODULE,                 /* module type */
    NULL,                            /* init master */
    NULL,                            /* init module */
    NULL,                            /* init process */
    NULL,                            /* init thread */
    NULL,                            /* exit thread */
    NULL,                            /* exit precess */
    NULL,                            /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_int_t
ngx_http_set_cbor_input(ngx_http_request_t *r, ngx_str_t *res,
                        ngx_http_variable_value_t *v)
{
    ngx_http_cbor_input_ctx_t *ctx;
    ngx_int_t rc;

    dd_enter();

    dd("set default return value");
    ngx_str_set(res, "");

    if (r->done)
    {
        dd("request done");
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_cbor_input_module);

    if (ctx == NULL)
    {
        dd("ndk handler:null ctx");
        return NGX_OK;
    }

    if (!ctx->done)
    {
        dd("ctx not done");
        return NGX_OK;
    }

    rc = ngx_http_cbor_input_arg(r, v->data, v->len, res);

    return rc;
}

/* fork from ngx_http_arg.
 * read argument(s) with name arg_name and length arg_len into value variable,
 * if multi flag is set, multi arguments with name arg_name will be read and
 * stored in an ngx_array_t struct, this can be operated by directives in
 * array-var-nginx-module */
// Note: This both copies the body into a buffer AND sets the variable value.  For multiple variables we might want to separate these two.
//       Even cooler would be to get NGINX to populate the body variable (hard) and reuse that over multiple calls.
static ngx_int_t
ngx_http_cbor_input_arg(ngx_http_request_t *r, u_char *arg_name, size_t arg_len,
                        ngx_str_t *value)
{
    u_char *p, *last, *buf;
    ngx_chain_t *cl;
    size_t len = 0;
    ngx_buf_t *b;

    ngx_str_set(value, "");

    /* we read data from r->request_body->bufs */
    if (r->request_body == NULL || r->request_body->bufs == NULL)
    {
        dd("empty rb or empty rb bufs");
        return NGX_OK;
    }

    if (r->request_body->bufs->next != NULL)
    {
        /* more than one buffer...we should copy the data out... */
        len = 0;
        for (cl = r->request_body->bufs; cl; cl = cl->next)
        {
            b = cl->buf;

            if (b->in_file)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "cbor-input: in-file buffer found. aborted. "
                              "consider increasing your "
                              "client_body_buffer_size setting");

                return NGX_OK;
            }

            len += b->last - b->pos;
        }

        dd("len=%d", (int)len);

        if (len == 0)
        {
            return NGX_OK;
        }

        buf = ngx_palloc(r->pool, len);
        if (buf == NULL)
        {
            return NGX_ERROR;
        }

        p = buf;
        last = p + len;

        for (cl = r->request_body->bufs; cl; cl = cl->next)
        {
            p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
        }

        dd("p - buf = %d, last - buf = %d", (int)(p - buf),
           (int)(last - buf));

        dd("copied buf (len %d): %.*s", (int)len, (int)len,
           buf);
    }
    else
    {
        dd("XXX one buffer only");

        b = r->request_body->bufs->buf;
        if (ngx_buf_size(b) == 0)
        {
            return NGX_OK;
        }

        buf = b->pos;
        last = b->last;
    }

    // Get the relevant values from the CBOR.
    // ... skip any magic bytes at the beinning, if present.
    cb0r_s root = get_root(&(cb0r_s){.type = CB0R_DATA, .start = buf, .end = last, .length = (last - buf)}, 0);
    // ... the root should be a map with "content" as a key.
    cb0r_s content = get_str_key(&root, 0, "content");
    if (content.type == CB0R_MAP)
    {
        ngx_log_stderr(NGX_LOG_DEBUG_HTTP, "Measuring out len...");
        size_t total_len = 0;
        // Look for all the parts:
        // ... request_type
        cb0r_s part_request_type = get_str_key(&content, 0, "request_type");
        if (part_request_type.type == CB0R_UTF8)
        {
            total_len += cbor_str_size(part_request_type);
        }
        else
        {
            ngx_log_stderr(NGX_LOG_WARN, "CBOR .content.request_type absent or has incorrect type: %s", cbor_e_names[part_request_type.type]);
            return NGX_DECLINED;
        }
        //   ... delimiter
        total_len += 1;
        // ... sender
        cb0r_s part_sender = get_str_key(&content, 0, "sender");
        if (part_sender.type == CB0R_BYTE)
        {
            total_len += cbor_str_size(part_sender);
        }
        else
        {
            ngx_log_stderr(NGX_LOG_WARN, "CBOR .content.sender absent or has incorrect type: %s", cbor_e_names[part_sender.type]);
            return NGX_DECLINED;
        }
        //   ... delimiter
        total_len += 1;
        // ... canister_id
        cb0r_s part_canister_id = get_str_key(&content, 0, "canister_id");
        if (part_canister_id.type == CB0R_BYTE)
        {
            total_len += cbor_str_size(part_canister_id);
        }
        else
        {
            ngx_log_stderr(NGX_LOG_WARN, "CBOR .content.canister_id absent or has incorrect type: %s", cbor_e_names[part_canister_id.type]);
            return NGX_DECLINED;
        }
        //   ... delimiter
        total_len += 1;
        // ... method_name
        cb0r_s part_method_name = get_str_key(&content, 0, "method_name");
        if (part_method_name.type == CB0R_UTF8)
        {
            total_len += cbor_str_size(part_method_name);
        }
        else
        {
            ngx_log_stderr(NGX_LOG_WARN, "CBOR .content.method_name absent or has incorrect type: %s", cbor_e_names[part_method_name.type]);
            return NGX_DECLINED;
        }
        //   ... delimiter
        total_len += 1;
        // ... arg
        cb0r_s part_arg = get_str_key(&content, 0, "arg");
        if (part_arg.type == CB0R_BYTE)
        {
            total_len += cbor_str_size(part_arg);
        }
        else
        {
            ngx_log_stderr(NGX_LOG_WARN, "CBOR .content.arg absent or has incorrect type: %s", cbor_e_names[part_arg.type]);
            return NGX_DECLINED;
        }

        ngx_log_stderr(NGX_LOG_DEBUG_HTTP, "Total out len: %d", total_len);

        // Stringify all
        u_char *strbuf = ngx_palloc(r->pool, total_len);
        u_char *writer = strbuf;
        // ... request_type
        writer = stringify_cbor(part_request_type, writer);
        *writer++ = '.';
        // ... sender
        writer = stringify_cbor(part_sender, writer);
        *writer++ = '.';
        // ... sender
        writer = stringify_cbor(part_canister_id, writer);
        *writer++ = '.';
        // ... sender
        writer = stringify_cbor(part_method_name, writer);
        *writer++ = '.';
        // ... sender
        writer = stringify_cbor(part_arg, writer);

        // Return the string
        value->data = strbuf;
        value->len = total_len;
    }
    else
    {
        ngx_log_stderr(NGX_LOG_WARN, "CBOR .content absent or has incorrect type: %s", cbor_e_names[content.type]);
        return NGX_DECLINED;
    }

    return NGX_OK;
}

static char *
ngx_http_set_cbor_input_conf_handler(ngx_conf_t *cf, ngx_command_t *cmd,
                                     void *conf)
{
    ndk_set_var_t filter;
    ngx_str_t *value, s;
    u_char *p;
    ngx_http_cbor_input_main_conf_t *fmcf;

#if defined(nginx_version) && nginx_version >= 8042 && nginx_version <= 8053
    return "does not work with " NGINX_VER;
#endif

    fmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_cbor_input_module);

    fmcf->used = 1;

    // If I understand correctly:  The filter may set multiple NGINX variables; these are passed in as an array to the filter function.
    // Note that there are also array return values, so I could be wrong.
    filter.type = NDK_SET_VAR_MULTI_VALUE;
    filter.size = 1; // Number of variables.

    value = cf->args->elts;

    filter.func = (void *)ngx_http_set_cbor_input;

    value++;

    if (cf->args->nelts == 2)
    {
        p = value->data;
        p++;
        s.len = value->len - 1;
        s.data = p;
    }
    else if (cf->args->nelts == 3)
    {
        s.len = (value + 1)->len;
        s.data = (value + 1)->data;
    }

    return ndk_set_var_multi_value_core(cf, value, &s, &filter);

    // Define variable.  Variables are indexed.
    // Method doc: https://www.nginx.com/resources/wiki/extending/api/variables/#c.ngx_http_variable_t
    // ngx_http_add_variable(cf, , NGX_HTTP_VAR_CHANGEABLE);
    // ngx_http_get_variable_index(...) get variable index
    // Presumably the variable can be set in the filter, using the index?
}

/* register a new rewrite phase handler */
static ngx_int_t
ngx_http_cbor_input_init(ngx_conf_t *cf)
{

    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_cbor_input_main_conf_t *fmcf;

    fmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_cbor_input_module);

    if (!fmcf->used)
    {
        return NGX_OK;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);

    if (h == NULL)
    {
        return NGX_ERROR;
    }

    *h = ngx_http_cbor_input_handler;

    return NGX_OK;
}

/* an rewrite phase handler */
static ngx_int_t
ngx_http_cbor_input_handler(ngx_http_request_t *r)
{
    ngx_http_cbor_input_ctx_t *ctx;
    ngx_int_t rc;

    dd_enter();

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cbor_input rewrite phase handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_cbor_input_module);

    if (ctx != NULL)
    {
        if (ctx->done)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http cbor_input rewrite phase handler done");

            return NGX_DECLINED;
        }

        return NGX_DONE;
    }

    if (r->method != NGX_HTTP_POST && r->method != NGX_HTTP_PUT)
    {
        return NGX_DECLINED;
    }

    if (r->headers_in.content_type == NULL || r->headers_in.content_type->value.data == NULL)
    {
        dd("content_type is %p", r->headers_in.content_type);

        return NGX_DECLINED;
    }

    dd("r->headers_in.content_length_n:%d",
       (int)r->headers_in.content_length_n);

    dd("create new ctx");

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_cbor_input_ctx_t));
    if (ctx == NULL)
    {
        return NGX_ERROR;
    }

    /* set by ngx_pcalloc:
     *      ctx->done = 0;
     *      ctx->waiting_more_body = 0;
     */

    ngx_http_set_ctx(r, ctx, ngx_http_cbor_input_module);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cbor_input start to read client request body");

    rc = ngx_http_read_client_request_body(r, ngx_http_cbor_input_post_read);

    if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE)
    {
#if (nginx_version < 1002006) || \
    (nginx_version >= 1003000 && nginx_version < 1003009)
        r->main->count--;
#endif

        return rc;
    }

    if (rc == NGX_AGAIN)
    {
        ctx->waiting_more_body = 1;

        return NGX_DONE;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cbor_input has read the request body in one run");

    return NGX_DECLINED;
}

static void
ngx_http_cbor_input_post_read(ngx_http_request_t *r)
{
    ngx_http_cbor_input_ctx_t *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http cbor_input post read request body");

    ctx = ngx_http_get_module_ctx(r, ngx_http_cbor_input_module);

    ctx->done = 1;

#if defined(nginx_version) && nginx_version >= 8011
    dd("count--");
    r->main->count--;
#endif

    dd("waiting more body: %d", (int)ctx->waiting_more_body);

    /* waiting_more_body my rewrite phase handler */
    if (ctx->waiting_more_body)
    {
        ctx->waiting_more_body = 0;

        ngx_http_core_run_phases(r);
    }
}

static void *
ngx_http_cbor_input_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_cbor_input_main_conf_t *fmcf;

    fmcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_cbor_input_main_conf_t));
    if (fmcf == NULL)
    {
        return NULL;
    }

    /* set by ngx_pcalloc:
     *      fmcf->used = 0;
     */

    return fmcf;
}
