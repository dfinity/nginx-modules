#include "ic.h"

parse_result_t parse_str(cb0r_t in, uint skip, ngx_str_t *s)
{
    if (in->type == CB0R_UTF8)
    {
        s->data = in->start + in->header;
        s->len = in->length;

        return PARSE_OK;
    }

    cb0r_s r = {0};

    cb0r(
        in->start + in->header, // start
        in->end,                // stop
        skip,                   // skip
        &r                      // result
    );

    if (r.type != CB0R_UTF8)
        return PARSE_ERR;

    s->data = r.start + r.header;
    s->len = r.length;

    return PARSE_OK;
}

parse_result_t parse_int(cb0r_t in, uint skip, ngx_int_t *i)
{
    if (in->type == CB0R_INT)
    {
        *i = in->value;

        return PARSE_OK;
    }

    cb0r_s r = {0};

    cb0r(
        in->start + in->header, // start
        in->end,                // stop
        skip,                   // skip
        &r                      // result
    );

    if (r.type != CB0R_INT)
        return PARSE_ERR;

    *i = r.value;

    return PARSE_OK;
}

cb0r_s get_key(cb0r_t r, char *key)
{
    if (r->type != CB0R_MAP)
    {
        cb0r_s ret = {.type = CB0R_ERR};
        return ret;
    }

    // Consume stream
    if (r->count == CB0R_STREAM)
    {
        r->count = 0; // NOTE(or): Can this be removed? It's already done in `cb0r(...)`?
        cb0r(
            r->start + r->header, // start
            r->end,               // stop
            CB0R_STREAM,          // skip
            r                     // result
        );
    }

    // Search for key
    for (uint64_t i = 0; i < r->count; i += 2)
    {
        ngx_str_t k;
        if (parse_str(r, i, &k) != PARSE_OK)
            continue;

        if (strncmp(key, (char *)k.data, k.len) != 0)
            continue;

        cb0r_s out = {0};
        cb0r(
            r->start + r->header, // start
            r->end,               // stop
            i + 1,                // skip
            &out                  // result
        );

        return out;
    }

    cb0r_s ret = {.type = CB0R_ERR};
    return ret;
}