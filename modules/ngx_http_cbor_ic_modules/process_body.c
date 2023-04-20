#include "cb0r.h"
#include "ic.h"
#include "identifier.h"
#include "ngx_http_cbor_req_ic_module.h"
#include "process_body.h"

// process_body extracts relevant CBOR fields from the given body
// and stores them in the context
//
// schema {
//     "content": {
//         "request_type": str, // mandatory
//         "sender": principal, // mandatory
//         "method_name": str, // optional
//         "canister_id": principal, // optional
//     }
// }

void process_body(buf_t b, ngx_http_cbor_req_ic_ctx_t *ctx)
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

    // Content
    cb0r_s content = get_map_key(&root, "content");
    if (content.type != CB0R_MAP)
        return;

    // Request type
    cb0r_s request_type_c = get_map_key(&content, "request_type");
    if (request_type_c.type != CB0R_UTF8)
        return;

    ngx_str_t request_type;
    if (parse_str(&request_type_c, 0, &request_type) != PARSE_OK)
        return;

    ctx->request_type = request_type;

    // Sender
    cb0r_s sender_c = get_map_key(&content, "sender");
    if (sender_c.type != CB0R_BYTE)
        return;

    ctx->sender.len = identifier_encode(cb0r_value(&sender_c), sender_c.length, ctx->sender.data);

    // `read_state` call does not have the other fields, so return here
    if (strncmp((const char *)request_type.data, "read_state", request_type.len) == 0)
        return;

    // Method name
    cb0r_s method_name_c = get_map_key(&content, "method_name");
    if (method_name_c.type != CB0R_UTF8)
        return;

    ngx_str_t method_name;
    if (parse_str(&method_name_c, 0, &method_name) != PARSE_OK)
        return;

    ctx->method_name = method_name;

    // Canister ID
    cb0r_s canister_id_c = get_map_key(&content, "canister_id");
    if (canister_id_c.type != CB0R_BYTE)
        return;

    ctx->canister_id.len = identifier_encode(cb0r_value(&canister_id_c), canister_id_c.length, ctx->canister_id.data);
    return;
}
