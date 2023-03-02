# ngx_http_cbor_modules

The following modules decode CBOR requests and responses to and from the Internet Computer.

It is assumed that the bodies being decoded are based on the CBOR schemas described in the [Internet Computer Specification](https://internetcomputer.org/docs/current/references/ic-interface-spec/#api-cddl).

---

## ngx_http_cbor_req_ic_module

This module will attempt to parse a CBOR-encoded request body and extract several pre-defined fields from it.

_*Caveat*_: The module skips processing bodies that are not stored in memory. Whether a request body is kept in memory or not can be controlled via [client_body_buffer_size](http://nginx.org/en/docs/http/ngx_http_core_module.html#client_body_buffer_size).

Usage:

```conf
load_module "/etc/nginx/modules/ngx_http_cbor_req_ic_module.so";
```

Variables:

1. `cbor_req_ic_request_type` - The type of the encapsulated request. E.g `query` or `call`.
1. `cbor_req_ic_method_name`- The name of the canister method being called.

---

## ngx_http_cbor_resp_ic_module

This module will attempt to parse a CBOR-encoded response body and extract several pre-defined fields from it.

_*Caveat*_: The module skips processing bodies that exceed a given size (currently hardcoded at 16kb).

Usage:

```conf
load_module "/etc/nginx/modules/ngx_http_cbor_resp_ic_module.so";
```

Variables:

1. `cbor_resp_ic_status` - The status of the reply. E.g `replied` or `rejected`.
1. `cbor_resp_ic_error_code`- An error code, if available.
1. `cbor_resp_ic_reject_code`- A rejection code, if available.
1. `cbor_resp_ic_reject_message`- A free-form rejection message, if available.
