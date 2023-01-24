# ngx_http_cbor_modules

The following modules decode CBOR requests and responses to and from the Internet Computer.

It is assumed that the bodies being decoded are based on the CBOR schemas described in the [Internet Computer Specification](https://internetcomputer.org/docs/current/references/ic-interface-spec/#api-cddl).

---

## ngx_http_cbor_req_ic_module

Usage:

```conf
load_module "/etc/nginx/modules/ngx_http_cbor_req_ic_module.so";
```

Variables:

1. `cbor_req_ic_request_type` - The type of the encapsulated request. E.g `query` or `call`.
1. `cbor_req_ic_method_name`- The name of the canister method being called.

---

## ngx_http_cbor_resp_ic_module

Usage:

```conf
load_module "/etc/nginx/modules/ngx_http_cbor_resp_ic_module.so";
```

Variables:

1. `cbor_resp_ic_status` - The status of the reply. E.g `replied` or `rejected`.
1. `cbor_resp_ic_error_code`- An error code, if available.
1. `cbor_resp_ic_reject_code`- A rejection code, if available.
1. `cbor_resp_ic_reject_message`- A free-form rejection message, if available.
