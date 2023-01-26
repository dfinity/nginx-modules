#include "cb0r.h"
#include "getvar.h"

#include <ndk.h>
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

// Returns the size in bytes of a CBOR payload
size_t cbor_payload_size(cb0r_s field) {
   return field.end - field.start - field.header;
}

// Returns the size in bytes of the string representation of a CBOR payload.
size_t cbor_str_size(cb0r_s field) {
   switch(field.type) {
   case CB0R_UTF8: return field.end - field.start - field.header;
   case CB0R_BYTE: return 2*(field.end - field.start - field.header);
   default: return 0; // Unsupported.
   }
}

// Stringifies a CBOR field into a buffer, returning a pointer just after the data just written.
u_char * stringify_cbor(cb0r_s field, u_char * strbuf) {
	switch(field.type) {
	case CB0R_UTF8: { return ngx_copy(strbuf, field.start + field.header, cbor_payload_size(field));} break;
	case CB0R_BYTE: { return ngx_hex_dump(strbuf, field.start + field.header, cbor_payload_size(field));} break;
	default: {return strbuf;} break;
	}
}
