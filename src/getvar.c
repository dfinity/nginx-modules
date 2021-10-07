#include "cb0r.h"
#include "getvar.h"


// Is this the string key we are looking for?
bool foundit(cb0r_t in, uint32_t skip, char* name, size_t name_len) {
  cb0r_s res = {0,};
  cb0r(in->start+in->header,in->end,skip,&res);
  switch(res.type)
  {
    case CB0R_UTF8: if(res.count != CB0R_STREAM) {
			    bool same_length = res.length == name_len;
			    bool ans = same_length && !memcmp ( name, res.start+res.header, name_len );
			    // printf("\"%.*s\" %d",(int)res.length,res.start+res.header, ans);
				    return ans;
    } else {
      return false;
    } break;
    default: {
      return false;
    } break;
  }
}

// Get value from a top level dictionary/struct.  If it is not found, return an error type.
// # Arguments
// skip == number of CBOR items to skip.
// sought == the string key we are looking for.
cb0r_s get_root(cb0r_t in, uint32_t skip) {
  // Skip magic bytes, if present:
  if ((in->end - in->start > 3) && (*(in->start) == 0xD9) && (*(in->start+1) == 0xD9) && (*(in->start+2) == 0xF7)) {
     in->start += 3;
  }
  cb0r_s res = {0,};
  cb0r(in->start+in->header,in->end,skip,&res);
  return res;
}
 
// Gets a null terminated string key.
cb0r_s get_str_key(cb0r_t in, uint32_t skip, char* sought) {
  size_t sought_len = strlen(sought);
  return get_key(in, skip, sought, sought_len);
}

// Get value from a top level dictionary/struct.  If it is not found, return an error type.
// # Arguments
// skip == number of CBOR items to skip.
// sought == the string key we are looking for.
cb0r_s get_key(cb0r_t in, uint32_t skip, char* sought, size_t sought_len) {
  cb0r_s res = *in;
  cb0r_s ans = {.type = CB0R_ERR,}; /* default answer */
  switch(res.type)
  {
    case CB0R_MAP: {
      if(res.count == CB0R_STREAM)
      {
        res.count = 0;
        cb0r(res.start+res.header,res.end,CB0R_STREAM,&res);
      }
      for(uint32_t i=0;i<res.count;i+=2)
      {
	if (foundit(&res, i, sought, sought_len) && (i+1 < res.count)) {
          cb0r(res.start+res.header,res.end,i+1,&ans);
	  return ans;
	}
      }
    } break;
    default: {
      // Wrong type
      ans.type = CB0R_EPARSE;
    } break;
  }
  return ans;
}
