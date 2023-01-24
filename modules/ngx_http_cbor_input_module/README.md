CBOR parser
===========

Set the cache key from CBOR in the request body.

# Build and configuration

You will need the source code for `NGINX` and `ngx_devel_kit`:
```
curl https://nginx.org/download/nginx-1.18.0.tar.gz | gunzip | tar -x
git clone git@github.com:vision5/ngx_devel_kit.git
```

See [`make-it-so`](./make-it-so) for how I have been building and testing; this will need to be changed to make it portable.

This is in my NGINX config:
```
location = /mod {

   # hello_world;
   #
       # ensure client_max_body_size == client_body_buffer_size
    client_max_body_size 100k;
    client_body_buffer_size 100k;

    set_cbor_input $cache_key;
    add_header X-CacheKey $cache_key always;
}
```

# Credits:

[nginx module that parses the body](https://github.com/calio/form-input-nginx-module) + [CBOR parser](https://github.com/quartzjer/cb0r) = this.

Also:
* [NGINX examples for how to write modules](https://www.nginx.com/resources/wiki/extending/examples/)
* [NGINX module API](https://www.nginx.com/resources/wiki/extending/api/)
* [Setting NGINX variables](https://github.com/vision5/ngx_devel_kit/blob/master/examples/http/set_var/ngx_http_set_var_examples_module.c)
* How the NGINX development kit sets vars:
  * [How the NGINX development kit sets vars](https://github.com/vision5/ngx_devel_kit/blob/a22dade76c838e5f377d58d007f65d35b5ce1df3/src/ndk_set_var.c#L530)
  * [How the NGINX development kit sets vars - continued](https://github.com/vision5/ngx_devel_kit/blob/a22dade76c838e5f377d58d007f65d35b5ce1df3/src/ndk_rewrite.c)
  * Alas these seem to have no documentation.

# TODO

## Cache Keys
Here are the keys we need for caching:

```
  var c = msg.content;
  return c.request_type + "." + Buffer.from(c.sender).toString() + "." + Buffer.from(c.canister_id).toString() + "." + c.method_name + "." + Buffer.from(c.arg).toString()
```

## Rate limiting

For rate limiting, we need:
```
canister ID
method name
source IP address (already available in NGINX)
```

With this config I get rate limiting for a toy `canister_id=0103050607080902` and update `method_name=register`.  The limit can also be applied to other canisters or methods:
```
# In an NGINX http section:

# If not defined already:
# map_hash_max_size 26214;
# map_hash_bucket_size 26214;

# Rate limit derived from the cache key variables.  This can rate limit by canister and method.
# Note: $binary_remote_addr can be used instead of $remote_addr to reduce memory usage, but it is not printable for debugging.
limit_req_zone $rate_limit_key zone=cache_key_rate_limit:1m rate=10r/m;

map $cache_key $rate_limit_key {
    default                                                "";
    "~^call[.][^.]*[.]0103050607080902[.]register[.].*"    $remote_addr;
}


# In a location directive:
limit_req zone=cache_key_rate_limit burst=3 delay=2;
```

## CBOR types
The Rust structs for HttpRequests are defined [here.](../../rs/types/types/src/messages/http.rs).  See in particular `HttpRequest` which has the `content` field, and inside that `HttpReadContent` (for `query` and `read_state`) or `HttpSubmitContent` (for update) (thanks to Paul for the pointers).
