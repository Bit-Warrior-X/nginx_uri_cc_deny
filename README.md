# HTTP NGINX URI CC DENY Module

Against CC attack requests for specific URIs in specific duration.

## Installation
```bash
  # cd /path/openresty
  # git clone https://github.com/Bit-Warrior-X/nginx_uri_cc_deny.git
  # ./configure -j2 --add-module=./nginx_uri_cc_deny/
  # make && make install
```

## Configuration directives (same location syntax)

#### **CC_DENY_URI**
- **syntax:** `CC_DENY_URI uri codes times/duration`
- **default:** `none`
- **context:** `http, server, location`

Set the cc deny rule

##### Example:
```bash
  CC_DENY_URI video.ts 404,302 5times/60s;
```

If the request ends with video.ts and it returns 404 or 302 more than 5 times in 60 seconds, nginx will deny this request.
You can add multiple cc deny rules as you want.
 