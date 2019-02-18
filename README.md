EscherLua - HTTP request signing lib [![Build Status](https://travis-ci.org/emartech/escher-lua.svg?branch=master)](https://travis-ci.org/emartech/escher-lua)
====================================

Lua implementation of the [AWS4](http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html) compatible [Escher](https://github.com/emartech/escher) HTTP request signing and authentication library. The library is compatible with the [Nginx's HttpLuaModule](http://wiki.nginx.org/HttpLuaModule) and [Openresty](http://openresty.org/).

We are using it for our OpenResty based API gateway server for authenticating the requests, and route the request to our microservices with a different signature.

Prerequisite
------------

In order to run the tests, Lua, LuaRocks and some libraries must be installed.

Setup
-----

Some tips to setup the local development environment on a Mac:

```bash
brew install lua
brew install luarocks
brew install cmake
brew install openssl
luarocks install busted
luarocks install luasocket
luarocks install rapidjson
luarocks install luacrypto 0.3.2-2 OPENSSL_DIR=/usr/local/opt/openssl
luarocks install date
```

Examples
-------------

Authentication:
```lua
local escher = Escher({
    algoPrefix = "AWS4",
    vendorKey = "AWS4",
    hashAlgo = "SHA256",
    credentialScope = "us-east-1/host/aws4_request",
    authHeaderName = "X-EMS-Auth",
    dateHeaderName = "X-EMS-Date",
    date = "2011-09-09T23:36:00.000Z" -- give date for testing purposes only
})

local request = {
    method = "GET",
    url = "/",
    headers = {
        { "X-EMS-Date", "20110909T233600Z" },
        { "Host", "host.foo.com" },
        { "X-EMS-Auth", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=x-ems-date;host, Signature=3a2b15801d517d0010be640f0685fa60b5d793396be38e0566ede3d334554479" }
    },
    body = ""
}

local my_key = "AKIDEXAMPLE"

local function keyDb(key)
    if key == my_key then
        return "1/K7MDENG+bPxRfiCYEXAMPLEKEY"
    end
end

local headersToSign = { "x-ems-date" }

local auth_key = escher:authenticate(request, keyDb, headersToSign)

assert(auth_key == my_key, "Auth key mismatch") -- should not throw error
```

Signing a request:
```lua
local escher = Escher({
    algoPrefix = "AWS4",
    vendorKey = "AWS4",
    hashAlgo = "SHA256",
    credentialScope = "us-east-1/host/aws4_request",
    authHeaderName = "X-EMS-Auth",
    dateHeaderName = "X-EMS-Date",
    date = "2011-09-09T23:36:00.000Z", -- give date for testing purposes only
    apiSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    accessKeyId = "AKIDEXAMPLE"
})

local request = {
    method = "GET",
    url = "/",
    headers = {
        { "Host", "host.foo.com" }
    },
    body = ""
}

local headersToSign = { "x-ems-date" }

escher:signRequest(request, headersToSign)

--[[
request should now look like this:
{
    body = "",
    method = "GET",
    url = "/",
    headers = {
        { "Host", "host.foo.com" },
        { "X-EMS-Date", "Fri, 09 Sep 2011 23:36:00 GMT" },
        { "X-EMS-Auth", "..." }
    }
}
--]]
```

Run the tests
-------------

To run all the tests, use the `busted` command.

About Escher
------------

More details are available at our [Escher documentation site](http://escherauth.io/).
