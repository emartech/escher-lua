local crypto = require("crypto")
local date = require("date")
local urlparser = require("socket.url")
local Escher = {
  algoPrefix      = 'ESR',
  vendorKey       = 'Escher',
  hashAlgo        = 'SHA256',
  credentialScope = 'escher_request',
  authHeaderName  = 'X-Escher-Auth',
  dateHeaderName  = 'X-Escher-Date',
  clockSkew       = 900,
  date            = false
}

function Escher:new(o)
  o = o or {}
  o.date = date(o.date)
  setmetatable(o, self)
  self.__index = self
  return o
end

function Escher:canonicalizeRequest(request)
  url = urlparser.parse(request.url)
  headers = request.headers
  return table.concat({
    request.method,
    url.path,
    url.query or '',
    self:canonicalizeHeaders(headers),
    "",
    self:canonicalizeSignedHeaders(headers),
    crypto.digest(self.hashAlgo, request.body)
  }, "\n")
end

function Escher:canonicalizeHeaders(headers)
  local normalizedHeaders = {}
  local n = 0
  for k, header in pairs(headers) do
    n = n+1
    normalizedHeaders[n] = header[1]:lower() .. ":" .. header[2]
  end
  return table.concat(normalizedHeaders, "\n")
end

function Escher:canonicalizeSignedHeaders(headers)
  local normalizedKeys = {}
  local n = 0
  for k, header in pairs(headers) do
    n = n+1
    normalizedKeys[n] = header[1]:lower()
  end
  return table.concat(normalizedKeys, ";")
end

function Escher:getStringToSign(request)
  return table.concat({
    self.algoPrefix .. "-HMAC-" .. self.hashAlgo,
    self:toLongDate(self.date),
    self:toShortDate(self.date) .. "/" .. self.credentialScope,
    crypto.digest(self.hashAlgo, self:canonicalizeRequest(request))
  }, "\n")
end

function Escher:generateHeader(request)
  return self.algoPrefix .. "-HMAC-" .. self.hashAlgo ..
         " Credential=" .. self:generateFullCredentials(self.date) ..
         ", SignedHeaders=" .. self:canonicalizeSignedHeaders(request.headers) ..
         ", Signature=" .. self:calculateSignature(request)
end

function Escher:calculateSignature(request)
  stringToSign = self:getStringToSign(request)
  signingKey = self:calculateSigningKey(self.date)
  return crypto.hmac.digest(self.hashAlgo, stringToSign, signingKey, false)
end

function Escher:getAuthKeyParts(date)
  parts = { self:toShortDate(date) }
  for part in string.gmatch(self.credentialScope, "[A-Za-z0-9_\\-]+") do
    table.insert(parts, part)
  end
  return parts
end

function Escher:calculateSigningKey(date)
  signingKey = self.algoPrefix .. self.apiSecret
  parts = self:getAuthKeyParts(date)
  for k, part in pairs(parts) do
    signingKey = crypto.hmac.digest(self.hashAlgo, part, signingKey, true)
  end
  return signingKey
end

function Escher:toLongDate(date)
  return date:fmt("%Y%m%dT%H%M%SZ")
end

function Escher:toShortDate(date)
  return date:fmt("%Y%m%d")
end

function Escher:generateFullCredentials(date)
  return self.accessKeyId .. "/" .. self:toShortDate(date) .. "/" .. self.credentialScope
end

return Escher
