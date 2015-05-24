local crypto = require("crypto")
local date = require("date")
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
  headers = request.headers
  return table.concat({
    request.method,
    request.url,
    "",
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

function Escher:toLongDate(date)
  return date:fmt("%Y%m%dT%H%M%SZ")
end

function Escher:toShortDate(date)
  return date:fmt("%Y%m%d")
end

return Escher
