local crypto = require("crypto")
local Escher = {
  hashAlgo = 'SHA256'
}

function Escher:new(o)
  o = o or {}
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

return Escher
