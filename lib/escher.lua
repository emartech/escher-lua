local crypto = require("crypto")
local Escher = {}

Escher.canonicalizeRequest = function(request)
  headers = request.headers
  return table.concat({
    request.method,
    request.url,
    "",
    Escher.canonicalizeHeaders(headers),
    "",
    Escher.canonicalizeSignedHeaders(headers),
    Escher.hash("sha256", request.body)
  }, "\n")
end

Escher.canonicalizeHeaders = function(headers)
  local normalizedHeaders = {}
  local n = 0
  for k,header in pairs(headers) do
    n = n+1
    normalizedHeaders[n] = header[1]:lower() .. ":" .. header[2]
  end
  return table.concat(normalizedHeaders, "\n")
end

Escher.canonicalizeSignedHeaders = function(headers)
  local normalizedKeys = {}
  local n = 0
  for k,header in pairs(headers) do
    n = n+1
    normalizedKeys[n] = header[1]:lower()
  end
  return table.concat(normalizedKeys, ";")
end

Escher.hash = function(hashAlgo, body)
  return crypto.digest(hashAlgo, body)
end

return Escher
