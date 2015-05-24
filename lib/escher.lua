local crypto = require("crypto")
local date = require("date")
local urlhandler = require("escher.urlhandler")
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
  url = urlhandler.parse(request.url):normalize()
  headers = request.headers
  return table.concat({
    request.method,
    url.path,
    url.query,
    self:canonicalizeHeaders(headers),
    "",
    self:canonicalizeSignedHeaders(headers),
    crypto.digest(self.hashAlgo, request.body)
  }, "\n")
end

function Escher:canonicalizeHeaders(headers)
  local normalizedHeaders = {}
  for k, header in ipairs(headers) do
    name = header[1]:lower():match("^%s*(.-)%s*$")
    value = self:normalizeWhiteSpacesInHeaderValue(header[2])
    table.insert(normalizedHeaders, { name, value })
  end
  local groupedHeaders = {}
  local lastKey = false
  for _, header in ipairs(normalizedHeaders) do
    if lastKey == header[1] then
      groupedHeaders[#groupedHeaders] = string.format('%s,%s', groupedHeaders[#groupedHeaders], header[2])
    else
      table.insert(groupedHeaders, string.format('%s:%s', header[1], header[2]))
    end
    lastKey = header[1]
  end
  table.sort(groupedHeaders)
  return table.concat(groupedHeaders, "\n")
end

function Escher:canonicalizeSignedHeaders(headers)
  local uniqueKeys = {}
  for k, header in pairs(headers) do
    uniqueKeys[header[1]:lower()] = true
  end
  local normalizedKeys = {}
  for k, _ in pairs(uniqueKeys) do
    table.insert(normalizedKeys, k)
  end
  table.sort(normalizedKeys)
  return table.concat(normalizedKeys, ";")
end

function Escher:getStringToSign(request)
  return table.concat({
    string.format('%s-HMAC-%s', self.algoPrefix, self.hashAlgo),
    self:toLongDate(),
    string.format('%s/%s', self:toShortDate(), self.credentialScope),
    crypto.digest(self.hashAlgo, self:canonicalizeRequest(request))
  }, "\n")
end

function Escher:normalizeWhiteSpacesInHeaderValue(value)
  value = string.format(" %s ", value)
  normalizedValue = {}
  n = 0
  for part in string.gmatch(value, '[^"]+') do
    n = n + 1
    if n % 2 == 1 then part = part:gsub("%s+", " ") end
    table.insert(normalizedValue, part)
  end
  return table.concat(normalizedValue, '"'):match("^%s*(.-)%s*$")
end

function Escher:generateHeader(request)
  return self.algoPrefix .. "-HMAC-" .. self.hashAlgo ..
         " Credential=" .. self:generateFullCredentials() ..
         ", SignedHeaders=" .. self:canonicalizeSignedHeaders(request.headers) ..
         ", Signature=" .. self:calculateSignature(request)
end

function Escher:calculateSignature(request)
  stringToSign = self:getStringToSign(request)
  signingKey = crypto.hmac.digest(self.hashAlgo, self:toShortDate(), self.algoPrefix .. self.apiSecret, true)
  for part in string.gmatch(self.credentialScope, "[A-Za-z0-9_\\-]+") do
    signingKey = crypto.hmac.digest(self.hashAlgo, part, signingKey, true)
  end
  return crypto.hmac.digest(self.hashAlgo, stringToSign, signingKey, false)
end

function Escher:toLongDate()
  return self.date:fmt("%Y%m%dT%H%M%SZ")
end

function Escher:toShortDate()
  return self.date:fmt("%Y%m%d")
end

function Escher:generateFullCredentials()
  return string.format("%s/%s/%s", self.accessKeyId, self:toShortDate(), self.credentialScope)
end

return Escher
