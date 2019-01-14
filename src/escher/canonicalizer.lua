local crypto = require("crypto")
local urlhandler = require("escher.urlhandler")
local utils = require("escher.utils")

local Canonicalizer = {}

local meta = {
  __index = Canonicalizer
}

function Canonicalizer:new(options)
  local object = {
    authHeaderName = options.authHeaderName,
    dateHeaderName = options.dateHeaderName,
    hashAlgo = options.hashAlgo
  }

  return setmetatable(object, meta)
end

setmetatable(Canonicalizer, {
  __call = Canonicalizer.new
})

local function addIfNotExists(headers, defaultHeaderName)
  if not utils.contains(headers, defaultHeaderName) then
    table.insert(headers, defaultHeaderName)
  end
end

local function shouldSignHeader(headerName, headersToSign)
  for _, header in ipairs(headersToSign) do
    if headerName:lower() == header:lower() then
      return true
    end
  end

  return false
end

local function getHeadersToSign(headers, headersToSign)
  local filteredHeaders = {}

  for _, header in ipairs(headers) do
    if shouldSignHeader(header[1], headersToSign) then
      table.insert(filteredHeaders, header)
    end
  end

  return filteredHeaders
end

local function normalizeWhiteSpacesInHeaderValue(value)
  value = string.format(" %s ", value)

  local normalizedValue = {}
  local n = 0

  for part in string.gmatch(value, "[^\"]+") do
    n = n + 1

    if n % 2 == 1 then
      part = part:gsub("%s+", " ")
    end

    table.insert(normalizedValue, part)
  end

  return utils.trim(table.concat(normalizedValue, "\""))
end

local function canonicalizeHeaders(headers, authHeaderName)
  local normalizedHeaders = {}

  for _, header in ipairs(headers) do
    local name = utils.trim(header[1]:lower())

    if name ~= authHeaderName:lower() then
      local value = normalizeWhiteSpacesInHeaderValue(header[2])

      table.insert(normalizedHeaders, { name, value })
    end
  end

  local groupedHeaders = {}
  local lastKey

  for _, header in ipairs(normalizedHeaders) do
    if lastKey == header[1] then
      groupedHeaders[#groupedHeaders] = string.format("%s,%s", groupedHeaders[#groupedHeaders], header[2])
    else
      table.insert(groupedHeaders, string.format("%s:%s", header[1], header[2]))
    end

    lastKey = header[1]
  end

  table.sort(groupedHeaders)

  return table.concat(groupedHeaders, "\n")
end

function Canonicalizer:canonicalizeSignedHeaders(headers, signedHeaders)
  local uniqueKeys = {}

  for _, header in pairs(headers) do
    local name = header[1]:lower()

    if name ~= self.authHeaderName:lower() then
      if utils.contains(signedHeaders, name) or name == self.dateHeaderName:lower() or name == "host" then
        uniqueKeys[name] = true
      end
    end
  end

  local normalizedKeys = {}

  for key, _ in pairs(uniqueKeys) do
    table.insert(normalizedKeys, key)
  end

  table.sort(normalizedKeys)

  return table.concat(normalizedKeys, ";")
end

function Canonicalizer:canonicalizeRequest(request, headersToSign)
  addIfNotExists(headersToSign, self.dateHeaderName)
  addIfNotExists(headersToSign, "Host")

  local url = urlhandler.parse(request.url):normalize()
  local headers = getHeadersToSign(request.headers, headersToSign)

  return table.concat({
    request.method,
    url.path,
    url.query,
    canonicalizeHeaders(headers, self.authHeaderName),
    "",
    self:canonicalizeSignedHeaders(headers, headersToSign),
    crypto.digest(self.hashAlgo, request.body or "")
  }, "\n")
end

return Canonicalizer
