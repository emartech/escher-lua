local crypto = require("crypto")
local date = require("date")
local urlhandler = require("escher.urlhandler")
local socketurl = require("socket.url")

local LONG_DATE_FORMAT = "%Y%m%dT%H%M%SZ"
local SHORT_DATE_FORMAT = "%Y%m%d"

local Escher = {}

Escher.__index = Escher

function Escher:new(options)
  options = options or {}

  local object = {
    algoPrefix = options.algoPrefix or "ESR",
    vendorKey = options.vendorKey or "ESCHER",
    hashAlgo = options.hashAlgo or "SHA256",
    apiSecret = options.apiSecret,
    accessKeyId = options.accessKeyId,
    credentialScope = options.credentialScope or "escher_request",
    authHeaderName = options.authHeaderName or "X-Escher-Auth",
    dateHeaderName = options.dateHeaderName or "X-Escher-Date",
    date = date(options.date or os.date("!%c")),
    clockSkew = options.clockSkew or 300
  }

  return setmetatable(object, self)
end

local function contains(table, element)
  for _, value in pairs(table) do
    if value:lower() == element:lower() then
      return true
    end
  end

  return false
end

local function split(str, separator)
  local pieces = {}
  local i = 1

  for matched in string.gmatch(str, "([^" .. separator .. "]+)") do
    pieces[i] = matched
    i = i + 1
  end

  return pieces
end

local function trim(str)
  return string.match(str, "^%s*(.-)%s*$")
end

local function merge(target, ...)
  if not target then return target end

  for _, obj in pairs({...}) do
    if obj then
      for k, v in pairs(obj) do
        target[k] = v
      end
    end
  end

  return target
end

local function getHeaderValue(headers, headerName)
  for _, header in ipairs(headers) do
    local name = trim(header[1]:lower())

    if name == headerName:lower() then
      return header[2]
    end
  end
end

local function throwError(error)
  return false, error
end

local function parseQuery(query, algoPrefix)
  local hashAlgo = string.match(query, algoPrefix .. "%-HMAC%-(%w+)&")
  local accessKeyId, shortDate, credentialScope = string.match(query, "Credentials=([A-Za-z0-9%-%_]+)/(%d+)/([A-Za-z0-9%-%_%/]-)&")
  local signedHeaders = string.match(query, "SignedHeaders=([a-z0-9%-%_%;]+)&")
  local signature = string.match(query, "Signature=([a-f0-9]+)")

  return {
    hashAlgo = hashAlgo,
    accessKeyId = accessKeyId,
    shortDate = shortDate,
    credentialScope = credentialScope,
    signedHeaders = signedHeaders,
    signature = signature
  }
end

local function canonicalizeUrl(url)
  local canonicalizedUrl = ""

  for _, value in ipairs(split(url, "&")) do
    if not string.match(value, "Signature") then
      canonicalizedUrl = canonicalizedUrl .. value .. "&"
    end
  end

  return string.sub(canonicalizedUrl, 1, -2)
end

local function parseAuthHeader(authHeader, algoPrefix)
  local hashAlgo, accessKeyId, shortDate, credentialScope, signedHeaders, signature = string.match(
    authHeader,
    algoPrefix ..
    "%-HMAC%-(%w+)%s+" ..
    "Credential=([A-Za-z0-9%-%_]+)/(%d+)/([A-Za-z0-9%-%_%/% ]-),%s*" ..
    "SignedHeaders=([a-zA-Z0-9%-%_%;]+),%s*" ..
    "Signature=([a-f0-9]+)"
  )

  return {
    hashAlgo = hashAlgo,
    accessKeyId = accessKeyId,
    shortDate = shortDate,
    credentialScope = credentialScope,
    signedHeaders = signedHeaders,
    signature = signature
  }
end

local function isDateWithinRange(requestDate, signedDate, expires)
  local diff = math.abs(date.diff(requestDate, signedDate):spanseconds())

  return diff <= expires
end

local function addIfNotExists(headers, defaultHeaderName)
  if not contains(headers, defaultHeaderName) then
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

  return trim(table.concat(normalizedValue, "\""))
end

local function canonicalizeHeaders(headers, authHeaderName)
  local normalizedHeaders = {}

  for _, header in ipairs(headers) do
    local name = trim(header[1]:lower())

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

local function canonicalizeSignedHeaders(self, headers, signedHeaders)
  local uniqueKeys = {}

  for _, header in pairs(headers) do
    local name = header[1]:lower()

    if name ~= self.authHeaderName:lower() then
      if (contains(signedHeaders, name) or name == self.dateHeaderName:lower() or name == "host") then
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

local function canonicalizeRequest(self, request, headersToSign)
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
    canonicalizeSignedHeaders(self, headers, headersToSign),
    crypto.digest(self.hashAlgo, request.body or "")
  }, "\n")
end

local function getStringToSign(self, request, headersToSign)
  return table.concat({
    string.format("%s-HMAC-%s", self.algoPrefix, self.hashAlgo),
    self.date:fmt(LONG_DATE_FORMAT),
    string.format("%s/%s", self.date:fmt(SHORT_DATE_FORMAT), self.credentialScope),
    crypto.digest(self.hashAlgo, canonicalizeRequest(self, request, headersToSign))
  }, "\n")
end

local function calculateSignature(self, request, headersToSign)
  local stringToSign = getStringToSign(self, request, headersToSign)
  local signingKey = crypto.hmac.digest(self.hashAlgo, self.date:fmt(SHORT_DATE_FORMAT), self.algoPrefix .. self.apiSecret, true)

  for part in string.gmatch(self.credentialScope, "[A-Za-z0-9_\\-]+") do
    signingKey = crypto.hmac.digest(self.hashAlgo, part, signingKey, true)
  end

  return crypto.hmac.digest(self.hashAlgo, stringToSign, signingKey, false)
end

function Escher:authenticate(request, getApiSecret, mandatorySignedHeaders)
  request = merge({}, request)

  local uri = socketurl.parse(request.url)
  local isPresignedUrl = string.match(uri.query or "", "Signature") and request.method == "GET"

  local dateHeader = getHeaderValue(request.headers, self.dateHeaderName)
  local authHeader = getHeaderValue(request.headers, self.authHeaderName)
  local hostHeader = getHeaderValue(request.headers, "host")

  if not dateHeader and not isPresignedUrl then
    return throwError("The " .. self.dateHeaderName:lower() .. " header is missing")
  end

  if not authHeader and not isPresignedUrl then
    return throwError("The " .. self.authHeaderName:lower() .. " header is missing")
  end

  if not hostHeader then
    return throwError("The host header is missing")
  end

  local authParts
  local expires
  local requestDate

  if isPresignedUrl then
    requestDate = date(string.match(uri.query, "Date=([A-Za-z0-9]+)&"))
    authParts = parseQuery(socketurl.unescape(uri.query), self.algoPrefix)
    expires = tonumber(string.match(uri.query, "Expires=([0-9]+)&"))
    request.url = canonicalizeUrl(request.url)
    request.body = "UNSIGNED-PAYLOAD"
  else
    requestDate = date(dateHeader)
    authParts = parseAuthHeader(authHeader or "", self.algoPrefix)
    expires = 0
  end

  if not authParts.hashAlgo then
    return throwError("Could not parse " .. self.authHeaderName .. " header")
  end

  local headersToSign = split(authParts.signedHeaders, ";")

  for _, header in ipairs(headersToSign) do
    if string.lower(header) ~= header then
      return throwError("SignedHeaders must contain lowercase header names in the " .. self.authHeaderName .. " header")
    end
  end

  if type(mandatorySignedHeaders) ~= "table" and mandatorySignedHeaders ~= nil then
    return throwError("The mandatorySignedHeaders parameter must be undefined or array of strings")
  end

  mandatorySignedHeaders = merge({}, mandatorySignedHeaders)

  table.insert(mandatorySignedHeaders, "host")

  if not isPresignedUrl then
    table.insert(mandatorySignedHeaders, self.dateHeaderName:lower())
  end

  for _, header in ipairs(mandatorySignedHeaders) do
    if type(header) ~= "string" then
      return throwError("The mandatorySignedHeaders parameter must be undefined or array of strings")
    end

    if not contains(headersToSign, header) then
      return throwError("The " ..  header .. " header is not signed")
    end
  end

  if authParts.credentialScope ~= self.credentialScope then
    return throwError("The credential scope is invalid")
  end

  if authParts.hashAlgo ~= self.hashAlgo then
    return throwError("Only SHA256 and SHA512 hash algorithms are allowed")
  end

  if authParts.shortDate ~= requestDate:fmt("%Y%m%d") then
    return throwError("The " .. self.authHeaderName .. " header's shortDate does not match with the request date")
  end

  if not isDateWithinRange(self.date, requestDate, self.clockSkew + expires) then
    return throwError("The request date is not within the accepted time range")
  end

  local apiSecret = getApiSecret(authParts.accessKeyId)

  if apiSecret == nil then
    return throwError("Invalid Escher key")
  end

  self.apiSecret = apiSecret
  self.date = date(requestDate)

  if authParts.signature ~= calculateSignature(self, request, headersToSign) then
    return throwError("The signatures do not match")
  end

  return authParts.accessKeyId
end

local function addDateHeaderIfNotExists(self, headers)
  local insertDate = true

  for _, values in ipairs(headers) do
    if values[1]:lower() == self.dateHeaderName:lower() then
      insertDate = false
    end
  end

  if insertDate then
    table.insert(headers, { self.dateHeaderName, self.date:fmt("${http}") })
  end
end

local function generateFullCredentials(self)
  return string.format("%s/%s/%s", self.accessKeyId, self.date:fmt(SHORT_DATE_FORMAT), self.credentialScope)
end

function Escher:generateHeader(request, headersToSign)
  request = merge({}, request)
  request.headers = merge({}, request.headers)

  addDateHeaderIfNotExists(self, request.headers)

  return self.algoPrefix .. "-HMAC-" .. self.hashAlgo ..
    " Credential=" .. generateFullCredentials(self) ..
    ", SignedHeaders=" .. canonicalizeSignedHeaders(self, request.headers, headersToSign) ..
    ", Signature=" .. calculateSignature(self, request, headersToSign)
end

function Escher:signRequest(request, headersToSign)
  local authHeader = self:generateHeader(request, headersToSign)

  addDateHeaderIfNotExists(self, request.headers)

  table.insert(request.headers, { self.authHeaderName, authHeader })
end

function Escher:generatePreSignedUrl(url, client, expires)
  expires = expires or 86400

  local parsedUrl = socketurl.parse(socketurl.unescape(url))
  local host = parsedUrl.host
  local headers = {
    { "host", host }
  }
  local headersToSign = { "host" }
  local body = "UNSIGNED-PAYLOAD"
  local params = {
    Algorithm = self.algoPrefix .. "-HMAC-" .. self.hashAlgo,
    Credentials = string.gsub(client[1] .. "/" .. self.date:fmt(SHORT_DATE_FORMAT) .. "/" .. self.credentialScope, "/", "%%2F"),
    Date = self.date:fmt(LONG_DATE_FORMAT),
    Expires = expires,
    SignedHeaders = headersToSign[1]
  }
  local hash = ""

  if parsedUrl.fragment ~= nil then
    hash = "#" .. parsedUrl.fragment
    parsedUrl.fragment = ""
    url = string.gsub(socketurl.build(parsedUrl), "#", "")
  end

  local signedUrl = url .. "&" ..
    "X-EMS-Algorithm=" .. params.Algorithm .. "&" ..
    "X-EMS-Credentials=" .. params.Credentials .. "&" ..
    "X-EMS-Date=" .. params.Date .. "&" ..
    "X-EMS-Expires=" .. params.Expires .. "&" ..
    "X-EMS-SignedHeaders=" .. params.SignedHeaders .. "&"

  local parsedSignedUrl = socketurl.parse(signedUrl)
  local request = {
    host = host,
    method = "GET",
    url = parsedSignedUrl.path .. "?" .. (parsedSignedUrl.query),
    headers = headers,
    body = body
  }
  local signature = calculateSignature(self, request, headersToSign)

  return signedUrl .. "X-EMS-Signature=" .. signature  .. hash
end

Escher.canonicalizeRequest = canonicalizeRequest
Escher.getStringToSign = getStringToSign

return Escher
