local date = require("date")
local socketurl = require("socket.url")
local utils = require("escher.utils")
local Canonicalizer = require("escher.canonicalizer")
local Signer = require("escher.signer")

local ONE_DAY_IN_SECONDS = 86400
local UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"

local Escher = {}

local meta = {
  __index = Escher
}

function Escher:new(options)
  options = options or {}

  local object = {
    debugInfo = options.debugInfo,
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

  return setmetatable(object, meta)
end

setmetatable(Escher, {
  __call = Escher.new
})

local function getQueryParam(self, key)
  return table.concat({ "X", self.vendorKey, key }, "-")
end

local function getQueryParamEscaped(self, key)
  local escapedParam = string.gsub(getQueryParam(self, key), "-", "%%-")
  return escapedParam
end

local function getHeaderValue(headers, headerName)
  for _, header in ipairs(headers) do
    local name = utils.trim(header[1]:lower())

    if name == headerName:lower() then
      return header[2]
    end
  end
end

local function throwError(error, debugInfo)
  return false, error, debugInfo
end

local function parseQuery(self, query)
  query = socketurl.unescape(query)

  local algorithmPattern = getQueryParamEscaped(self ,"Algorithm") .. "=" .. self.algoPrefix .. "%-HMAC%-(%w+)"
  local credentialPattern = getQueryParamEscaped(self ,"Credentials") .. "=([A-Za-z0-9%-%_]+)/(%d+)/([A-Za-z0-9%-%_%/% ]+)"
  local signedHeadersPattern = getQueryParamEscaped(self ,"SignedHeaders") .. "=([a-z0-9%-%_%;]+)"
  local signaturePattern = getQueryParamEscaped(self ,"Signature") .. "=([a-f0-9]+)"

  local hashAlgo = string.match(query, algorithmPattern)
  local accessKeyId, shortDate, credentialScope = string.match(query, credentialPattern)
  local signedHeaders = string.match(query, signedHeadersPattern)
  local signature = string.match(query, signaturePattern)

  return {
    hashAlgo = hashAlgo,
    accessKeyId = accessKeyId,
    shortDate = shortDate,
    credentialScope = credentialScope,
    signedHeaders = signedHeaders,
    signature = signature
  }
end

local function stripSignatureFromQuery(self, url)
  local signaturePattern = getQueryParamEscaped(self ,"Signature") .. "=([a-f0-9]+)"
  local parts = {}

  for _, value in ipairs(utils.split(url, "&")) do
    if not string.match(value, signaturePattern) then
      table.insert(parts, value)
    end
  end

  return table.concat(parts, "&")
end

local function parseAuthHeader(self, authHeader)
  local hashAlgo, accessKeyId, shortDate, credentialScope, signedHeaders, signature = string.match(
    authHeader,
    self.algoPrefix .. "%-HMAC%-(%w+)" .. "%s+" ..
    table.concat({
      "Credential=([A-Za-z0-9%-%_]+)/(%d+)/([A-Za-z0-9%-%_%/% ]+)",
      "SignedHeaders=([a-zA-Z0-9%-%_%;]+)",
      "Signature=([a-f0-9]+)"
    }, ",%s*")
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

local function isDateWithinRange(requestDate, signedDate, maxDiffInSeconds)
  return math.abs(date.diff(requestDate, signedDate):spanseconds()) <= maxDiffInSeconds
end

local function getTimestampInSeconds(dateObject)
    return math.floor(date.diff(dateObject, date.epoch()):spanseconds())
end

function Escher:authenticate(request, getApiSecret, mandatorySignedHeaders)
  request = utils.merge({}, request)

  local query = socketurl.parse(request.url).query
  local isPresignedUrl = request.method == "GET" and query and string.match(query, getQueryParamEscaped(self ,"Signature"))

  local requestDate
  local authParts
  local expires

  if isPresignedUrl then
    requestDate = date(string.match(query, getQueryParamEscaped(self ,"Date") .. "=([A-Za-z0-9]+)"))
    authParts = parseQuery(self, query)
    expires = tonumber(string.match(query, getQueryParamEscaped(self ,"Expires") .."=([0-9]+)"))

    request.url = stripSignatureFromQuery(self, request.url)
    request.body = UNSIGNED_PAYLOAD
  else
    local dateHeader = getHeaderValue(request.headers, self.dateHeaderName)
    local authHeader = getHeaderValue(request.headers, self.authHeaderName)

    if not dateHeader then
      return throwError("The " .. self.dateHeaderName:lower() .. " header is missing")
    end

    if not authHeader then
      return throwError("The " .. self.authHeaderName:lower() .. " header is missing")
    end

    requestDate = date(dateHeader)
    authParts = parseAuthHeader(self, authHeader)
    expires = 0
  end

  local hostHeader = getHeaderValue(request.headers, "host")

  if not hostHeader then
    return throwError("The host header is missing")
  end

  if not authParts.hashAlgo then
    return throwError("Could not parse " .. self.authHeaderName .. " header")
  end

  local headersToSign = utils.split(authParts.signedHeaders, ";")

  for _, header in ipairs(headersToSign) do
    if string.lower(header) ~= header then
      return throwError("SignedHeaders must contain lowercase header names in the " .. self.authHeaderName .. " header")
    end
  end

  if type(mandatorySignedHeaders) ~= "table" and mandatorySignedHeaders ~= nil then
    return throwError("The mandatorySignedHeaders parameter must be undefined or array of strings")
  end

  mandatorySignedHeaders = utils.merge({}, mandatorySignedHeaders)

  table.insert(mandatorySignedHeaders, "host")

  if not isPresignedUrl then
    table.insert(mandatorySignedHeaders, self.dateHeaderName:lower())
  end

  for _, header in ipairs(mandatorySignedHeaders) do
    if type(header) ~= "string" then
      return throwError("The mandatorySignedHeaders parameter must be undefined or array of strings")
    end

    if not utils.contains(headersToSign, header) then
      return throwError("The " ..  header .. " header is not signed")
    end
  end

  if authParts.credentialScope ~= self.credentialScope then
    local debugInfo

    if self.debugInfo then
      debugInfo = self.credentialScope
    end

    return throwError("The credential scope is invalid", debugInfo)
  end

  if authParts.hashAlgo ~= self.hashAlgo then
    return throwError("Only " .. self.hashAlgo .. " hash algorithm is allowed")
  end

  if authParts.shortDate ~= utils.toShortDate(requestDate) then
    return throwError("The " .. self.authHeaderName .. " header's shortDate does not match with the request date")
  end

  if not isDateWithinRange(self.date, requestDate, self.clockSkew + expires) then
    local debugInfo

    if self.debugInfo then
      debugInfo = table.concat({
        "server timestamp: " .. getTimestampInSeconds(self.date),
        "request timestamp: " .. getTimestampInSeconds(requestDate),
        "clock skew: " .. self.clockSkew
      }, "\n")
    end

    return throwError("The request date is not within the accepted time range", debugInfo)
  end

  local apiSecret = getApiSecret(authParts.accessKeyId)

  if not apiSecret then
    return throwError("Invalid Escher key")
  end

  if authParts.signature ~= Signer(self):calculateSignature(request, headersToSign, date(requestDate), apiSecret) then
    local debugInfo

    if self.debugInfo then
      debugInfo = Canonicalizer(self):canonicalizeRequest(request, headersToSign)
    end

    return throwError("The signatures do not match", debugInfo)
  end

  return authParts.accessKeyId
end

local function hasHeader(headers, headerName)
  for _, values in ipairs(headers) do
    if values[1]:lower() == headerName:lower() then
      return true
    end
  end

  return false
end

local function addDateHeaderIfNotExists(self, headers)
  if not hasHeader(headers, self.dateHeaderName) then
    table.insert(headers, { self.dateHeaderName, self.date:fmt("${http}") })
  end
end

local function getAlgorithmId(self)
  return self.algoPrefix .. "-HMAC-" .. self.hashAlgo
end

local function getCredentials(self)
  return table.concat({ self.accessKeyId, utils.toShortDate(self.date), self.credentialScope }, "/")
end

function Escher:generateHeader(request, headersToSign)
  request = utils.merge({}, request)
  request.headers = utils.merge({}, request.headers)

  addDateHeaderIfNotExists(self, request.headers)

  return getAlgorithmId(self) .. " " .. table.concat({
    "Credential=" .. getCredentials(self),
    "SignedHeaders=" .. Canonicalizer(self):canonicalizeSignedHeaders(request.headers, headersToSign),
    "Signature=" .. Signer(self):calculateSignature(request, headersToSign, self.date, self.apiSecret)
  }, ", ")
end

function Escher:signRequest(request, headersToSign)
  local authHeader = self:generateHeader(request, headersToSign)

  addDateHeaderIfNotExists(self, request.headers)

  table.insert(request.headers, { self.authHeaderName, authHeader })
end

local function getHash(parsedUrl)
  if parsedUrl.fragment then
    return "#" .. parsedUrl.fragment
  end

  return ""
end

local function stripHash(parsedUrl)
  parsedUrl = utils.merge({}, parsedUrl)

  parsedUrl.fragment = ""

  local builtUrl = socketurl.build(parsedUrl)

  return string.gsub(builtUrl, "#", "")
end

local function encodeSlashes(str)
  return string.gsub(str, "/", "%%2F")
end

function Escher:generatePreSignedUrl(url, client, expires)
  expires = expires or ONE_DAY_IN_SECONDS

  local headersToSign = { "host" }
  local parsedUrl = socketurl.parse(socketurl.unescape(url))
  local hash = getHash(parsedUrl)

  if #hash > 0 then
    url = stripHash(parsedUrl)
  end

  local fullCredentials = encodeSlashes(client[1] .. "/" .. utils.toShortDate(self.date) .. "/" .. self.credentialScope)

  local signedUrl = table.concat({
    url,
    getQueryParam(self, "Algorithm") .. "=" .. getAlgorithmId(self),
    getQueryParam(self, "Credentials") .. "=" .. fullCredentials,
    getQueryParam(self, "Date") .. "=" .. utils.toLongDate(self.date),
    getQueryParam(self, "Expires") .. "=" .. expires,
    getQueryParam(self, "SignedHeaders") .. "=" .. table.concat(headersToSign, ";")
  }, "&") .. "&"

  local parsedSignedUrl = socketurl.parse(signedUrl)

  local host = parsedUrl.host

  local request = {
    host = host,
    method = "GET",
    url = parsedSignedUrl.path .. "?" .. parsedSignedUrl.query,
    headers = {
      { "host", host }
    },
    body = UNSIGNED_PAYLOAD
  }

  local signature = Signer(self):calculateSignature(request, headersToSign, self.date, self.apiSecret)

  return signedUrl .. getQueryParam(self, "Signature") .."=" .. signature  .. hash
end

return Escher
