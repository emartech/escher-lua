local crypto = require("crypto")
local date = require("date")
local urlhandler = require("escher.urlhandler")
local socketurl = require("socket.url")
local Escher = {
  algoPrefix      = 'ESR',
  vendorKey       = 'ESCHER',
  hashAlgo        = 'SHA256',
  credentialScope = 'escher_request',
  authHeaderName  = 'X-Escher-Auth',
  dateHeaderName  = 'X-Escher-Date',
  clockSkew       = 900,
  date            = false
}



function Escher:new(o)
  o = o or {}
  o.date = date(o.date or os.date("!%c"))
  setmetatable(o, self)
  self.__index = self
  return o
end



function Escher:authenticate(request, getApiSecret)
  local uri = socketurl.parse(request.url)
  local isPresignedUrl = string.match(uri.query or '', "Signature") and request.method == 'GET'

  local dateHeader = self:getHeader(request.headers, self.dateHeaderName)
  local authHeader = self:getHeader(request.headers, self.authHeaderName)
  local hostHeader = self:getHeader(request.headers, 'host')

  if dateHeader == nil and not isPresignedUrl then
    return self.throwError("The " .. self.dateHeaderName:lower() .. " header is missing")
  end

  if authHeader == nil and not isPresignedUrl then
    return self.throwError("The " .. self.authHeaderName:lower() .. " header is missing")
  end

  if hostHeader == nil then
    return self.throwError("The host header is missing")
  end

  local authParts
  local expires
  local requestDate

  if isPresignedUrl then
    requestDate = date(string.match(uri.query, 'Date=([A-Za-z0-9]+)&'))
    authParts = self:parseQuery(socketurl.unescape(uri.query))
    request.body = 'UNSIGNED-PAYLOAD';
    expires = tonumber(string.match(uri.query, 'Expires=([0-9]+)&'))
    request.url = self:canonicalizeUrl(request.url)
  else
    requestDate = date(dateHeader)
    authParts = self:parseAuthHeader(authHeader or '')
    expires = 0
  end

  if authParts.hashAlgo == nil then
    return self.throwError("Could not parse auth header")
  end

  if not string.match(authParts.signedHeaders, "host") then
    return self.throwError("The host header is not signed")
  end

  if not string.match(authParts.signedHeaders, "date") and not isPresignedUrl then
    return self.throwError("The date header is not signed")
  end

  if authParts.credentialScope ~= self.credentialScope then
    return self.throwError("The credential scope is invalid")
  end

  if authParts.hashAlgo ~= self.hashAlgo then
    return self.throwError("Only SHA256 and SHA512 hash algorithms are allowed")
  end

  if authParts.shortDate ~= requestDate:fmt("%Y%m%d") then
    return self.throwError("The credential date does not match with the request date")
  end

  if not self:isDateWithinRange(requestDate, expires) then
    return self.throwError("The request date is not within the accepted time range")
  end

  local apiSecret = getApiSecret(authParts.accessKeyId)

  if apiSecret == nil then
    return self.throwError("Invalid Escher key")
  end

  self.apiSecret = apiSecret
  self.date = date(requestDate)
  local headersToSign = splitter(authParts.signedHeaders, ';')

  if authParts.signature ~= self:calculateSignature(request, headersToSign) then
    return self.throwError("The signatures do not match")
  end

  return authParts.accessKeyId
end



function Escher:getHeader(headers, headerName)
  for _, header in ipairs(headers) do
    name = header[1]:lower():match("^%s*(.-)%s*$")
    if name == headerName:lower() then
      return header[2]
    end
  end
end



function Escher:canonicalizeRequest(request, headersToSign)
  local url = urlhandler.parse(request.url):normalize()
  local headers = self:filterHeaders(request.headers, headersToSign)
  return table.concat({
    request.method,
    url.path,
    url.query,
    self:canonicalizeHeaders(headers),
    "",
    self:canonicalizeSignedHeaders(headers),
    crypto.digest(self.hashAlgo, request.body or '')
  }, "\n")
end



function Escher:canonicalizeHeaders(headers)
  local normalizedHeaders = {}
  for _, header in ipairs(headers) do
    name = header[1]:lower():match("^%s*(.-)%s*$")
    if name ~= self.authHeaderName:lower() then
      value = self:normalizeWhiteSpacesInHeaderValue(header[2])
      table.insert(normalizedHeaders, { name, value })
    end
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
  for _, header in pairs(headers) do
    local name = header[1]:lower()
    if name ~= self.authHeaderName:lower() then
      uniqueKeys[name] = true
    end
  end

  local normalizedKeys = {}
  for key, _ in pairs(uniqueKeys) do
    table.insert(normalizedKeys, key)
  end

  table.sort(normalizedKeys)
  return table.concat(normalizedKeys, ";")
end



function Escher:getStringToSign(request, headersToSign)

  return table.concat({
    string.format('%s-HMAC-%s', self.algoPrefix, self.hashAlgo),
    self:toLongDate(),
    string.format('%s/%s', self:toShortDate(), self.credentialScope),
    crypto.digest(self.hashAlgo, self:canonicalizeRequest(request, headersToSign))
  }, "\n")
end



function Escher:normalizeWhiteSpacesInHeaderValue(value)
  value = string.format(" %s ", value)
  local normalizedValue = {}
  local n = 0
  for part in string.gmatch(value, '[^"]+') do
    n = n + 1
    if n % 2 == 1 then part = part:gsub("%s+", " ") end
    table.insert(normalizedValue, part)
  end
  return table.concat(normalizedValue, '"'):match("^%s*(.-)%s*$")
end



function Escher:generateHeader(request, headersToSign)
  headersToSign = headersToSign or {"host", self.dateHeaderName}
  return self.algoPrefix .. "-HMAC-" .. self.hashAlgo ..
          " Credential=" .. self:generateFullCredentials() ..
          ", SignedHeaders=" .. self:canonicalizeSignedHeaders(request.headers) ..
          ", Signature=" .. self:calculateSignature(request, headersToSign)
end



function Escher:calculateSignature(request, headersToSign)
  local stringToSign = self:getStringToSign(request, headersToSign)
  local signingKey = crypto.hmac.digest(self.hashAlgo, self:toShortDate(), self.algoPrefix .. self.apiSecret, true)

  for part in string.gmatch(self.credentialScope, "[A-Za-z0-9_\\-]+") do
    signingKey = crypto.hmac.digest(self.hashAlgo, part, signingKey, true)
  end

  return crypto.hmac.digest(self.hashAlgo, stringToSign, signingKey, false)
end



function Escher:parseAuthHeader(authHeader)
  local hashAlgo, accessKeyId, shortDate, credentialScope, signedHeaders, signature = string.match(authHeader,
    self.algoPrefix .. "%-HMAC%-(%w+)%s+" ..
            "Credential=([A-Za-z0-9%-%_]+)/(%d+)/([A-Za-z0-9%-%_%/]-),%s*" ..
            "SignedHeaders=([a-z0-9%-%_%;]+),%s*" ..
            "Signature=([a-f0-9]+)")
  return {
    hashAlgo = hashAlgo,
    accessKeyId = accessKeyId,
    shortDate = shortDate,
    credentialScope = credentialScope,
    signedHeaders = signedHeaders,
    signature = signature
  }
end



function Escher:parseQuery(query)
  local hashAlgo = string.match(query, self.algoPrefix .. "%-HMAC%-(%w+)&")
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



function Escher:toLongDate()
  return self.date:fmt("%Y%m%dT%H%M%SZ")
end



function Escher:toShortDate()
  return self.date:fmt("%Y%m%d")
end



function Escher:generateFullCredentials()
  return string.format("%s/%s/%s", self.accessKeyId, self:toShortDate(), self.credentialScope)
end



function Escher:isDateWithinRange(request_date, expires)
  local diff = math.abs(date.diff(self.date, request_date):spanseconds())
  return diff <= self.clockSkew + expires
end



function Escher.throwError(error)
  return false, error
end

function Escher:filterHeaders(headers, headersToSign)
  local filteredHeaders = {}
  local fullHeadersToSign = headersToSign

  for _, header in pairs(headers) do
    if self.headerNeedToSign(header[1], fullHeadersToSign) then
      table.insert(filteredHeaders, header)
    end
  end

  return filteredHeaders
end

function Escher.headerNeedToSign(headerName, headersToSign)
  local enable = false
  for _, header in pairs(headersToSign) do
    if headerName:lower() == header:lower() then
      enable = true
    end
  end

  return enable
end

function Escher:generatePreSignedUrl(url, client, expires)
  if expires == nil then
    expires = 86400
  end

  local parsedUrl = socketurl.parse(socketurl.unescape(url))
  local host = parsedUrl.host
  local headers = {{'host', host}}
  local headersToSign = {'host'}
  local body = 'UNSIGNED-PAYLOAD'
  local params = {
    Algorithm = self.algoPrefix .. '-HMAC-' .. self.hashAlgo,
    Credentials = string.gsub(client[1] .. '/' .. self:toShortDate() .. '/' .. self.credentialScope, '/', '%%2F'),
    Date = self:toLongDate(),
    Expires = expires,
    SignedHeaders = headersToSign[1],
  }

  local hash = ''
  if parsedUrl.fragment ~= nil then
    hash = '#' .. parsedUrl.fragment
    parsedUrl.fragment = ''
    url = string.gsub(socketurl.build(parsedUrl), "#", '')
  end

  local signedUrl = url .. "&" ..
          "X-EMS-Algorithm=" .. params.Algorithm .. '&' ..
          "X-EMS-Credentials=" .. params.Credentials .. '&' ..
          "X-EMS-Date=" .. params.Date .. '&' ..
          "X-EMS-Expires=" .. params.Expires .. '&' ..
          "X-EMS-SignedHeaders=" .. params.SignedHeaders .. '&'

  local parsedSignedUrl = socketurl.parse(signedUrl)
  local request = {
    host = host,
    method = 'GET',
    url = parsedSignedUrl.path .. '?' .. (parsedSignedUrl.query),
    headers = headers,
    body = body,
  }
  local signature = self:calculateSignature(request, headersToSign)
  signedUrl = signedUrl .. "X-EMS-Signature=" .. signature  .. hash
  return signedUrl
end

function Escher:canonicalizeUrl(url)
  local splittedUrl = splitter(url, "&")
  local canonicalizedUrl = ''

  for _, value in ipairs(splittedUrl) do
    if not string.match(value, "Signature") then
      canonicalizedUrl = canonicalizedUrl .. value .. "&"
    end
  end

  return string.sub(canonicalizedUrl, 1, -2)
end

function splitter(inputstr, sep)
  if sep == nil then
    sep = "%s"
  end
  local t={} ; i=1
  for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
    t[i] = str
    i = i + 1
  end
  return t
end

return Escher