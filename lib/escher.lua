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
  url = urlhandler.parse(request.url)
  url:normalize()
  headers = request.headers
  return table.concat({
    request.method,
    url.path,
    self:canonicalizeQuery(url.query or ""),
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
  table.sort(normalizedHeaders)
  return table.concat(normalizedHeaders, "\n")
end

function Escher:canonicalizeSignedHeaders(headers)
  local normalizedKeys = {}
  local n = 0
  for k, header in pairs(headers) do
    n = n+1
    normalizedKeys[n] = header[1]:lower()
  end
  table.sort(normalizedKeys)
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

function Escher:canonicalizeQuery(queryString)
  query = {}
  for k, v in string.gmatch(queryString, "([^&=?]+)=([^&=?]+)") do
    table.insert(query, self:urlEncode(self:urlDecode(k)) .. '=' .. self:urlEncode(self:urlDecode(v)))
  end
  table.sort(query)
  return table.concat(query, "&")
end

function Escher:normalizePath(base_path)
  relative_path = ''
	local path = base_path or ''
	if relative_path ~= "" then
		path = '/'..path:gsub("[^/]*$", "")
	end
	path = path .. relative_path
	path = path:gsub("([^/]*%./)", function (s)
		if s ~= "./" then return s else return "" end
	end)
	path = string.gsub(path, "/%.$", "/")
	local reduced
	while reduced ~= path do
		reduced = path
		path = string.gsub(reduced, "([^/]*/%.%./)", function (s)
			if s ~= "../../" then return "" else return s end
		end)
	end
	path = string.gsub(path, "([^/]*/%.%.?)$", function (s)
		if s ~= "../.." then return "" else return s end
	end)
	local reduced
	while reduced ~= path do
		reduced = path
		path = string.gsub(reduced, '^/?%.%./', '')
	end
  path = path:gsub("//+", "/")
  if path == '' then
    return "/"
  else
    return path
	end
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

function Escher:urlDecode(str)
  str = string.gsub (str, "+", " ")
  str = string.gsub (str, "%%(%x%x)",
      function(h) return string.char(tonumber(h,16)) end)
  str = string.gsub (str, "\r\n", "\n")
  return str
end

function Escher:urlEncode(str)
  if (str) then
    str = string.gsub (str, "\n", "\r\n")
    str = string.gsub (str, "([^%w %-%_%.%~])",
        function (c) return string.format ("%%%02X", string.byte(c)) end)
    str = string.gsub (str, " ", "+")
  end
  return str
end

return Escher
