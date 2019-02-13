local crypto = require("crypto")
local Canonicalizer = require("escher.canonicalizer")
local utils = require("escher.utils")

local Signer = {}

local meta = {
  __index = Signer
}

function Signer:new(options)
  local object = {
    authHeaderName = options.authHeaderName,
    dateHeaderName = options.dateHeaderName,
    credentialScope = options.credentialScope,
    hashAlgo = options.hashAlgo,
    algoPrefix = options.algoPrefix
  }

  return setmetatable(object, meta)
end

setmetatable(Signer, {
  __call = Signer.new
})

function Signer:getStringToSign(request, headersToSign, date)
  return table.concat({
    self.algoPrefix .. "-HMAC-" .. self.hashAlgo,
    utils.toLongDate(date),
    utils.toShortDate(date) .. "/" .. self.credentialScope,
    crypto.digest(self.hashAlgo, Canonicalizer(self):canonicalizeRequest(request, headersToSign))
  }, "\n")
end

local function getSigningKey(self, date, secret)
  local signingKey = crypto.hmac.digest(self.hashAlgo, utils.toShortDate(date), self.algoPrefix .. secret, true)

  for part in string.gmatch(self.credentialScope, "[A-Za-z0-9_\\-]+") do
    signingKey = crypto.hmac.digest(self.hashAlgo, part, signingKey, true)
  end

  return signingKey
end

function Signer:calculateSignature(request, headersToSign, date, secret)
  local stringToSign = self:getStringToSign(request, headersToSign, date, secret)
  local signingKey = getSigningKey(self, date, secret)

  return crypto.hmac.digest(self.hashAlgo, stringToSign, signingKey, false)
end

return Signer
