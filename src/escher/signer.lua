local crypto = require("escher.crypto")
local Canonicalizer = require("escher.canonicalizer")
local utils = require("escher.utils")

local Signer = {}

local meta = {
  __index = Signer
}

function Signer:new(options)
  local object = {
    debugInfo = {},
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
  local canonicalizedRequest = Canonicalizer(self):canonicalizeRequest(request, headersToSign)
  self.debugInfo['canonicalizedRequest'] = canonicalizedRequest

  return table.concat({
    self.algoPrefix .. "-HMAC-" .. self.hashAlgo,
    utils.toLongDate(date),
    utils.toShortDate(date) .. "/" .. self.credentialScope,
    crypto.digest(self.hashAlgo, canonicalizedRequest)
  }, "\n")
end

local function getSigningKey(self, date, secret)
  local signingKey = crypto.hmac.digest(self.hashAlgo, utils.toShortDate(date), self.algoPrefix .. secret, true)

  for _, value in ipairs(utils.split(self.credentialScope, "/")) do
    signingKey = crypto.hmac.digest(self.hashAlgo, value, signingKey, true)
  end

  return signingKey
end

function Signer:calculateSignature(request, headersToSign, date, secret)
  local stringToSign = self:getStringToSign(request, headersToSign, date)
  self.debugInfo['stringToSign'] = stringToSign

  local signingKey = getSigningKey(self, date, secret)

  return crypto.hmac.digest(self.hashAlgo, stringToSign, signingKey, false)
end

return Signer
