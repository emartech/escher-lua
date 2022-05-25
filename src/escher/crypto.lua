local digest = require("resty.openssl.digest")
local hmac = require("resty.openssl.hmac")

local function binaryToHex(char)
  return string.format("%.2x", string.byte(char))
end

local crypto = {}

function crypto.digest(algorithm, inputString)
  local binary = digest.new(algorithm):final(inputString)

  local binaryAsHex = string.gsub(binary, ".", binaryToHex)

  return binaryAsHex
end

crypto.hmac = {}

function crypto.hmac.digest(algorithm, inputString, key, shouldReturnBinaryString)
  local binary = hmac.new(key, algorithm):final(inputString)

  if shouldReturnBinaryString then
    return binary
  end

  local binaryAsHex = string.gsub(binary, ".", binaryToHex)

  return binaryAsHex
end

return crypto
