
local json = require("json")
local Escher = require("escher")

function readTest(filename)
    local f = io.open(filename, "r")
    local content = f:read("*all")
    f:close()
    return json.decode(content)
end

function getConfigFromTestsuite(config)
  return {
    vendorKey = test.config.vendorKey,
    algoPrefix = test.config.algoPrefix,
    hashAlgo = test.config.hashAlgo,
    credentialScope = test.config.credentialScope,
    authHeaderName = test.config.authHeaderName,
    dateHeaderName = test.config.dateHeaderName,
    date = test.config.date
  }
end

describe("Escher TestSuite", function()

  describe('load "GET vanilla" JSON', function()

    it("should properly loaded", function()
      test = readTest('spec/aws4_testsuite/get-vanilla.json')
      assert.are.equals(test.request.method, "GET")
    end)

  end)

  describe('canonicalizeRequest', function()

    it("should canonicalize the request", function()
      test = readTest('spec/aws4_testsuite/get-vanilla.json')
      escher = Escher:new(getConfigFromTestsuite(test.config))
      canonicalized_request = escher:canonicalizeRequest(test.request)
      assert.are.equals(test.expected.canonicalizedRequest, canonicalized_request)
    end)

  end)

  describe('getStringToSign', function()

    it("should return the proper string to sign", function()
      test = readTest('spec/aws4_testsuite/get-vanilla.json')
      escher = Escher:new(getConfigFromTestsuite(test.config))
      canonicalized_request = escher:getStringToSign(test.request)
      assert.are.equals(test.expected.stringToSign, canonicalized_request)
    end)

  end)

end)
