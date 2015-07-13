
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
    vendorKey = config.vendorKey,
    algoPrefix = config.algoPrefix,
    hashAlgo = config.hashAlgo,
    credentialScope = config.credentialScope,
    authHeaderName = config.authHeaderName,
    dateHeaderName = config.dateHeaderName,
    accessKeyId = config.accessKeyId,
    apiSecret = config.apiSecret,
    date = config.date
  }
end

function runTestFiles(group, fn)
  testFiles = {
    signing = {
      'spec/aws4_testsuite/get-vanilla.json',
      'spec/aws4_testsuite/post-vanilla.json',
      'spec/aws4_testsuite/get-vanilla-query.json',
      'spec/aws4_testsuite/post-vanilla-query.json',
      'spec/aws4_testsuite/get-vanilla-empty-query-key.json',
      'spec/aws4_testsuite/post-vanilla-empty-query-value.json',
      'spec/aws4_testsuite/get-vanilla-query-order-key.json',
      'spec/aws4_testsuite/post-x-www-form-urlencoded.json',
      'spec/aws4_testsuite/post-x-www-form-urlencoded-parameters.json',
      'spec/aws4_testsuite/get-header-value-trim.json',
      'spec/aws4_testsuite/post-header-key-case.json',
      'spec/aws4_testsuite/post-header-key-sort.json',
      'spec/aws4_testsuite/post-header-value-case.json',
      'spec/aws4_testsuite/get-vanilla-query-order-value.json',
      'spec/aws4_testsuite/get-vanilla-query-order-key-case.json',
      'spec/aws4_testsuite/get-unreserved.json',
      'spec/aws4_testsuite/get-vanilla-query-unreserved.json',
      'spec/aws4_testsuite/get-vanilla-ut8-query.json',
      'spec/aws4_testsuite/get-utf8.json',
      'spec/aws4_testsuite/get-space.json',
      'spec/aws4_testsuite/post-vanilla-query-space.json',
      'spec/aws4_testsuite/post-vanilla-query-nonunreserved.json',
      'spec/aws4_testsuite/get-slash.json',
      'spec/aws4_testsuite/get-slashes.json',
      'spec/aws4_testsuite/get-slash-dot-slash.json',
      'spec/aws4_testsuite/get-slash-pointless-dot.json',
      'spec/aws4_testsuite/get-relative.json',
      'spec/aws4_testsuite/get-relative-relative.json',
      'spec/emarsys_testsuite/get-header-key-duplicate.json',
      'spec/emarsys_testsuite/get-header-value-order.json',
      'spec/emarsys_testsuite/post-header-key-order.json',
      'spec/emarsys_testsuite/post-header-value-spaces.json',
      'spec/emarsys_testsuite/post-header-value-spaces-within-quotes.json',
      'spec/emarsys_testsuite/post-payload-utf8.json'
    },
    validation = {
      'spec/emarsys_testsuite/valid-get-vanilla-empty-query.json'
    }
  }
  for k, testFile in pairs(testFiles[group]) do
    fn(testFile)
  end
end

describe("Escher TestSuite", function()

  describe('load "GET vanilla" JSON', function()

    it("should properly loaded", function()
      test = readTest('spec/aws4_testsuite/get-vanilla.json')
      assert.are.equals(test.request.method, "GET")
    end)

  end)

  describe('canonicalizeRequest', function()

    runTestFiles("signing", function(testFile)
      it("should canonicalize the request " .. testFile, function()
        local test = readTest(testFile)
        local escher = Escher:new(getConfigFromTestsuite(test.config))
        local canonicalizedRequest = escher:canonicalizeRequest(test.request)
        assert.are.equals(test.expected.canonicalizedRequest, canonicalizedRequest)
      end)
    end)

  end)

  describe('getStringToSign', function()

    runTestFiles("signing", function(testFile)
      it("should return the proper string to sign", function()
        local test = readTest(testFile)
        local escher = Escher:new(getConfigFromTestsuite(test.config))
        local stringToSign = escher:getStringToSign(test.request)
        assert.are.equals(test.expected.stringToSign, stringToSign)
      end)
    end)

  end)

  describe('generateHeader', function()

    runTestFiles("signing", function(testFile)
      it("should return the proper authHeader string", function()
        local test = readTest(testFile)
        local escher = Escher:new(getConfigFromTestsuite(test.config))
        local authHeader = escher:generateHeader(test.request)
        assert.are.equals(test.expected.authHeader, authHeader)
      end)
    end)

  end)

  describe('authenticateRequest', function()

    runTestFiles("validation", function(testFile)
      it("should validate the request", function()
        local test = readTest(testFile)
        local escher = Escher:new(getConfigFromTestsuite(test.config))
        local response = escher:authenticate(test.request)
        assert.are.equals(true, response)
      end)
    end)

  end)

end)
