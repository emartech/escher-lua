local openssl = require("resty.openssl")

assert(openssl.load_library())

local json = require("rapidjson")
local socketUrl = require("socket.url")
local date = require("date")
local Escher = require("escher")
local Canonicalizer = require("escher.canonicalizer")
local Signer = require("escher.signer")

local function readTest(filename)
  local f = io.open(filename, "r")
  local content = f:read("*all")

  f:close()

  return json.decode(content)
end

local function getConfigFromTestsuite(config)
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

local function runTestFiles(group, fn)
  local testFiles = {
    authenticate = {},
    presignUrl = {},
    signRequest = {},
  }

  for file in io.popen([[ls -pa test-cases/*/authenticate-*.json]]):lines() do
    table.insert(testFiles["authenticate"], file)
  end
  for file in io.popen([[ls -pa test-cases/*/presignurl-*.json]]):lines() do
    table.insert(testFiles["presignUrl"], file)
  end
  for file in io.popen([[ls -pa test-cases/*/signrequest-*.json]]):lines() do
    table.insert(testFiles["signRequest"], file)
  end

  for _, testFile in pairs(testFiles[group]) do
    fn(testFile, readTest(testFile))
  end
end

describe("Escher TestSuite", function()

  describe("load 'GET vanilla' JSON", function()

    it("should properly loaded", function()
      local test = readTest("test-cases/aws4_testsuite/signrequest-get-vanilla.json")

      assert.are.equals(test.request.method, "GET")
    end)

  end)

  local function findHeader(request, headerName)
    for _, element in ipairs(request.headers) do
      if element[1]:lower() == headerName:lower() then
        return element[2]
      end
    end
  end

  local function trim(str)
    return string.match(str, "^%s*(.-)%s*$")
  end

  local function dateDiffInSeconds(date1, date2)
    return date.diff(date(trim(date1)), date(trim(date2))):spanseconds()
  end

  describe("signRequest", function()

    runTestFiles("signRequest", function(testFile, test)
      it("should generate full authorization header " .. testFile, function()
        local escher = Escher(getConfigFromTestsuite(test.config))

        local dateHeaderBeforeSign = findHeader(test.request, escher.dateHeaderName)

        local result, err = escher:signRequest(test.request, test.headersToSign)

        local dateHeader = findHeader(test.request, escher.dateHeaderName)
        local authHeader = findHeader(test.request, escher.authHeaderName)

        if test.expected.error then
          assert.is.Not.True(result)
          assert.are.equals(test.expected.error, err)
        else
          assert.is.True(result)
        end

        if test.expected.canonicalizedRequest then
          assert.are.same(test.expected.canonicalizedRequest, escher.debugInfo["canonicalizedRequest"])
        end
        if test.expected.stringToSign then
          assert.are.same(test.expected.stringToSign, escher.debugInfo["stringToSign"])
        end
        if test.expected.authHeader then
          assert.are.same(test.expected.authHeader, authHeader)
        end
        if test.expected.request then
          assert.are.same(test.expected.request, test.request)
        end

        if dateHeaderBeforeSign then
          assert.are.same(dateHeaderBeforeSign, dateHeader)
        else
          assert.are.equals(0, dateDiffInSeconds(test.config.date, dateHeader))
        end
     end)
   end)

  end)

  describe("generatePreSignedUrl", function()

    runTestFiles("presignUrl", function(testFile, test)
      it("should return the proper url string" .. testFile, function()
        local escher = Escher(getConfigFromTestsuite(test.config))
        local client = { test.config.accessKeyId, test.config.apiSecret }
        local signedUrl = escher:generatePreSignedUrl(test.request.url, client, test.request.expires)

        assert.are.equals(test.expected.url, signedUrl)
      end)
    end)

  end)

  local function makeKeyRetriever(keyDb)
    return function(keyToFind)
      for _, keySecretPair in ipairs(keyDb) do
        local key = keySecretPair[1]
        local secret = keySecretPair[2]

        if key == keyToFind then
          return secret
        end
      end
    end
  end

  describe("authenticateRequest", function()

    runTestFiles("authenticate", function(testFile, test)
      it("should validate the request " .. testFile, function()
        local keyDb = makeKeyRetriever(test.keyDb)
        local escher = Escher(getConfigFromTestsuite(test.config))
        local apiKey, err = escher:authenticate(test.request, keyDb, test.mandatorySignedHeaders)

        if test.expected.apiKey then
          assert.are.equals(nil, err)
          assert.are.equals(test.expected.apiKey, apiKey)
        end

        if test.expected.error then
          assert.are.equals(test.expected.error, err)
          assert.are.equals(false, apiKey)
        end
      end)
    end)

  end)

end)
