local json = require("rapidjson")
local Escher = require("escher")
local socketUrl = require("socket.url")

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
      'spec/aws4_testsuite/signrequest-get-vanilla.json',
      'spec/aws4_testsuite/signrequest-post-vanilla.json',
      'spec/aws4_testsuite/signrequest-get-vanilla-query.json',
      'spec/aws4_testsuite/signrequest-post-vanilla-query.json',
      'spec/aws4_testsuite/signrequest-get-vanilla-empty-query-key.json',
      'spec/aws4_testsuite/signrequest-post-vanilla-empty-query-value.json',
      'spec/aws4_testsuite/signrequest-get-vanilla-query-order-key.json',
      'spec/aws4_testsuite/signrequest-post-x-www-form-urlencoded.json',
      'spec/aws4_testsuite/signrequest-post-x-www-form-urlencoded-parameters.json',
      'spec/aws4_testsuite/signrequest-get-header-value-trim.json',
      'spec/aws4_testsuite/signrequest-post-header-key-case.json',
      'spec/aws4_testsuite/signrequest-post-header-key-sort.json',
      'spec/aws4_testsuite/signrequest-post-header-value-case.json',
      'spec/aws4_testsuite/signrequest-get-vanilla-query-order-value.json',
      'spec/aws4_testsuite/signrequest-get-vanilla-query-order-key-case.json',
      'spec/aws4_testsuite/signrequest-get-unreserved.json',
      'spec/aws4_testsuite/signrequest-get-vanilla-query-unreserved.json',
      'spec/aws4_testsuite/signrequest-get-vanilla-ut8-query.json',
      'spec/aws4_testsuite/signrequest-get-utf8.json',
      'spec/aws4_testsuite/signrequest-get-space.json',
      'spec/aws4_testsuite/signrequest-post-vanilla-query-space.json',
      'spec/aws4_testsuite/signrequest-post-vanilla-query-nonunreserved.json',
      'spec/aws4_testsuite/signrequest-get-slash.json',
      'spec/aws4_testsuite/signrequest-get-slashes.json',
      'spec/aws4_testsuite/signrequest-get-slash-dot-slash.json',
      'spec/aws4_testsuite/signrequest-get-slash-pointless-dot.json',
      'spec/aws4_testsuite/signrequest-get-relative.json',
      'spec/aws4_testsuite/signrequest-get-relative-relative.json',
      'spec/emarsys_testsuite/signrequest-get-header-key-duplicate.json',
      'spec/emarsys_testsuite/signrequest-get-header-value-order.json',
      'spec/emarsys_testsuite/signrequest-post-header-key-order.json',
      'spec/emarsys_testsuite/signrequest-post-header-value-spaces.json',
      'spec/emarsys_testsuite/signrequest-post-header-value-spaces-within-quotes.json',
      'spec/emarsys_testsuite/signrequest-post-payload-utf8.json',
      'spec/emarsys_testsuite/signrequest-date-header-should-be-signed-headers.json',
      'spec/emarsys_testsuite/signrequest-only-sign-specified-headers.json',
      'spec/emarsys_testsuite/signrequest-support-custom-config.json',
    },
    validation = {
      'spec/emarsys_testsuite/authenticate-error-date-header-auth-header-date-not-equal.json',
      'spec/emarsys_testsuite/authenticate-error-date-header-not-signed.json',
      'spec/emarsys_testsuite/authenticate-error-host-header-not-signed.json',
      'spec/emarsys_testsuite/authenticate-error-invalid-auth-header.json',
      'spec/emarsys_testsuite/authenticate-error-invalid-credential-scope.json',
      'spec/emarsys_testsuite/authenticate-error-invalid-escher-key.json',
      'spec/emarsys_testsuite/authenticate-error-invalid-hash-algorithm.json',
      'spec/emarsys_testsuite/authenticate-error-missing-auth-header.json',
      'spec/emarsys_testsuite/authenticate-error-missing-date-header.json',
      'spec/emarsys_testsuite/authenticate-error-missing-host-header.json',
      'spec/emarsys_testsuite/authenticate-error-presigned-url-expired.json',
      'spec/emarsys_testsuite/authenticate-error-request-date-invalid.json',
      'spec/emarsys_testsuite/authenticate-error-wrong-signature.json',
      'spec/emarsys_testsuite/authenticate-valid-authentication-datein-expiretime.json',
      'spec/emarsys_testsuite/authenticate-valid-get-vanilla-empty-query-with-custom-headernames.json',
      'spec/emarsys_testsuite/authenticate-valid-get-vanilla-empty-query.json',
      'spec/emarsys_testsuite/authenticate-valid-ignore-headers-order.json',
      'spec/emarsys_testsuite/authenticate-valid-presigned-url-with-query.json',
      'spec/emarsys_testsuite/authenticate-valid-presigned-double-url-encoded.json'
    },
    generateSignedUrl = {
      'spec/emarsys_testsuite/presignurl-valid-with-path-query.json',
      'spec/emarsys_testsuite/presignurl-valid-with-port.json',
      'spec/emarsys_testsuite/presignurl-valid-with-hash.json',
      'spec/emarsys_testsuite/presignurl-valid-with-URL-encoded-array-parameters.json',
      'spec/emarsys_testsuite/presignurl-valid-with-double-url-encoded.json'
    },
    generateAndAuthenticate = {
      'spec/emarsys_testsuite/authenticate-valid-with-generating-presigned-url-with-query.json',
    }
  }
  for _, testFile in pairs(testFiles[group]) do
    fn(testFile, readTest(testFile))
  end
end

describe("Escher TestSuite", function()

  describe('load "GET vanilla" JSON', function()

    it("should properly loaded", function()
      test = readTest('spec/aws4_testsuite/signrequest-get-vanilla.json')
      assert.are.equals(test.request.method, "GET")
    end)

  end)

  describe('canonicalizeRequest', function()

    runTestFiles("signing", function(testFile, test)
      it("should canonicalize the request " .. testFile, function()
        local escher = Escher:new(getConfigFromTestsuite(test.config))
        local canonicalizedRequest = escher:canonicalizeRequest(test.request, test.headersToSign)

        if test.expected.canonicalizedRequest then
          assert.are.equals(test.expected.canonicalizedRequest, canonicalizedRequest)
        end
      end)
    end)

  end)

  describe('getStringToSign', function()

    runTestFiles("signing", function(testFile, test)
      it("should return the proper string to sign " .. testFile, function()
        local escher = Escher:new(getConfigFromTestsuite(test.config))
        local stringToSign = escher:getStringToSign(test.request, test.headersToSign)
        if test.expected.stringToSign then
          assert.are.equals(test.expected.stringToSign, stringToSign)
        end
      end)
    end)

  end)

  describe('generatePreSignedUrl', function()

    runTestFiles("generateSignedUrl", function(testFile, test)
      it("should return the proper url string" .. testFile, function()
        local escher = Escher:new(getConfigFromTestsuite(test.config))
        local client = {test.config.accessKeyId, test.config.apiSecret}
        local signedUrl = escher:generatePreSignedUrl(test.request.url, client, test.request.expires)

        if test.expected.url then
          assert.are.equals(test.expected.url, signedUrl)
        end
      end)
    end)

  end)

  describe('authenticateRequest', function()

    runTestFiles("validation", function(testFile, test)
      it("should validate the request " .. testFile, function()
        local escher = Escher:new(getConfigFromTestsuite(test.config))
        local getApiSecret = function(key)
          for _, element in pairs(test.keyDb) do
            if element[1] == key then
              return element[2]
            end
          end
        end
        local apiKey, err = escher:authenticate(test.request, getApiSecret)
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

  describe('generateAndAuthenticatePreSignedUrl', function()

    runTestFiles("generateAndAuthenticate", function(testFile, test)
      it("should validate the request " .. testFile, function()
        local escher = Escher:new(getConfigFromTestsuite(test.config))
        local client = {test.config.accessKeyId, test.config.apiSecret}

        local getApiSecret = function(key)
          for _, element in pairs(test.keyDb) do
            if element[1] == key then
              return element[2]
            end
          end
        end

        test.request.url = escher:generatePreSignedUrl(test.request.url, client, test.request.expires)
        local request = createRequestFromUrl(test.request.url)
        local apiKey, err = escher:authenticate(request, getApiSecret)
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

function createRequestFromUrl(url)
  local parsedUrl = socketUrl.parse(url)
  local buildedUrl = ''
  local enableBuild = false

  for _,v in ipairs(socketUrl.parse_path(url)) do
    if enableBuild then
      buildedUrl = buildedUrl .. '/' .. v
    elseif string.find(v, parsedUrl.host) ~= nil then
      enableBuild = true
    end
  end

  return {
    method = 'GET',
    url = buildedUrl,
    body = "",
    headers = {{'Host', parsedUrl.host}}
  }
end