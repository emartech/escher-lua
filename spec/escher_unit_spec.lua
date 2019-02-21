local Escher = require("escher")

describe("Escher", function()

  describe("#new", function()

    it("should not mutate passed in parameters", function()
      local options = {
        algoPrefix = "AWS4",
        vendorKey = "AWS4",
        hashAlgo = "SHA256",
        apiSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        accessKeyId = "AKIDEXAMPLE",
        credentialScope = "my/custom/scope",
        authHeaderName = "X-EMS-Auth",
        dateHeaderName = "X-EMS-Date",
        date = "2019-01-10T20:25:00.000Z",
        clockSkew = 300
      }

      local escher = Escher:new(options)

      assert.are.Not.equals(options, escher)
      assert.are.same({
        algoPrefix = "AWS4",
        vendorKey = "AWS4",
        hashAlgo = "SHA256",
        apiSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        accessKeyId = "AKIDEXAMPLE",
        credentialScope = "my/custom/scope",
        authHeaderName = "X-EMS-Auth",
        dateHeaderName = "X-EMS-Date",
        date = "2019-01-10T20:25:00.000Z",
        clockSkew = 300
      }, options)
    end)

  end)

  describe("constructor", function()

    it("should create an Escher instance", function()
      local options = {
        algoPrefix = "AWS4",
        vendorKey = "AWS4",
        hashAlgo = "SHA256",
        apiSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        accessKeyId = "AKIDEXAMPLE",
        credentialScope = "my/custom/scope",
        authHeaderName = "X-EMS-Auth",
        dateHeaderName = "X-EMS-Date",
        date = "2019-01-10T20:25:00.000Z",
        clockSkew = 300
      }

      assert.are.same(
        Escher:new(options),
        Escher(options)
      )
    end)

  end)

  describe("#authenticate", function()

    it("should not mutate passed in parameters", function()
      local escher = Escher:new({
        algoPrefix = "AWS4",
        vendorKey = "AWS4",
        hashAlgo = "SHA256",
        credentialScope = "us-east-1/host/aws4_request",
        authHeaderName = "X-EMS-Auth",
        dateHeaderName = "X-EMS-Date",
        date = "2011-09-09T23:36:00.000Z"
      })

      local request = {
        method = "GET",
        url = "/",
        headers = {
          { "X-EMS-Date", "20110909T233600Z" },
          { "Host", "host.foo.com" },
          { "X-EMS-Auth", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=x-ems-date;host, Signature=3a2b15801d517d0010be640f0685fa60b5d793396be38e0566ede3d334554479" }
        },
        body = ""
      }

      local function keyDb()
        return "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
      end

      local headersToSign = { "x-ems-date" }

      escher:authenticate(request, keyDb, headersToSign)

      assert.are.same({
        method = "GET",
        url = "/",
        headers = {
          { "X-EMS-Date", "20110909T233600Z" },
          { "Host", "host.foo.com" },
          { "X-EMS-Auth", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=x-ems-date;host, Signature=3a2b15801d517d0010be640f0685fa60b5d793396be38e0566ede3d334554479" }
        },
        body = ""
      }, request)
      assert.are.same({ "x-ems-date" }, headersToSign)
    end)

    context("when URL is pre-signed", function()

      it("should not mutate passed in parameters", function()
        local escher = Escher:new({
          algoPrefix = "EMS",
          vendorKey = "EMS",
          hashAlgo = "SHA256",
          credentialScope = "us-east-1/host/aws4_request",
          date = "2011-05-11T12:00:00.000Z"
        })

        local request = {
          method = "GET",
          url = "/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67",
          headers = {
            { "Host", "example.com" }
          },
          body = ""
        }

        local function keyDb()
          return "very_secure"
        end

        local headersToSign = {}

        escher:authenticate(request, keyDb, headersToSign)

        assert.are.same({
          method = "GET",
          url = "/something?foo=bar&baz=barbaz&X-EMS-Algorithm=EMS-HMAC-SHA256&X-EMS-Credentials=th3K3y%2F20110511%2Fus-east-1%2Fhost%2Faws4_request&X-EMS-Date=20110511T120000Z&X-EMS-Expires=123456&X-EMS-SignedHeaders=host&X-EMS-Signature=fbc9dbb91670e84d04ad2ae7505f4f52ab3ff9e192b8233feeae57e9022c2b67",
          headers = {
            { "Host", "example.com" }
          },
          body = ""
        }, request)
        assert.are.same({}, headersToSign)
      end)

    end)

    context("debug mode", function()

      local function keyDb()
        return "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
      end

      local config, authHeader, request

      local function replaceAuthHeader(pattern, replace)
        authHeader[2] = string.gsub(authHeader[2], pattern, replace)
      end

      before_each(function()
        config = {
          algoPrefix = "AWS4",
          vendorKey = "AWS4",
          hashAlgo = "SHA256",
          credentialScope = "us-east-1/host/aws4_request",
          authHeaderName = "X-EMS-Auth",
          dateHeaderName = "X-EMS-Date",
          date = "2011-09-09T23:36:00.000Z",
          apiSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
          accessKeyId = "AKIDEXAMPLE"
        }

        authHeader = { "X-EMS-Auth", "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=x-ems-date;host, Signature=3a2b15801d517d0010be640f0685fa60b5d793396be38e0566ede3d334554479" }

        request = {
          method = "GET",
          url = "/",
          headers = {
            { "X-EMS-Date", "20110909T233600Z" },
            { "Host", "host.foo.com" },
            authHeader
          },
          body = ""
        }
      end)

      context("is enabled", function()

        before_each(function()
          config.debugInfo = true
        end)

        it("should return canonicalized request if signatures do not match", function()
          local escher = Escher(config)

          replaceAuthHeader("Signature=.*", "Signature=bad_signature")

          local success, err, debugInfo = escher:authenticate(request, keyDb)

          assert.is_false(success)
          assert.is_equal("The signatures do not match", err)
          assert.is_equal(table.concat({
            "GET",
            "/",
            "",
            "host:host.foo.com",
            "x-ems-date:20110909T233600Z",
            "",
            "host;x-ems-date",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
          }, "\n"), debugInfo)
        end)

        it("should return date info if request is out of time range", function()
          config.date = "2011-09-10T23:36:00.000Z"
          config.clockSkew = 300

          local escher = Escher(config)

          local success, err, debugInfo = escher:authenticate(request, keyDb)

          assert.is_false(success)
          assert.is_equal("The request date is not within the accepted time range", err)
          assert.is_equal(table.concat({
            "server timestamp: 1315697760",
            "request timestamp: 1315611360",
            "clock skew: 300"
          }, "\n"), debugInfo)
        end)

        it("should return credential scope if bad credential scope used", function()
          config.credentialScope = "us-east-2/host/aws4_request"

          local escher = Escher(config)

          local success, err, debugInfo = escher:authenticate(request, keyDb)

          assert.is_false(success)
          assert.is_equal("The credential scope is invalid", err)
          assert.is_equal("us-east-2/host/aws4_request", debugInfo)
        end)

      end)

      context("is disabled", function()

        before_each(function()
          config.debugInfo = false
        end)

        it("should not return debug info if signatures do not match", function()
          local escher = Escher(config)

          replaceAuthHeader("Signature=.*", "Signature=bad_signature")

          local success, err, debugInfo = escher:authenticate(request, keyDb)

          assert.is_false(success)
          assert.is_equal("The signatures do not match", err)
          assert.is_nil(debugInfo)
        end)

        it("should not return debug info if request is out of time range", function()
          config.date = "2011-09-10T23:36:00.000Z"
          config.clockSkew = 300

          local escher = Escher(config)

          local success, err, debugInfo = escher:authenticate(request, keyDb)

          assert.is_false(success)
          assert.is_equal("The request date is not within the accepted time range", err)
          assert.is_nil(debugInfo)
        end)

        it("should not return debug info if bad credential scope used", function()
          config.credentialScope = "us-east-2/host/aws4_request"

          local escher = Escher(config)

          local success, err, debugInfo = escher:authenticate(request, keyDb)

          assert.is_false(success)
          assert.is_equal("The credential scope is invalid", err)
          assert.is_nil(debugInfo)
        end)

      end)

    end)

  end)

  describe("#generateHeader", function()

    it("should not mutate passed in parameters", function()
      local escher = Escher:new({
        algoPrefix = "AWS4",
        vendorKey = "AWS4",
        hashAlgo = "SHA256",
        credentialScope = "us-east-1/host/aws4_request",
        authHeaderName = "X-EMS-Auth",
        dateHeaderName = "X-EMS-Date",
        date = "2011-09-09T23:36:00.000Z",
        apiSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        accessKeyId = "AKIDEXAMPLE"
      })

      local request = {
        method = "GET",
        url = "/",
        headers = {
          { "Host", "host.foo.com" }
        },
        body = ""
      }

      local headersToSign = { "x-ems-date" }

      escher:generateHeader(request, headersToSign)

      assert.are.same({
        method = "GET",
        url = "/",
        headers = {
          { "Host", "host.foo.com" }
        },
        body = ""
      }, request)
    end)

  end)

end)
