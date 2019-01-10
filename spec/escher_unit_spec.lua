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

    end)

end)
