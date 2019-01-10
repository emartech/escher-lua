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

    end)

end)
