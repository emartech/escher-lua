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

end)
