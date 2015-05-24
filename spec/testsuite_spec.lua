
local json = require("json")

function readTest(filename)
    local f = io.open(filename, "r")
    local content = f:read("*all")
    f:close()
    return json.decode(content)
end

describe("Escher TestSuite", function()

  describe('load "GET vanilla" JSON', function()

    it("should properly loaded", function()
      test = readTest('spec/aws4_testsuite/get-vanilla.json')
      assert.are.equals(test.request.method, "GET")
    end)

  end)

end)
