package = "Escher"
version = "0.2-17"
source = {
  url = "git://github.com/emartech/escher-lua",
  tag = "0.2-17",
  dir = "escher-lua"
}
description = {
    summary = "Lua implementation of the Escher HTTP request signing library",
    homepage = "https://github.com/emartech/escher-lua/",
    license = "MIT"
}
dependencies = {
    "luafilesystem == 1.6.3-2",
    "rapidjson == 0.4.5-1",
    "luacrypto == 0.3.2-2",
    "date == 2.1.1-1",
}
build = {
    type = "builtin",
    modules = {
        ["escher"] = "src/escher.lua",
        ["escher.canonicalizer"] = "src/escher/canonicalizer.lua",
        ["escher.urlhandler"] = "src/escher/urlhandler.lua",
        ["escher.utils"] = "src/escher/utils.lua"
    }
}
