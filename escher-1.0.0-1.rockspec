package = "Escher"
version = "1.0.0-1"
source = {
  url = "git://github.com/emartech/escher-lua",
  tag = "1.0.0-1",
  dir = "escher-lua"
}
description = {
    summary = "Lua implementation of the Escher HTTP request signing library",
    homepage = "https://github.com/emartech/escher-lua/",
    license = "MIT"
}
dependencies = {
    "lua-resty-openssl == 0.8.8-1",
    "date == 2.1.2-1"
}
build = {
    type = "builtin",
    modules = {
        ["escher"] = "src/escher.lua",
        ["escher.canonicalizer"] = "src/escher/canonicalizer.lua",
        ["escher.signer"] = "src/escher/signer.lua",
        ["escher.urlhandler"] = "src/escher/urlhandler.lua",
        ["escher.utils"] = "src/escher/utils.lua",
        ["escher.crypto"] = "src/escher/crypto.lua"
    }
}
