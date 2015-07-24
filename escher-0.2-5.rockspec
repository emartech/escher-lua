package = "Escher"
version = "0.2-5"
source = {
  url = "git://github.com/emartech/escher-lua",
  tag = "0.2-5",
  dir = "escher-lua"
}
description = {
    summary = "Lua implementation of the Escher HTTP request signing library",
    homepage = "https://github.com/emartech/escher-lua/",
    license = "MIT"
}
dependencies = {
    "luafilesystem",
    "json",
    "luacrypto",
    "date",
}
build = {
    type = "builtin",
    modules = {
        ["escher"] = "escher.lua",
        ["escher.urlhandler"] = "escher/urlhandler.lua",
    }
}
