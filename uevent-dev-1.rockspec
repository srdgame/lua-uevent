package = "uevent"
version = "dev-1"

source = {
  url = "git://github.com/srdgame/lua-uevent.git"
}

description = {
  summary = "A library for receive kernel uevent object in Lua",
  detailed = [[
   Kernel uevent object read from kernel 
  ]],
  homepage = "http://github.com/srdgame/lua-uevent",
  license = "MIT"
}

dependencies = {
  "lua >= 5.1"
}

build = {
  type = "builtin",
  modules = {
    uevent = {
      sources = {"lua_uevent.c"},
      libraries = {"uevent"},
    }
  }
}
