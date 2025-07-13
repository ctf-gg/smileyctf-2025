#include <fstream>
#include <cassert>

#include "cowsayLib.h"
#include "luacode.h"
#include "lua.h"
#include "lualib.h"

void loadCowsayLib(lua_State *L) {
    // load the lib from lib.lua
    // read from file
    std::ifstream file("lib.lua");
    std::string source((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // get the global table
    size_t bytecodeSize = 0;
    char* bytecode = luau_compile(source.data(), source.length(), nullptr, &bytecodeSize);

    lua_State* T = lua_newthread(L);
    luaL_sandboxthread(T);

    int result = luau_load(T, COWSAY_LIB_NAME, bytecode, bytecodeSize, 0);
    assert(result == 0);

    int status = lua_resume(T, NULL, 0);
    assert(status == 0);   
    assert(lua_gettop(T) == 1); // one return value

    lua_xmove(T, L, 1); // move the module to the main thread
    lua_pushvalue(L, -1);
    lua_setglobal(L, COWSAY_LIB_NAME);

    lua_remove(L, -2); // pop the thread
}