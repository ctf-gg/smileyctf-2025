#include <iostream>
#include <fstream>
#include <cstring>
#include <cassert>

#include "lua.h"
#include "lualib.h"
#include "luacode.h"

#include "cowsayLib.h"
#include "security.h"

#include "safeLua.h"

int openSecure(lua_State *L);
std::string flag;

// from linit.cpp
static const luaL_Reg luaLibs[] = {
    {"", luaopen_base},
    {LUA_COLIBNAME, luaopen_coroutine},
    {LUA_TABLIBNAME, luaopen_table},
    {LUA_OSLIBNAME, luaopen_os},
    {LUA_STRLIBNAME, luaopen_string},
    {LUA_MATHLIBNAME, luaopen_math},
    {LUA_DBLIBNAME, luaopen_debug},
    {LUA_UTF8LIBNAME, luaopen_utf8},
    {LUA_BITLIBNAME, luaopen_bit32},
    {LUA_BUFFERLIBNAME, luaopen_buffer},
    /* secure lib */
    {"secure", openSecure},
    {NULL, NULL},
};

int printFlag(lua_State *L) {
    // add the flag to the stack
    lua_getglobal(L, "print");
    lua_pushstring(L, flag.c_str());
    lua_call(L, 1, 0);
    return 0;
}

static const luaL_Reg seFuncs[] = {
    {"printflag", printFlag},
    {NULL, NULL},
};

int openSecure(lua_State *L) {
    luaL_register(L, "secure", seFuncs);

    return 1;
}

int runCode(lua_State *L, const std::string& source) {
    size_t bytecodeSize = 0;
    char* bytecode = luau_compile(source.data(), source.length(), nullptr, &bytecodeSize);

    lua_State* T = safeLua::initThread(L);

    // move function to the new thread
    int result = luau_load(T, "=stdin", bytecode, bytecodeSize, 0);
    free(bytecode);

    // check for errors
    if (result != 0)
    {
        lua_xmove(T, L, 1); // move error to L
        lua_remove(L, -2); // pop T

        return 1;
    }

    // resume the thread by calling the function
    int status = lua_resume(T, NULL, 0);

    if (status == LUA_OK)
    {
        lua_pop(L, 1); // pop T
        return 0;
    }
    else if (status == LUA_YIELD)
    {
        lua_pop(L, 1); // pop T
        return 0;
    }
    else
    {
        lua_xmove(T, L, 1); // move error to L
        lua_remove(L, -2); // pop T
        return 1;
    }
}

void openLibs(lua_State *L)
{
    const luaL_Reg* lib = luaLibs;
    for (; lib->func; lib++)
    {
        lua_pushcfunction(L, lib->func, NULL);
        lua_pushstring(L, lib->name);
        lua_call(L, 1, 0);
        
        if (strlen(lib->name) != 0) {            
            // get the lib we just loaded
            lua_getglobal(L, lib->name);
            lua_pushnil(L);
            while (lua_next(L, -2) != 0) {
                if (lua_type(L, -1) != LUA_TFUNCTION) {
                    lua_pop(L, 1);
                    continue;
                }
                secureFunction(L);

                lua_setfield(L, -3, lua_tostring(L, -2)); // pops the closure
            }
        }
    }

    /* i heard these can be used for evil so i removed them */
    lua_pushnil(L);
    lua_setglobal(L, "getfenv");

    lua_pushnil(L);
    lua_setglobal(L, "setfenv");

    lua_getglobal(L, "setmetatable");
    secureFunction(L);
    lua_setglobal(L, "setmetatable");
}

int main() {
    std::ifstream flagFile("flag.txt");
    if (!flagFile.is_open()) {
        return 1;
    }
    std::getline(flagFile, flag);
    flagFile.close();

    int64_t totalAllocated = 0;
    lua_State *L= lua_newstate(safeLua::safeLuaAlloc, &totalAllocated);
    
    openLibs(L);
    loadCowsayLib(L);

    luaL_sandbox(L); // sandboxing

    std::string source;
    // read line
    std::getline(std::cin, source);
    source = "return " + source;
    int n = lua_gettop(L);
    int result = runCode(L, source);
    if (result != 0) {
        int type = lua_type(L, -1);
        if (type != LUA_TSTRING) {
            std::cout << "Run failed: error of type " << lua_typename(L, type) << std::endl;
        } else {
            std::cout << "Run failed:" << std::endl << lua_tostring(L, -1) << std::endl;
        }
    }
    lua_close(L);
}