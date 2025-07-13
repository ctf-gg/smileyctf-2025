#pragma once

#include "lua.h"
#include "lualib.h"
#include "luacode.h"


namespace safeLua {
    struct ThreadState
    {
        int interrupts;
        int totalAllocated;
    };

    void* safeLuaAlloc(void *ud, void *ptr, size_t osize, size_t nsize);
    lua_State *initThread(lua_State *L);
}