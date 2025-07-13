#include "safeLua.h"

#include <cassert>
#include <stdexcept>
#include <iostream>

static const int MAX_ALLOC = (int)1e6;

void* safeLua::safeLuaAlloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
    int64_t &totalAllocated = *(int64_t *)ud;
    if (nsize == 0) {
        // free memory
        if (ptr) {
            totalAllocated -= osize;
        }
        return nullptr;
    }
    else {
        // allocate memory and handle errors from realloc
        if (ptr) {
            if (totalAllocated + nsize - osize > MAX_ALLOC) {
                throw std::runtime_error("Max allocation size exceeded");
            }
            void *new_ptr = realloc(ptr, nsize);
            if (!new_ptr) {
                return nullptr;
            }
            totalAllocated += nsize - osize;
            return new_ptr;
        }
        else {
            if (totalAllocated + nsize > MAX_ALLOC) {
                throw std::runtime_error("Max allocation size exceeded");
            }
            void *new_ptr = malloc(nsize);
            if (!new_ptr) {
                return nullptr;
            }
            totalAllocated += nsize;
            return new_ptr;
        }
    }
}

static void safeLuaInterrupt(lua_State *L, int gc)
{
    safeLua::ThreadState *state = (safeLua::ThreadState *)lua_getthreaddata(L);
    if (++state->interrupts > 100) {
        throw std::runtime_error("Max execution time exceeded");
    }
}

lua_State *safeLua::initThread(lua_State *L)
{
    lua_State *T = lua_newthread(L);
    luaL_sandboxthread(T);

    // set the thread state
    ThreadState *state = (ThreadState *)lua_newuserdata(T, sizeof(ThreadState));
    state->interrupts = 0;
    lua_setthreaddata(T, state);
    lua_callbacks(T)->interrupt = safeLuaInterrupt;

    return T;
}