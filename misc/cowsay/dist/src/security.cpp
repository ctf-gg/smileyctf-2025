#include "lualib.h"
#include "string.h"

#include "security.h"
#include "cowsayLib.h"

static int secureDecorator(lua_State *L) {
    int i = 1;
    lua_Debug ar;
    bool allowed = false;
    while (lua_getinfo(L, i++, "s", &ar) == 1) {
        // look for permitted source
        if (strcmp(ar.source, COWSAY_LIB_NAME) == 0) {
            allowed = true;
            break;
        }
    }

    if (!allowed) {
        luaL_error(L, "Attempt to call secured function from a forbidden source");
    }
    // call the function
    // push function on to the stack and then args
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);

    lua_call(L, lua_gettop(L) - 1, LUA_MULTRET);

    return lua_gettop(L); // return all results
}

void secureFunction(lua_State *L)
{
    lua_pushcclosurek(L, &secureDecorator, NULL, 1, NULL);
}