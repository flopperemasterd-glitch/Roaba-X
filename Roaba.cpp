#include "pch.h"
#include <windows.h>
#include <iostream>
#include <vector>
#include <map>
#include <string>
#include <iomanip>

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

using namespace std;

//═══════════════════════════════════════════════════════
// CONFIG
//═══════════════════════════════════════════════════════
#define ROABA_VERSION   "4.2-ENV-REAL"
#define ROABA_IDENTITY  8

//═══════════════════════════════════════════════════════
// GLOBAL STATE
//═══════════════════════════════════════════════════════
struct RoabaState {
    lua_State* mainState = nullptr;     // "real" Roblox-like env (renv)
    lua_State* exploitEnv = nullptr;     // exploit globals (genv) - actually a table reference
    int identity = ROABA_IDENTITY;
    bool detected = false;
};

RoabaState* g_RoabaState = nullptr;

//═══════════════════════════════════════════════════════
// ENVIRONMENT METAMETHOD (for genv fallback)
//═══════════════════════════════════════════════════════
static int genv_index(lua_State* L) {
    // genv[key] → first look in exploit table, then fallback to renv (_G)
    lua_getfield(L, lua_upvalueindex(1), lua_tostring(L, 2));   // check exploit table
    if (!lua_isnil(L, -1)) return 1;

    lua_pop(L, 1);
    lua_pushvalue(L, lua_upvalueindex(2));                      // push renv
    lua_pushvalue(L, 2);
    lua_gettable(L, -2);
    return 1;
}

//═══════════════════════════════════════════════════════
// REAL ENVIRONMENT FUNCTIONS
//═══════════════════════════════════════════════════════

static int RoabaAPI_getgenv(lua_State* L) {
    if (!g_RoabaState || !g_RoabaState->exploitEnv) {
        lua_newtable(L);
        return 1;
    }

    // Return the exploit globals table
    lua_pushlightuserdata(L, g_RoabaState->exploitEnv); // we store table as lightuserdata ref
    lua_gettable(L, LUA_REGISTRYINDEX);                 // retrieve from registry
    return 1;
}

static int RoabaAPI_getrenv(lua_State* L) {
    // Return the "real" Roblox environment (main global table)
    lua_pushglobaltable(L);
    return 1;
}

//lua that i imported sadly dosent have setfenv(), getfenv() so these are commented out

//static int RoabaAPI_getfenv(lua_State* L) {
//    // Standard Lua: getfenv([f | level])
 //   if (lua_isnoneornil(L, 1)) {
//        lua_pushinteger(L, 1); // default to level 1
//    }
//    else if (lua_isnumber(L, 1)) {
//        lua_pushvalue(L, 1);
 //   }
//    else if (lua_isfunction(L, 1)) {
//        // keep function on stack
//    }
//    else {
 //       return luaL_error(L, "getfenv expects function, number, or no arg");
//    }
//
//    lua_getfenv(L, -1); // Lua 5.1 / Luau compatible
 //   return 1;
//}

//static int RoabaAPI_setfenv(lua_State* L) {
 //   // Standard Lua: setfenv(f, table)
//    luaL_checktype(L, 2, LUA_TTABLE);
//
//    if (lua_isnumber(L, 1)) {
//        lua_pushvalue(L, 1);
//    }
 //   else if (lua_isfunction(L, 1)) {
//        // keep function
//    }
//    else {
 //       return luaL_error(L, "setfenv expects function or level");
//    }
//
//    lua_pushvalue(L, 2); // env table
//    lua_setfenv(L, -2);  // set it
//    lua_settop(L, 2);    // return function + env (standard behavior)
//    return 2;
//}

//═══════════════════════════════════════════════════════
// OTHER API STUBS (kept minimal but real)
//═══════════════════════════════════════════════════════

static int RoabaAPI_newcclosure(lua_State* L) {
    if (!lua_isfunction(L, 1)) return luaL_error(L, "newcclosure expects function");
    lua_pushvalue(L, 1);
    lua_pushcclosure(L, [](lua_State* L) -> int {
        lua_pushvalue(L, lua_upvalueindex(1));
        int n = lua_gettop(L) - 1;
        for (int i = 1; i <= n; ++i) lua_pushvalue(L, i);
        lua_call(L, n, LUA_MULTRET);
        return lua_gettop(L);
        }, 1);
    return 1;
}

static int RoabaAPI_getidentity(lua_State* L) {
    lua_pushinteger(L, g_RoabaState ? g_RoabaState->identity : 2); // default level 2
    return 1;
}

static int RoabaAPI_Drawing_new(lua_State* L) {
    const char* type = luaL_checkstring(L, 1);
    lua_newtable(L);
    lua_pushboolean(L, true); lua_setfield(L, -2, "Visible");
    lua_pushnumber(L, 1.0);   lua_setfield(L, -2, "Transparency");

    lua_newtable(L);
    lua_pushnumber(L, 255); lua_setfield(L, -2, "R");
    lua_pushnumber(L, 255); lua_setfield(L, -2, "G");
    lua_pushnumber(L, 255); lua_setfield(L, -2, "B");
    lua_setfield(L, -2, "Color");

    if (_stricmp(type, "Line") == 0) {
        lua_newtable(L); lua_pushnumber(L, 0); lua_setfield(L, -2, "X"); lua_pushnumber(L, 0); lua_setfield(L, -2, "Y"); lua_setfield(L, -2, "From");
        lua_newtable(L); lua_pushnumber(L, 100); lua_setfield(L, -2, "X"); lua_pushnumber(L, 100); lua_setfield(L, -2, "Y"); lua_setfield(L, -2, "To");
    }

    return 1;
}

static void RegisterRoabaAPI(lua_State* L) {
    if (!L) return;

    cout << "[API] Registering environment + other functions..." << endl;

    lua_register(L, "getgenv", RoabaAPI_getgenv);
    lua_register(L, "getrenv", RoabaAPI_getrenv);
    //lua_register(L, "getfenv", RoabaAPI_getfenv);
    //lua_register(L, "setfenv", RoabaAPI_setfenv);
    lua_register(L, "newcclosure", RoabaAPI_newcclosure);
    lua_register(L, "getidentity", RoabaAPI_getidentity);

    lua_newtable(L);
    lua_pushcfunction(L, RoabaAPI_Drawing_new);
    lua_setfield(L, -2, "new");
    lua_setglobal(L, "Drawing");

    cout << "[API] Environment functions ready." << endl;
}

//═══════════════════════════════════════════════════════
// CREATE STATES (real setup)
//═══════════════════════════════════════════════════════
static lua_State* CreateMainLuauState() {
    lua_State* L = luaL_newstate();
    if (!L) return nullptr;
    luaL_openlibs(L);

    // Fake Roblox globals
    lua_newtable(L);
    lua_pushstring(L, "Players"); lua_setfield(L, -2, "Players");
    lua_setglobal(L, "game");

    return L;
}

static void SetupExploitEnv() {
    lua_State* L = g_RoabaState->mainState;

    // Create exploit globals table
    lua_newtable(L);
    int exploitTableRef = luaL_ref(L, LUA_REGISTRYINDEX); // store in registry

    // Create metatable for fallback
    lua_newtable(L);
    lua_pushvalue(L, -1); lua_setfield(L, -2, "__index"); // self as fallback? no
    lua_pushvalue(L, -1); // duplicate mt
    lua_pushlightuserdata(L, (void*)(intptr_t)exploitTableRef);
    lua_gettable(L, LUA_REGISTRYINDEX); // push exploit table
    lua_pushglobaltable(L);             // push renv = _G
    lua_pushcclosure(L, genv_index, 2); // upvalues: exploit table + renv
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2); // set mt on exploit table

    // Store reference
    g_RoabaState->exploitEnv = (lua_State*)(intptr_t)exploitTableRef; // abuse as ref key
}

//═══════════════════════════════════════════════════════
// MAIN THREAD
//═══════════════════════════════════════════════════════
DWORD WINAPI RoabaMain(LPVOID lpParam) {
    AllocConsole();
    FILE* dummy;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    freopen_s(&dummy, "CONIN$", "r", stdin);

    cout << "\nROABA X v" << ROABA_VERSION << " - full env support\n\n";

    g_RoabaState = new RoabaState();
    if (!g_RoabaState) {
        // optional: log something
        FreeConsole();
        FreeLibraryAndExitThread((HMODULE)lpParam, 0);
        return 0;
    }

    g_RoabaState->mainState = CreateMainLuauState();

    if (!g_RoabaState->mainState) {
        cout << "Failed to create main Luau state\n";
        FreeConsole();
        FreeLibraryAndExitThread((HMODULE)lpParam, 0);
        return 0;
    }

    SetupExploitEnv();

    RegisterRoabaAPI(g_RoabaState->mainState);

    cout << "Ready. Try:\n";
    cout << "  exec print(getrenv().game)\n";
    cout << "  exec getgenv().myvar = 1337; print(getgenv().myvar)\n";
    cout << "  exec print(getfenv(print))\n";
    cout << "  exec exit\n\n";

    string line;
    while (true) {
        cout << "ROABA> ";
        if (!getline(cin, line)) break;

        if (line == "exit") break;

        if (line.rfind("exec ", 0) == 0) {
            string code = line.substr(5);
            lua_State* L = g_RoabaState->mainState;

            int err = luaL_loadstring(L, code.c_str());
            if (err) {
                cout << "Load error: " << lua_tostring(L, -1) << "\n";
                lua_pop(L, 1);
                continue;
            }

            err = lua_pcall(L, 0, LUA_MULTRET, 0);
            if (err) {
                cout << "Runtime error: " << lua_tostring(L, -1) << "\n";
                lua_pop(L, 1);
            }

            int n = lua_gettop(L);
            if (n > 0) {
                cout << "→ ";
                for (int i = 1; i <= n; ++i) {
                    cout << (lua_tostring(L, i) ? lua_tostring(L, i) : luaL_typename(L, i)) << (i < n ? "  " : "");
                }
                cout << "\n";
                lua_settop(L, 0);
            }
        }
    }

cleanup:
    if (g_RoabaState) {
        if (g_RoabaState->mainState) lua_close(g_RoabaState->mainState);
        delete g_RoabaState;
    }
    FreeConsole();
    FreeLibraryAndExitThread((HMODULE)lpParam, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, RoabaMain, hModule, 0, nullptr);
    }
    return TRUE;
}
