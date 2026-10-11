// Platform primitives only; JSON traversal and all VH-Log rules live in Lua.
#include <lua.hpp>
#include <sodium.h>
#include <charconv>
#include <cmath>
#include <string>
static int number(lua_State *L) {
  double d=luaL_checknumber(L,1);
  if(!std::isfinite(d)) return luaL_error(L,"non-finite number");
  char b[64]; auto r=std::to_chars(b,b+sizeof(b),d,std::chars_format::scientific);
  if(r.ec!=std::errc()) return luaL_error(L,"number formatting failed");
  lua_pushlstring(L,b,r.ptr-b); return 1;
}
static int sha(lua_State *L) {
  size_t n; auto s=luaL_checklstring(L,1,&n); unsigned char out[32];
  crypto_hash_sha256(out,(const unsigned char*)s,n);
  lua_pushlstring(L,(char*)out,32); return 1;
}
static void key(lua_State *L,unsigned char *pk,unsigned char *sk) {
  size_t n; auto seed=luaL_checklstring(L,1,&n);
  if(n!=32) luaL_error(L,"seed must be 32 bytes");
  crypto_sign_seed_keypair(pk,sk,(const unsigned char*)seed);
}
static int public_key(lua_State *L) {
  unsigned char pk[32],sk[64]; key(L,pk,sk); sodium_memzero(sk,64);
  lua_pushlstring(L,(char*)pk,32); return 1;
}
static int sign(lua_State *L) {
  unsigned char pk[32],sk[64],sig[64]; key(L,pk,sk);
  size_t n; auto msg=luaL_checklstring(L,2,&n);
  crypto_sign_detached(sig,nullptr,(const unsigned char*)msg,n,sk); sodium_memzero(sk,64);
  lua_pushlstring(L,(char*)sig,64); return 1;
}
static int verify(lua_State *L) {
  size_t pn,mn,sn; auto pk=luaL_checklstring(L,1,&pn); auto msg=luaL_checklstring(L,2,&mn); auto sig=luaL_checklstring(L,3,&sn);
  lua_pushboolean(L,pn==32 && sn==64 && crypto_sign_verify_detached((const unsigned char*)sig,(const unsigned char*)msg,mn,(const unsigned char*)pk)==0); return 1;
}
extern "C" int luaopen_vh_native(lua_State *L) {
  if(sodium_init()<0) return luaL_error(L,"sodium init failed");
  luaL_Reg methods[]={{"number",number},{"sha",sha},{"public_key",public_key},{"sign",sign},{"verify",verify},{nullptr,nullptr}};
  luaL_newlib(L,methods); return 1;
}
