#include <charconv>
#include <openssl/evp.h>
#include <string>
extern "C" {
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
CAMLprim value vh_number(value v) {
  CAMLparam1(v);
  double x = Double_val(v);
  if (x == 0)
    CAMLreturn(caml_copy_string("0"));
  char b[128];
  auto r = std::to_chars(b, b + 128, x, std::chars_format::scientific);
  std::string s(b, r.ptr);
  bool neg = s[0] == '-';
  size_t e = s.find('e');
  int exp = std::stoi(s.substr(e + 1));
  std::string d = s.substr(neg ? 1 : 0, e - (neg ? 1 : 0));
  size_t dot = d.find('.');
  if (dot != std::string::npos)
    d.erase(dot, 1);
  std::string out = neg ? "-" : "";
  int point = exp + 1;
  if (exp >= -6 && exp < 21) {
    if (point <= 0)
      out += "0." + std::string(-point, '0') + d;
    else if (point >= (int)d.size())
      out += d + std::string(point - d.size(), '0');
    else
      out += d.substr(0, point) + "." + d.substr(point);
  } else {
    out += d.substr(0, 1);
    if (d.size() > 1)
      out += "." + d.substr(1);
    out += "e";
    if (exp >= 0)
      out += "+";
    out += std::to_string(exp);
  }
  CAMLreturn(caml_copy_string(out.c_str()));
}
CAMLprim value vh_digest(value alg, value data) {
  CAMLparam2(alg, data);
  CAMLlocal1(out);
  const EVP_MD *md = Int_val(alg) == 512 ? EVP_sha512() : EVP_sha256();
  unsigned char b[64];
  unsigned n;
  if (!EVP_Digest(String_val(data), caml_string_length(data), b, &n, md, NULL))
    caml_failwith("digest");
  out = caml_alloc_initialized_string(n, (char *)b);
  CAMLreturn(out);
}
CAMLprim value vh_public(value seed) {
  CAMLparam1(seed);
  CAMLlocal1(out);
  if (caml_string_length(seed) != 32)
    caml_failwith("seed length");
  EVP_PKEY *p = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, NULL, (const unsigned char *)String_val(seed), 32);
  if (!p)
    caml_failwith("key");
  unsigned char b[32];
  size_t n = 32;
  int ok = EVP_PKEY_get_raw_public_key(p, b, &n);
  EVP_PKEY_free(p);
  if (!ok)
    caml_failwith("public key");
  out = caml_alloc_initialized_string(n, (char *)b);
  CAMLreturn(out);
}
CAMLprim value vh_sign(value seed, value data) {
  CAMLparam2(seed, data);
  CAMLlocal1(out);
  if (caml_string_length(seed) != 32)
    caml_failwith("seed length");
  EVP_PKEY *p = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, NULL, (const unsigned char *)String_val(seed), 32);
  EVP_MD_CTX *c = EVP_MD_CTX_new();
  unsigned char b[64];
  size_t n = 64;
  int ok = p && c && EVP_DigestSignInit(c, NULL, NULL, NULL, p) &&
           EVP_DigestSign(c, b, &n, (const unsigned char *)String_val(data),
                          caml_string_length(data));
  EVP_MD_CTX_free(c);
  EVP_PKEY_free(p);
  if (!ok)
    caml_failwith("sign");
  out = caml_alloc_initialized_string(n, (char *)b);
  CAMLreturn(out);
}
CAMLprim value vh_verify(value key, value data, value sig) {
  CAMLparam3(key, data, sig);
  if (caml_string_length(key) != 32 || caml_string_length(sig) != 64)
    CAMLreturn(Val_false);
  EVP_PKEY *p = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, NULL, (const unsigned char *)String_val(key), 32);
  EVP_MD_CTX *c = EVP_MD_CTX_new();
  int ok = p && c && EVP_DigestVerifyInit(c, NULL, NULL, NULL, p) &&
           EVP_DigestVerify(c, (const unsigned char *)String_val(sig), 64,
                            (const unsigned char *)String_val(data),
                            caml_string_length(data)) == 1;
  EVP_MD_CTX_free(c);
  EVP_PKEY_free(p);
  CAMLreturn(Val_bool(ok));
}
}
