// Generic runtime support only: no VH-Log or Data Integrity rules live here.
#include <charconv>
#include <cmath>
#include <iostream>
#include <limits>
#include <memory>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include <string>
#include <utf8proc.h>
#include <vector>
using J = nlohmann::ordered_json;
static std::vector<std::unique_ptr<J>> arena;
static J missing;
static J &val(intptr_t h) { return h ? *reinterpret_cast<J *>(h) : missing; }
static intptr_t keep(J j) {
  arena.push_back(std::make_unique<J>(std::move(j)));
  return reinterpret_cast<intptr_t>(arena.back().get());
}
static std::string str(intptr_t h) {
  return val(h).is_string() ? val(h).get<std::string>() : std::string();
}
static void doubles(J &j) {
  if (j.is_number())
    j = j.get<double>();
  else if (j.is_structured())
    for (auto &v : j)
      doubles(v);
}
extern "C" {
intptr_t v_init() { return sodium_init(); }
void v_reset() { arena.clear(); }
intptr_t v_parse(const char *p, intptr_t n) {
  try {
    auto j = J::parse(p, p + n);
    doubles(j);
    return keep(j);
  } catch (...) {
    return 0;
  }
}
intptr_t v_string(const char *p, intptr_t n) { return keep(std::string(p, n)); }
const char *v_data(intptr_t h) {
  return val(h).is_string() ? val(h).get_ref<const std::string &>().data() : "";
}
intptr_t v_size(intptr_t h) {
  return val(h).is_string()       ? str(h).size()
         : val(h).is_structured() ? val(h).size()
                                  : 0;
}
intptr_t v_type(intptr_t h) {
  auto &j = val(h);
  return j.is_null()      ? 0
         : j.is_boolean() ? 1
         : j.is_number()  ? 2
         : j.is_string()  ? 3
         : j.is_array()   ? 4
                          : 5;
}
intptr_t v_number(intptr_t n) { return keep(double(n)); }
intptr_t v_integer(intptr_t h) {
  if (!val(h).is_number())
    return 0;
  double d = val(h).get<double>();
  return d >= -9007199254740991. && d <= 9007199254740991.
             ? intptr_t(d)
             : std::numeric_limits<intptr_t>::min();
}
intptr_t v_integral(intptr_t h) {
  if (!val(h).is_number())
    return 0;
  double d = val(h).get<double>();
  return std::isfinite(d) && std::floor(d) == d;
}
intptr_t v_bool(intptr_t n) { return keep(n != 0); }
intptr_t v_truth(intptr_t h) { return val(h) == true; }
intptr_t v_object() { return keep(J::object()); }
intptr_t v_array() { return keep(J::array()); }
intptr_t v_get(intptr_t h, const char *p, intptr_t n) {
  auto &j = val(h);
  std::string k(p, n);
  return j.is_object() && j.contains(k) ? keep(j[k]) : 0;
}
intptr_t v_has(intptr_t h, const char *p, intptr_t n) {
  return val(h).is_object() && val(h).contains(std::string(p, n));
}
void v_set(intptr_t h, const char *p, intptr_t n, intptr_t v) {
  val(h)[std::string(p, n)] = val(v);
}
void v_del(intptr_t h, const char *p, intptr_t n) {
  if (val(h).is_object())
    val(h).erase(std::string(p, n));
}
intptr_t v_at(intptr_t h, intptr_t i) {
  return val(h).is_array() && i >= 0 && size_t(i) < val(h).size()
             ? keep(val(h)[i])
             : 0;
}
void v_push(intptr_t h, intptr_t v) { val(h).push_back(val(v)); }
intptr_t v_clone(intptr_t h) { return keep(val(h)); }
intptr_t v_equal(intptr_t a, intptr_t b) { return val(a) == val(b); }
intptr_t v_keys(intptr_t h) {
  J a = J::array();
  if (val(h).is_object())
    for (auto it = val(h).begin(); it != val(h).end(); ++it)
      a.push_back(it.key());
  return keep(a);
}
intptr_t v_dump(intptr_t h) {
  try {
    return keep(val(h).dump());
  } catch (...) {
    return 0;
  }
}
intptr_t v_cat(intptr_t a, intptr_t b) { return keep(str(a) + str(b)); }
intptr_t v_slice(intptr_t h, intptr_t start, intptr_t count) {
  auto s = str(h);
  if (start < 0 || size_t(start) > s.size() || count < 0)
    return 0;
  return keep(s.substr(start, count));
}
intptr_t v_replace(intptr_t h, intptr_t from, intptr_t to) {
  auto s = str(h), f = str(from), t = str(to);
  if (f.empty())
    return keep(s);
  size_t p = 0;
  while ((p = s.find(f, p)) != std::string::npos) {
    s.replace(p, f.size(), t);
    p += t.size();
  }
  return keep(s);
}
intptr_t v_find(intptr_t h, intptr_t needle) {
  auto p = str(h).find(str(needle));
  return p == std::string::npos ? -1 : intptr_t(p);
}
intptr_t v_split(intptr_t h, intptr_t delim) {
  auto s = str(h), d = str(delim);
  J a = J::array();
  size_t p = 0, q;
  if (d.empty())
    return keep(a);
  while ((q = s.find(d, p)) != std::string::npos) {
    a.push_back(s.substr(p, q - p));
    p = q + d.size();
  }
  a.push_back(s.substr(p));
  return keep(a);
}
intptr_t v_nfc(intptr_t h) {
  auto s = str(h);
  utf8proc_uint8_t *out = nullptr;
  auto n = utf8proc_map(reinterpret_cast<const utf8proc_uint8_t *>(s.data()),
                        s.size(), &out,
                        utf8proc_option_t(UTF8PROC_STABLE | UTF8PROC_COMPOSE));
  if (n < 0)
    return 0;
  auto r = keep(std::string(reinterpret_cast<char *>(out), n));
  free(out);
  return r;
}
intptr_t v_utf16cmp(intptr_t a, intptr_t b) {
  auto conv = [](std::string s) {
    std::u16string r;
    for (size_t p = 0; p < s.size();) {
      utf8proc_int32_t c;
      auto n = utf8proc_iterate(
          reinterpret_cast<const utf8proc_uint8_t *>(s.data() + p),
          s.size() - p, &c);
      if (n < 0)
        break;
      p += n;
      if (c > 0xffff) {
        c -= 0x10000;
        r += char16_t(0xd800 + (c >> 10));
        r += char16_t(0xdc00 + (c & 1023));
      } else
        r += char16_t(c);
    }
    return r;
  };
  auto x = conv(str(a)), y = conv(str(b));
  return x < y ? -1 : x > y ? 1 : 0;
}
// Convert shortest-roundtrip decimal to ECMAScript's fixed/exponent thresholds.
intptr_t v_decimal(intptr_t h) {
  double d = val(h).get<double>();
  if (d == 0)
    return keep("0");
  char buf[64];
  auto r = std::to_chars(buf, buf + 64, d, std::chars_format::scientific);
  std::string s(buf, r.ptr);
  bool neg = s[0] == '-';
  auto e = s.find('e');
  int exponent = std::stoi(s.substr(e + 1));
  std::string digits = s.substr(neg, e - neg);
  auto dot = digits.find('.');
  if (dot != std::string::npos)
    digits.erase(dot, 1);
  int point = exponent + 1;
  std::string out = neg ? "-" : "";
  if (exponent >= -6 && exponent < 21) {
    if (point <= 0)
      out += "0." + std::string(-point, '0') + digits;
    else if (size_t(point) >= digits.size())
      out += digits + std::string(point - digits.size(), '0');
    else
      out += digits.substr(0, point) + "." + digits.substr(point);
  } else {
    out += digits.substr(0, 1);
    if (digits.size() > 1)
      out += "." + digits.substr(1);
    out += "e";
    if (exponent >= 0)
      out += "+";
    out += std::to_string(exponent);
  }
  return keep(out);
}
intptr_t v_sha(intptr_t h) {
  auto s = str(h);
  unsigned char out[32];
  crypto_hash_sha256(out, reinterpret_cast<const unsigned char *>(s.data()),
                     s.size());
  return keep(std::string(reinterpret_cast<char *>(out), 32));
}
static bool seed(intptr_t h, unsigned char *out) {
  auto s = str(h);
  size_t n;
  return s.size() == 64 &&
         sodium_hex2bin(out, 32, s.data(), s.size(), nullptr, &n, nullptr) ==
             0 &&
         n == 32;
}
intptr_t v_public(intptr_t h) {
  unsigned char sd[32], pk[32], sk[64];
  if (!seed(h, sd))
    return 0;
  crypto_sign_seed_keypair(pk, sk, sd);
  sodium_memzero(sk, 64);
  return keep(std::string(reinterpret_cast<char *>(pk), 32));
}
intptr_t v_sign(intptr_t data, intptr_t h) {
  unsigned char sd[32], pk[32], sk[64], sig[64];
  if (!seed(h, sd))
    return 0;
  crypto_sign_seed_keypair(pk, sk, sd);
  auto s = str(data);
  crypto_sign_detached(sig, nullptr,
                       reinterpret_cast<const unsigned char *>(s.data()),
                       s.size(), sk);
  sodium_memzero(sk, 64);
  return keep(std::string(reinterpret_cast<char *>(sig), 64));
}
intptr_t v_verify(intptr_t data, intptr_t signature, intptr_t key) {
  auto s = str(data), sig = str(signature), pk = str(key);
  return sig.size() == 64 && pk.size() == 32 &&
         crypto_sign_verify_detached(
             reinterpret_cast<const unsigned char *>(sig.data()),
             reinterpret_cast<const unsigned char *>(s.data()), s.size(),
             reinterpret_cast<const unsigned char *>(pk.data())) == 0;
}
intptr_t v_read() {
  std::string s;
  return std::getline(std::cin, s) ? keep(s) : 0;
}
void v_write(intptr_t h) { std::cout << val(h).dump() << '\n' << std::flush; }
}
