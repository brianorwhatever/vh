#include "vh_log.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sodium.h>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace vhlog {
using Bytes = std::vector<unsigned char>;
static constexpr std::string_view alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
struct Error : std::runtime_error {
    Json report;
    Error(const std::string &code, Json version = nullptr, Json fork = nullptr)
        : std::runtime_error(code),
          report{{"code", code}, {"version", version}, {"message", code}} {
        if (!fork.is_null())
            report["fork"] = std::move(fork);
    }
};
[[noreturn]] static void fail(const std::string &code, Json version = nullptr) {
    throw Error(code, version);
}
static Json get(const Json &v, const std::string &k) {
    return v.is_object() && v.contains(k) ? v.at(k) : Json();
}
static bool has(const Json &v, const std::string &k) { return v.is_object() && v.contains(k); }
static std::string str(const Json &v) { return v.get<std::string>(); }
static void normalize(Json &v) {
    if (v.is_number()) {
        double d = v.get<double>();
        if (!std::isfinite(d))
            throw std::invalid_argument("non-finite number");
        v = d;
    } else if (v.is_structured())
        for (auto &x : v)
            normalize(x);
}
Json parse(const std::string &text) {
    auto v = Json::parse(text);
    normalize(v);
    return v;
}
static std::string number(double d) {
    if (!std::isfinite(d))
        throw std::invalid_argument("non-finite number");
    if (d == 0)
        return "0";
    std::array<char, 64> buffer{};
    auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), std::abs(d),
                                std::chars_format::general);
    if (result.ec != std::errc())
        throw std::runtime_error("number formatting failed");
    std::string s(buffer.data(), result.ptr);
    auto ep = s.find('e');
    int power = ep == std::string::npos ? 0 : std::stoi(s.substr(ep + 1));
    std::string mantissa = s.substr(0, ep);
    auto dot = mantissa.find('.');
    int point = static_cast<int>(dot == std::string::npos ? mantissa.size() : dot) + power;
    std::string digits = mantissa;
    if (dot != std::string::npos)
        digits.erase(dot, 1);
    while (!digits.empty() && digits.back() == '0')
        digits.pop_back();
    while (digits.front() == '0') {
        digits.erase(0, 1);
        --point;
    }
    std::string body;
    if (point > 0 && point <= 21) {
        if (static_cast<int>(digits.size()) <= point)
            body = digits + std::string(point - digits.size(), '0');
        else
            body = digits.substr(0, point) + "." + digits.substr(point);
    } else if (point <= 0 && point > -6)
        body = "0." + std::string(-point, '0') + digits;
    else
        body = digits.substr(0, 1) + (digits.size() > 1 ? "." + digits.substr(1) : "") + "e" +
               (point - 1 >= 0 ? "+" : "") + std::to_string(point - 1);
    return (d < 0 ? "-" : "") + body;
}
// RFC 8785 orders object keys by UTF-16 code units, not UTF-8 bytes.
static std::u16string utf16(const std::string &s) {
    std::u16string out;
    for (size_t i = 0; i < s.size();) {
        uint32_t c = static_cast<unsigned char>(s[i++]);
        if (c >= 0x80) {
            int count = c < 0xe0 ? 1 : c < 0xf0 ? 2 : 3;
            c &= (1u << (6 - count)) - 1;
            while (count-- > 0)
                c = (c << 6) | (static_cast<unsigned char>(s.at(i++)) & 63);
        }
        if (c < 0x10000)
            out.push_back(static_cast<char16_t>(c));
        else {
            c -= 0x10000;
            out.push_back(static_cast<char16_t>(0xd800 + (c >> 10)));
            out.push_back(static_cast<char16_t>(0xdc00 + (c & 1023)));
        }
    }
    return out;
}
std::string canonicalize(const Json &v) {
    if (v.is_number())
        return number(v.get<double>());
    if (v.is_array()) {
        std::string out = "[";
        bool first = true;
        for (const auto &x : v) {
            if (!first)
                out += ',';
            first = false;
            out += canonicalize(x);
        }
        return out + "]";
    }
    if (v.is_object()) {
        std::vector<std::string> keys;
        for (auto it = v.begin(); it != v.end(); ++it)
            keys.push_back(it.key());
        std::sort(keys.begin(), keys.end(),
                  [](const auto &a, const auto &b) { return utf16(a) < utf16(b); });
        std::string out = "{";
        bool first = true;
        for (const auto &k : keys) {
            if (!first)
                out += ',';
            first = false;
            out += Json(k).dump() + ":" + canonicalize(v.at(k));
        }
        return out + "}";
    }
    return v.dump();
}
static std::string encode(const Bytes &bytes) {
    size_t zeros = 0;
    while (zeros < bytes.size() && bytes[zeros] == 0)
        ++zeros;
    std::vector<unsigned> digits;
    for (size_t i = zeros; i < bytes.size(); ++i) {
        unsigned carry = bytes[i];
        for (auto &d : digits) {
            carry += d * 256;
            d = carry % 58;
            carry /= 58;
        }
        while (carry) {
            digits.push_back(carry % 58);
            carry /= 58;
        }
    }
    std::string out(zeros, '1');
    for (auto i = digits.rbegin(); i != digits.rend(); ++i)
        out += alphabet[*i];
    return out;
}
static std::optional<Bytes> decode(const std::string &s) {
    size_t zeros = 0;
    while (zeros < s.size() && s[zeros] == '1')
        ++zeros;
    Bytes b;
    for (size_t i = zeros; i < s.size(); ++i) {
        auto d = alphabet.find(s[i]);
        if (d == std::string_view::npos)
            return std::nullopt;
        unsigned carry = static_cast<unsigned>(d);
        for (auto &x : b) {
            carry += x * 58;
            x = carry & 255;
            carry >>= 8;
        }
        while (carry) {
            b.push_back(carry & 255);
            carry >>= 8;
        }
    }
    Bytes out(zeros, 0);
    out.insert(out.end(), b.rbegin(), b.rend());
    return out;
}
static Bytes sha(const std::string &s) {
    Bytes b(32);
    crypto_hash_sha256(b.data(), reinterpret_cast<const unsigned char *>(s.data()), s.size());
    return b;
}
std::string hash(const std::string &s) {
    Bytes b{0x12, 0x20};
    auto h = sha(s);
    b.insert(b.end(), h.begin(), h.end());
    return encode(b);
}
static std::string check_hash(const std::string &s) {
    auto b = decode(s);
    return !b                                                      ? "not-base58"
           : b->size() == 34 && (*b)[0] == 0x12 && (*b)[1] == 0x20 ? "ok"
                                                                   : "unsupported-algorithm";
}
static std::optional<Bytes> public_key(const Json &mk) {
    if (!mk.is_string())
        return std::nullopt;
    auto s = str(mk);
    if (s.empty() || s[0] != 'z')
        return std::nullopt;
    auto b = decode(s.substr(1));
    if (!b || b->size() != 34 || (*b)[0] != 0xed || (*b)[1] != 1)
        return std::nullopt;
    return Bytes(b->begin() + 2, b->end());
}
static std::pair<Bytes, Bytes> signer(const std::string &seed) {
    if (!std::regex_match(seed, std::regex("[0-9a-fA-F]{64}")))
        throw std::invalid_argument("seed must be 32-byte hex");
    Bytes raw(32), pk(32), sk(64);
    for (size_t i = 0; i < 32; i++)
        raw[i] = static_cast<unsigned char>(std::stoul(seed.substr(i * 2, 2), nullptr, 16));
    crypto_sign_seed_keypair(pk.data(), sk.data(), raw.data());
    return {pk, sk};
}
std::string multikey(const std::string &seed) {
    Bytes b{0xed, 1};
    auto keys = signer(seed);
    b.insert(b.end(), keys.first.begin(), keys.first.end());
    return "z" + encode(b);
}
static std::optional<std::string> method_key(const Json &vm) {
    if (!vm.is_string())
        return std::nullopt;
    std::string s = str(vm);
    std::smatch m;
    if (!std::regex_match(s, m, std::regex("did:key:([^#]+)#(.+)")) || m[1] != m[2] ||
        !public_key(m[1].str()))
        return std::nullopt;
    return m[1].str();
}
static Bytes signing_input(const Json &document, const Json &config) {
    auto out = sha(canonicalize(config));
    auto d = sha(canonicalize(document));
    out.insert(out.end(), d.begin(), d.end());
    return out;
}
Json sign(const Json &document, const std::string &seed, const Json &options) {
    auto mk = multikey(seed);
    Json c = {{"type", "DataIntegrityProof"},
              {"cryptosuite", "eddsa-jcs-2022"},
              {"verificationMethod", has(options, "verificationMethod")
                                         ? options.at("verificationMethod")
                                         : Json("did:key:" + mk + "#" + mk)}};
    if (has(options, "created"))
        c["created"] = options.at("created");
    c["proofPurpose"] = "assertionMethod";
    auto data = signing_input(document, c);
    auto keys = signer(seed);
    Bytes signature(64);
    crypto_sign_detached(signature.data(), nullptr, data.data(), data.size(), keys.second.data());
    c["proofValue"] = "z" + encode(signature);
    return c;
}
bool verify(const Json &document, const Json &proof) {
    if (!proof.is_object() || get(proof, "type") != "DataIntegrityProof" ||
        get(proof, "cryptosuite") != "eddsa-jcs-2022" ||
        get(proof, "proofPurpose") != "assertionMethod")
        return false;
    auto mk = method_key(get(proof, "verificationMethod"));
    auto value = get(proof, "proofValue");
    if (!mk || !value.is_string() || str(value).empty() || str(value)[0] != 'z')
        return false;
    auto signature = decode(str(value).substr(1));
    if (!signature || signature->size() != 64)
        return false;
    Json config = proof;
    config.erase("proofValue");
    auto data = signing_input(document, config);
    auto pk = public_key(*mk);
    return crypto_sign_verify_detached(signature->data(), data.data(), data.size(), pk->data()) ==
           0;
}
static Json without_proof(Json e) {
    e.erase("proof");
    return e;
}
std::string scid(const Json &e) { return hash(canonicalize(without_proof(e))); }
std::string entry_hash(const Json &e, const std::string &previous) {
    auto d = without_proof(e);
    d["versionId"] = previous;
    return hash(canonicalize(d));
}
static std::string replace_all(std::string s, const std::string &from, const std::string &to) {
    size_t p = 0;
    while ((p = s.find(from, p)) != std::string::npos) {
        s.replace(p, from.size(), to);
        p += to.size();
    }
    return s;
}
static std::vector<std::string> lines(const std::string &s) {
    std::vector<std::string> out;
    size_t start = 0, p;
    while ((p = s.find('\n', start)) != std::string::npos) {
        out.push_back(s.substr(start, p - start));
        start = p + 1;
    }
    if (start < s.size())
        out.push_back(s.substr(start));
    return out;
}
Json create(const Json &input) {
    Json p = input.at("parameters");
    if (!p.contains("logVersion"))
        p["logVersion"] = "vh-log:1.0";
    if (!p.contains("scid"))
        p["scid"] = "{SCID}";
    Json e = {{"versionId", "{SCID}"},
              {"versionTime", input.at("versionTime")},
              {"parameters", p},
              {"state", input.at("state")}};
    auto id = scid(e);
    e = parse(replace_all(canonicalize(e), "{SCID}", id));
    e["versionId"] = "1-" + entry_hash(e, id);
    Json proofs = Json::array();
    for (const auto &seed : input.at("signers"))
        proofs.push_back(sign(e, str(seed), {{"created", input.at("versionTime")}}));
    e["proof"] = proofs;
    return {{"log", canonicalize(e) + "\n"}, {"scid", id}, {"versionId", e.at("versionId")}};
}
Json update(const Json &input) {
    auto log = str(input.at("log"));
    auto ls = lines(log);
    if (ls.empty())
        throw std::invalid_argument("empty log");
    auto previous = str(parse(ls.back()).at("versionId"));
    Json e = {{"versionId", previous},
              {"versionTime", input.at("versionTime")},
              {"parameters", input.value("parameters", Json::object())},
              {"state", input.at("state")}};
    e["versionId"] = std::to_string(std::stoll(previous.substr(0, previous.find('-'))) + 1) + "-" +
                     entry_hash(e, previous);
    Json proofs = Json::array();
    for (const auto &seed : input.at("signers"))
        proofs.push_back(sign(e, str(seed), {{"created", input.at("versionTime")}}));
    e["proof"] = proofs;
    return {{"log", log + (log.empty() || log.back() != '\n' ? "\n" : "") + canonicalize(e) + "\n"},
            {"versionId", e.at("versionId")}};
}
static std::optional<int64_t> time(const Json &v) {
    if (!v.is_string())
        return std::nullopt;
    std::string s = str(v);
    std::smatch m;
    if (!std::regex_match(
            s, m,
            std::regex(
                "([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(Z|\\+00:00)")))
        return std::nullopt;
    int y = std::stoi(m[1]), mo = std::stoi(m[2]), d = std::stoi(m[3]), h = std::stoi(m[4]),
        mi = std::stoi(m[5]), sec = std::stoi(m[6]);
    bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    int days[] = {31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (mo < 1 || mo > 12 || d < 1 || d > days[mo - 1] || h > 23 || mi > 59 || sec > 59)
        return std::nullopt;
    // Proleptic Gregorian civil date, including year zero.
    y -= mo <= 2;
    int era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = static_cast<unsigned>(y - era * 400);
    unsigned doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (static_cast<int64_t>(era) * 146097 + doe) * 86400 + h * 3600 + mi * 60 + sec;
}
static bool integer(const Json &v) {
    return v.is_number() && std::isfinite(v.get<double>()) &&
           v.get<double>() == std::floor(v.get<double>());
}
static bool strings(const Json &v) {
    return v.is_array() &&
           std::all_of(v.begin(), v.end(), [](const Json &x) { return x.is_string(); });
}
static Json parameters(const Json &raw, const Json &previous, int n) {
    for (const auto &v : raw)
        if (v.is_null())
            fail("invalid-parameter", n);
    if ((previous.is_null() && !has(raw, "logVersion")) ||
        (has(raw, "logVersion") && raw.at("logVersion") != "vh-log:1.0"))
        fail("unsupported-log-version", n);
    if (!previous.is_null() ? has(raw, "scid")
                            : !get(raw, "scid").is_string() || !has(raw, "updateKeys"))
        fail("invalid-parameter", n);
    if (has(raw, "updateKeys")) {
        if (!strings(raw.at("updateKeys")))
            fail("invalid-parameter", n);
        for (const auto &k : raw.at("updateKeys"))
            if (!public_key(k))
                fail("invalid-parameter", n);
    }
    if (has(raw, "nextKeyHashes")) {
        if (!strings(raw.at("nextKeyHashes")))
            fail("invalid-parameter", n);
        for (const auto &h : raw.at("nextKeyHashes"))
            if (check_hash(str(h)) != "ok")
                fail("invalid-parameter", n);
    }
    Json p = previous.is_null() ? Json{{"nextKeyHashes", Json::array()},
                                       {"witness", nullptr},
                                       {"watchers", Json::array()},
                                       {"ttl", 3600}}
                                : previous;
    for (const auto &k :
         {"logVersion", "scid", "updateKeys", "nextKeyHashes", "witness", "watchers", "ttl"})
        if (has(raw, k))
            p[k] = raw.at(k);
    p["deactivated"] = raw.value("deactivated", Json(false));
    if (has(raw, "witness")) {
        const auto &w = raw.at("witness");
        if (!w.is_object())
            fail("invalid-parameter", n);
        if (w.empty())
            p["witness"] = nullptr;
        else {
            auto ws = get(w, "witnesses");
            if (!ws.is_array() || ws.empty())
                fail("invalid-parameter", n);
            std::set<std::string> ids;
            for (const auto &x : ws) {
                auto id = get(x, "id");
                if (!id.is_string() || str(id).rfind("did:key:", 0) != 0 ||
                    !public_key(str(id).substr(8)) || !ids.insert(str(id)).second)
                    fail("invalid-parameter", n);
            }
            auto t = get(w, "threshold");
            if (!integer(t) || t.get<double>() < 1 || t.get<double>() > ids.size())
                fail("invalid-parameter", n);
            p["witness"] = {{"threshold", t}, {"witnesses", ws}};
        }
    }
    if (has(raw, "watchers")) {
        auto ws = raw.at("watchers");
        if (!strings(ws))
            fail("invalid-parameter", n);
        for (const auto &u : ws)
            if (!std::regex_match(str(u), std::regex("[\\x21-\\x7e]+")) ||
                !std::regex_search(str(u), std::regex("^https?://[^/?#]")))
                fail("invalid-parameter", n);
    }
    if (!p.at("deactivated").is_boolean() || !integer(p.at("ttl")) ||
        p.at("ttl").get<double>() < 0 || p.at("ttl").get<double>() > 2147483648.0)
        fail("invalid-parameter", n);
    if (!previous.is_null() && !previous.at("nextKeyHashes").empty()) {
        if (!has(raw, "updateKeys") || !has(raw, "nextKeyHashes"))
            fail("prerotation-violation", n);
        for (const auto &key : raw.at("updateKeys")) {
            auto h = hash(str(key));
            const auto &hs = previous.at("nextKeyHashes");
            if (std::find(hs.begin(), hs.end(), h) == hs.end())
                fail("prerotation-violation", n);
        }
    }
    return p;
}
struct Entry {
    Json e, p;
    int n;
    int64_t timestamp;
    Json rule;
};
struct Verified {
    std::vector<Entry> entries;
    std::vector<std::string> lines;
    Json failure;
};
static Entry verify_entry(const Json &e, const Entry *previous, int64_t now) {
    int n = previous ? previous->n + 1 : 1;
    if (previous && previous->p.at("deactivated") == true)
        fail("entry-after-deactivation", n);
    if (e.size() != 5 || !get(e, "versionId").is_string() || !get(e, "versionTime").is_string() ||
        !get(e, "parameters").is_object() || !get(e, "state").is_object() ||
        !get(e, "proof").is_array())
        fail("invalid-entry", n);
    auto p = parameters(e.at("parameters"), previous ? previous->p : Json(), n);
    auto active = !previous || !previous->p.at("nextKeyHashes").empty()
                      ? p.at("updateKeys")
                      : previous->p.at("updateKeys");
    auto rule =
        !previous || (has(e.at("parameters"), "witness") && previous->p.at("witness").is_null())
            ? p.at("witness")
            : previous->p.at("witness");
    if (e.at("proof").empty())
        fail("invalid-proof", n);
    for (const auto &proof : e.at("proof")) {
        auto mk = method_key(get(proof, "verificationMethod"));
        if (!mk)
            fail("invalid-proof", n);
        if (std::find(active.begin(), active.end(), *mk) == active.end())
            fail("unauthorized-key", n);
        if (!verify(without_proof(e), proof))
            fail("invalid-proof", n);
    }
    std::string id = str(e.at("versionId"));
    std::smatch m;
    if (!std::regex_match(id, m, std::regex("([1-9][0-9]*)-([^-]+)")) || m[1] != std::to_string(n))
        fail("invalid-version-id", n);
    auto check = check_hash(m[2]);
    if (check == "not-base58")
        fail("invalid-version-id", n);
    if (check != "ok")
        fail("invalid-hash-algorithm", n);
    if (entry_hash(e, str(previous ? previous->e.at("versionId") : p.at("scid"))) != m[2])
        fail("entry-hash-mismatch", n);
    auto t = time(e.at("versionTime"));
    if (!t || (previous && *t <= previous->timestamp))
        fail("invalid-version-time", n);
    if (*t > now + 300)
        fail("future-version-time", n);
    if (!previous) {
        auto sc = str(p.at("scid"));
        check = check_hash(sc);
        if (check == "unsupported-algorithm")
            fail("invalid-hash-algorithm", n);
        if (check != "ok")
            fail("scid-mismatch", n);
        auto rest = without_proof(e);
        rest["versionId"] = "{SCID}";
        if (scid(parse(replace_all(canonicalize(rest), sc, "{SCID}"))) != sc)
            fail("scid-mismatch", n);
    }
    return {e, p, n, *t, rule};
}
static Verified verify_log(const std::string &log, const Json &witness, bool has_witness,
                           int64_t now) {
    Verified v{{}, lines(log), nullptr};
    if (v.lines.empty()) {
        v.failure = Error("invalid-log").report;
        return v;
    }
    for (size_t i = 0; i < v.lines.size(); i++) {
        try {
            Json raw;
            try {
                raw = parse(v.lines[i]);
            } catch (const std::exception &) {
                fail("invalid-log", i + 1);
            }
            if (!raw.is_object())
                fail("invalid-log", i + 1);
            v.entries.push_back(
                verify_entry(raw, v.entries.empty() ? nullptr : &v.entries.back(), now));
        } catch (const Error &e) {
            v.failure = e.report;
            break;
        }
    }
    for (size_t i = 0; i < v.entries.size(); i++) {
        const auto &rule = v.entries[i].rule;
        if (rule.is_null())
            continue;
        auto file = has_witness ? witness : Json::array();
        std::string code;
        bool valid = file.is_array();
        if (valid)
            for (const auto &r : file)
                if (!get(r, "versionId").is_string() || !get(r, "proof").is_array()) {
                    valid = false;
                    break;
                }
        if (!valid)
            code = "invalid-witness-file";
        else {
            std::set<std::string> allowed, approved;
            for (const auto &w : rule.at("witnesses"))
                allowed.insert(str(w.at("id")));
            for (const auto &r : file) {
                auto it = std::find_if(v.entries.begin(), v.entries.end(), [&](const Entry &e) {
                    return e.e.at("versionId") == r.at("versionId");
                });
                if (it == v.entries.end() || static_cast<size_t>(it - v.entries.begin()) < i)
                    continue;
                for (const auto &proof : r.at("proof")) {
                    auto mk = method_key(get(proof, "verificationMethod"));
                    if (mk && allowed.count("did:key:" + *mk) &&
                        verify({{"versionId", r.at("versionId")}}, proof))
                        approved.insert("did:key:" + *mk);
                }
            }
            if (approved.size() < rule.at("threshold").get<double>())
                code = "witness-threshold-not-met";
        }
        if (!code.empty()) {
            v.failure = Error(code, i + 1).report;
            v.entries.resize(i);
            break;
        }
    }
    return v;
}
static Json line_value(const std::vector<std::string> &ls, size_t i) {
    if (i >= ls.size())
        return nullptr;
    try {
        return parse(ls[i]);
    } catch (const std::exception &) {
        return nullptr;
    }
}
static Json line_id(const std::vector<std::string> &ls, size_t i) {
    auto id = get(line_value(ls, i), "versionId");
    return id.is_string() ? id : Json();
}
static void retained(const Verified &v, const std::string &source, const Json &id, Json &warnings) {
    std::smatch m;
    auto s = id.is_string() ? str(id) : "";
    if (!std::regex_search(s, m, std::regex("^([1-9][0-9]*)-")))
        fail("invalid-option");
    double big = std::stod(m[1]);
    if (big > v.entries.size()) {
        warnings.push_back(
            {{"code", "retained-version-not-found"}, {"message", "retained version not found"}});
        return;
    }
    auto n = static_cast<size_t>(big);
    auto actual = v.entries[n - 1].e.at("versionId");
    if (actual != id)
        throw Error("fork-detected", n,
                    {{"version", n},
                     {"copies", Json::array({{{"source", "retained"}, {"versionId", id}},
                                             {{"source", source}, {"versionId", actual}}})}});
}
static Json result(const Verified &v, const Json &options, Json warnings, Json copies = nullptr) {
    const Entry *target = nullptr;
    auto invalid = [&]() { throw Error(str(v.failure.at("code")), v.failure.at("version")); };
    if (has(options, "versionId")) {
        for (const auto &e : v.entries)
            if (e.e.at("versionId") == options.at("versionId")) {
                target = &e;
                break;
            }
        if (!target)
            for (size_t i = v.entries.size(); i < v.lines.size(); i++)
                if (line_id(v.lines, i) == options.at("versionId"))
                    invalid();
    } else if (has(options, "versionNumber")) {
        double n = options.at("versionNumber").get<double>();
        if (n <= v.entries.size())
            target = &v.entries[static_cast<size_t>(n) - 1];
        else if (n <= v.lines.size())
            invalid();
    } else if (has(options, "versionTime")) {
        auto t = *time(options.at("versionTime"));
        if (!v.failure.is_null()) {
            auto it = time(get(line_value(v.lines, v.entries.size()), "versionTime"));
            if (it && *it <= t)
                invalid();
        }
        for (auto it = v.entries.rbegin(); it != v.entries.rend(); ++it)
            if (it->timestamp <= t) {
                target = &*it;
                break;
            }
    } else
        target = &v.entries.back();
    if (!target)
        fail("not-found");
    const auto &first = v.entries.front();
    const auto &last = v.entries.back();
    if (!v.failure.is_null())
        warnings.push_back({{"code", "invalid-entries"}, {"message", v.failure.at("message")}});
    Json meta = {{"versionId", target->e.at("versionId")},
                 {"versionTime", target->e.at("versionTime")},
                 {"versionNumber", target->n},
                 {"created", first.e.at("versionTime")},
                 {"updated", last.e.at("versionTime")},
                 {"scid", first.p.at("scid")},
                 {"deactivated", last.p.at("deactivated")},
                 {"ttl", last.p.at("ttl")},
                 {"witness", last.p.at("witness")},
                 {"watchers", last.p.at("watchers")},
                 {"updateKeys", target->p.at("updateKeys")},
                 {"nextKeyHashes", target->p.at("nextKeyHashes")},
                 {"warnings", warnings}};
    if (!copies.is_null())
        meta["copies"] = copies;
    return {{"valid", true},
            {"state", target->e.at("state")},
            {"metadata", meta},
            {"firstInvalidVersion", v.failure.is_null() ? Json() : Json(v.entries.size() + 1)},
            {"error", v.failure}};
}
static Json resolve_copies(const Json &input, int64_t now, const Json &options) {
    Json primary = {{"source", "primary"}, {"log", input.at("log")}};
    if (has(input, "witness"))
        primary["witness"] = input.at("witness");
    Json all = Json::array({primary});
    if (has(input, "copies"))
        for (const auto &c : input.at("copies"))
            all.push_back(c);
    Json warnings = Json::array();
    std::map<size_t, std::string> status;
    std::map<size_t, Verified> cache;
    auto get_copy = [&](size_t i) -> const Verified & {
        if (!cache.count(i)) {
            const auto &c = all[i];
            cache.emplace(i,
                          verify_log(str(c.at("log")), get(c, "witness"), has(c, "witness"), now));
        }
        return cache.at(i);
    };
    auto invalid = [&](size_t i) {
        status[i] = "invalid";
        warnings.push_back({{"code", "copy-invalid"},
                            {"source", all[i].at("source")},
                            {"message", "copy fails verification"}});
    };
    for (size_t i = 0; i < all.size(); i++)
        if (has(all[i], "unavailable")) {
            status[i] = "unavailable";
            warnings.push_back({{"code", "copy-unavailable"},
                                {"source", all[i].at("source")},
                                {"message", all[i].at("unavailable")}});
        }
    size_t ref = all.size();
    for (size_t i = 0; i < all.size(); i++) {
        if (status.count(i))
            continue;
        if (get_copy(i).failure.is_null()) {
            ref = i;
            break;
        }
        invalid(i);
    }
    if (ref == all.size())
        return {{"valid", false}, {"error", get_copy(0).failure}};
    std::set<size_t> matched{ref};
    for (size_t i = 0; i < all.size(); i++) {
        if (status.count(i) || matched.count(i))
            continue;
        const auto &r = get_copy(ref);
        const auto &c = get_copy(i);
        const auto &rl = r.lines;
        const auto &cl = c.lines;
        if (cl.empty()) {
            invalid(i);
            continue;
        }
        bool same = cl.size() <= rl.size() &&
                    line_id(cl, cl.size() - 1) == r.entries[cl.size() - 1].e.at("versionId");
        bool extends = cl.size() > rl.size() &&
                       line_id(cl, rl.size() - 1) == r.entries.back().e.at("versionId");
        if (same)
            matched.insert(i);
        else if (extends && c.failure.is_null()) {
            matched.insert(i);
            ref = i;
        } else if (!c.failure.is_null())
            invalid(i);
        else {
            size_t k = 0;
            while (k < std::min(rl.size(), cl.size()) && line_id(rl, k) == line_id(cl, k))
                ++k;
            auto rid = line_id(rl, k), cid = line_id(cl, k);
            throw Error(
                "fork-detected", k + 1,
                {{"version", k + 1},
                 {"copies", Json::array({{{"source", all[ref].at("source")},
                                          {"versionId", rid.is_null() ? Json("") : rid}},
                                         {{"source", all[i].at("source")},
                                          {"versionId", cid.is_null() ? Json("") : cid}}})}});
        }
    }
    const auto &r = get_copy(ref);
    if (has(input, "retainedVersionId"))
        retained(r, str(all[ref].at("source")), input.at("retainedVersionId"), warnings);
    Json copies = Json::array();
    size_t usable = 0;
    for (size_t i = 0; i < all.size(); i++) {
        auto source = all[i].at("source");
        Json report = {{"source", source}};
        if (status.count(i)) {
            auto s = status.at(i);
            report["status"] = s;
            if (s != "unavailable") {
                const auto &ls = get_copy(i).lines;
                auto id = line_id(ls, ls.size() - 1);
                if (!id.is_null())
                    report["versionId"] = id;
            }
        } else {
            const auto &ls = get_copy(i).lines;
            bool behind = ls.size() < r.lines.size();
            report["status"] = behind ? "behind" : "current";
            report["versionId"] = line_id(ls, ls.size() - 1);
            ++usable;
            if (behind)
                warnings.push_back(
                    {{"code", "copy-behind"}, {"source", source}, {"message", "copy is behind"}});
        }
        copies.push_back(report);
    }
    if (usable < options.value("minCopies", 1.0))
        fail("min-copies-not-met");
    return result(r, options, warnings, copies);
}
Json resolve(const Json &input) {
    try {
        auto now = time(get(input, "now"));
        if (!now)
            fail("invalid-option");
        Json options = get(input, "options");
        if (options.is_null())
            options = Json::object();
        if (!options.is_object())
            fail("invalid-option");
        std::set<std::string> allowed{"versionId", "versionTime", "versionNumber", "minCopies"};
        int selectors = 0;
        for (auto it = options.begin(); it != options.end(); ++it) {
            if (!allowed.count(it.key()))
                fail("invalid-option");
            if (it.key() != "minCopies")
                ++selectors;
        }
        if (selectors > 1)
            fail("invalid-option");
        if (has(options, "versionId") && !options.at("versionId").is_string())
            fail("invalid-option");
        if (has(options, "versionTime") && !time(options.at("versionTime")))
            fail("invalid-option");
        for (const auto &k : {"versionNumber", "minCopies"})
            if (has(options, k) && (!integer(options.at(k)) || options.at(k).get<double>() < 1))
                fail("invalid-option");
        if (has(input, "copies") || options.value("minCopies", 1.0) > 1)
            return resolve_copies(input, *now, options);
        auto v =
            verify_log(str(input.at("log")), get(input, "witness"), has(input, "witness"), *now);
        if (v.entries.empty())
            return {{"valid", false}, {"error", v.failure}};
        Json warnings = Json::array();
        if (has(input, "retainedVersionId"))
            retained(v, "primary", input.at("retainedVersionId"), warnings);
        return result(v, options, warnings);
    } catch (const Error &e) {
        return {{"valid", false}, {"error", e.report}};
    }
}
Json dispatch(const std::string &op, const Json &input) {
    if (op == "jcs")
        return {{"output", canonicalize(parse(str(input.at("text"))))}};
    if (op == "hash")
        return {{"output", hash(str(input.at("data")))}};
    if (op == "key-hash")
        return {{"output", hash(str(input.at("multikey")))}};
    if (op == "multikey")
        return {{"multikey", multikey(str(input.at("seed")))}};
    if (op == "scid")
        return {{"scid", scid(input.at("entry"))}};
    if (op == "entry-hash")
        return {{"hash", entry_hash(input.at("entry"), str(input.at("previousVersionId")))}};
    if (op == "sign")
        return {{"proof", sign(input.at("document"), str(input.at("seed")), input)}};
    if (op == "verify")
        return {{"valid", verify(input.at("document"), input.at("proof"))}};
    if (op == "witness")
        return {
            {"proof", sign({{"versionId", input.at("versionId")}}, str(input.at("seed")), input)}};
    if (op == "create")
        return create(input);
    if (op == "update")
        return update(input);
    if (op == "resolve")
        return resolve(input);
    throw std::invalid_argument("unknown operation " + op);
}
} // namespace vhlog
