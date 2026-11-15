#include "didvh.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <ctime>
#include <regex>
#include <vector>

namespace vhlog::didvh {
namespace {
const std::string ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool has(const Json &v, const std::string &k) { return v.is_object() && v.contains(k); }
Json get(const Json &v, const std::string &k) { return has(v, k) ? v.at(k) : Json(); }
bool starts_with(const std::string &s, const std::string &prefix) {
    return s.compare(0, prefix.size(), prefix) == 0;
}
std::string lower(std::string s) {
    for (auto &c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
std::vector<std::string> split(const std::string &s, char sep) {
    std::vector<std::string> out;
    size_t start = 0, p;
    while ((p = s.find(sep, start)) != std::string::npos) {
        out.push_back(s.substr(start, p - start));
        start = p + 1;
    }
    out.push_back(s.substr(start));
    return out;
}
bool integer(const Json &v) {
    return v.is_number() && std::isfinite(v.get<double>()) &&
           v.get<double>() == std::floor(v.get<double>());
}
bool positive_integer(const Json &v) { return integer(v) && v.get<double>() >= 1; }

// Decodes UTF-8 into code points; nullopt if malformed (RFC 3629).
std::optional<std::vector<uint32_t>> code_points(const std::string &s) {
    std::vector<uint32_t> out;
    for (size_t i = 0; i < s.size();) {
        unsigned char b = static_cast<unsigned char>(s[i]);
        size_t extra;
        uint32_t cp, min;
        if (b < 0x80) {
            out.push_back(b);
            ++i;
            continue;
        } else if ((b & 0xE0) == 0xC0)
            extra = 1, cp = b & 0x1F, min = 0x80;
        else if ((b & 0xF0) == 0xE0)
            extra = 2, cp = b & 0x0F, min = 0x800;
        else if ((b & 0xF8) == 0xF0)
            extra = 3, cp = b & 0x07, min = 0x10000;
        else
            return std::nullopt;
        if (s.size() - i <= extra)
            return std::nullopt;
        for (size_t j = 1; j <= extra; ++j) {
            unsigned char c = static_cast<unsigned char>(s[i + j]);
            if ((c & 0xC0) != 0x80)
                return std::nullopt;
            cp = (cp << 6) | (c & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
            return std::nullopt;
        out.push_back(cp);
        i += extra + 1;
    }
    return out;
}
int hex(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}
} // namespace

// Percent-decodes `s` as UTF-8, or nullopt if an escape or the UTF-8 is malformed.
static std::optional<std::string> percent_decode(const std::string &s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%') {
            if (s.size() - i < 3 || hex(s[i + 1]) < 0 || hex(s[i + 2]) < 0)
                return std::nullopt;
            out += static_cast<char>(hex(s[i + 1]) * 16 + hex(s[i + 2]));
            i += 2;
        } else
            out += s[i];
    }
    if (!code_points(out))
        return std::nullopt;
    return out;
}

// Unicode White_Space (profile §3.2).
static bool whitespace(uint32_t c) {
    return (c >= 0x09 && c <= 0x0d) || c == 0x20 || c == 0x85 || c == 0xa0 || c == 0x1680 ||
           (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f ||
           c == 0x205f || c == 0x3000;
}

std::optional<std::string> parse_did(const Json &did) {
    if (!did.is_string())
        return std::nullopt;
    auto s = did.get<std::string>();
    if (!starts_with(s, DID_PREFIX) || s.size() != DID_PREFIX.size() + 46)
        return std::nullopt;
    auto scid = s.substr(DID_PREFIX.size());
    if (scid.find_first_not_of(ALPHABET) != std::string::npos)
        return std::nullopt;
    return scid;
}

Specialisation specialisation(std::optional<std::string> expected_scid) {
    static const std::regex syntax("did:vh:(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)");
    return {"method", METHOD,
            [](const std::string &v) { return std::regex_match(v, syntax); }, true,
            [expected_scid](const Json &state, const std::string &scid) {
                if (expected_scid && scid != *expected_scid)
                    return false;
                return get(state, "id") == Json(DID_PREFIX + scid);
            }};
}

Json create_did(const Json &input) {
    Json in = {{"state", input.at("document")},
               {"parameters", input.at("parameters")},
               {"versionTime", input.at("versionTime")},
               {"signers", input.at("signers")}};
    Json out = create(in, specialisation());
    out["did"] = DID_PREFIX + out.at("scid").get<std::string>();
    return out;
}

Json update_did(const Json &input) {
    Json in = {{"log", input.at("log")},
               {"state", input.at("document")},
               {"versionTime", input.at("versionTime")},
               {"signers", input.at("signers")}};
    if (has(input, "parameters"))
        in["parameters"] = input.at("parameters");
    return update(in);
}

// ---------------------------------------------------------------- shared URL checks

static bool is_octet(const std::string &s) {
    static const std::regex octet("0|[1-9][0-9]{0,2}");
    return std::regex_match(s, octet) && std::stoi(s) <= 255;
}

static bool is_loopback_host(const std::string &host) {
    if (host == "localhost" || host == "[::1]")
        return true;
    auto parts = split(host, '.');
    return parts.size() == 4 && std::all_of(parts.begin(), parts.end(), is_octet) &&
           parts[0] == "127";
}

static bool is_domain_name(const std::string &host) {
    static const std::regex label("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");
    static const std::regex digits("[0-9]+");
    auto name = !host.empty() && host.back() == '.' ? host.substr(0, host.size() - 1) : host;
    if (name.empty() || name.size() > 253)
        return false;
    auto labels = split(name, '.');
    if (std::regex_match(labels.back(), digits)) // an IPv4 literal, or ends in a number
        return false;
    return std::all_of(labels.begin(), labels.end(),
                       [](const std::string &l) { return std::regex_match(l, label); });
}

// Splits scheme:rest (profile §3.1 steps 1–2); nullopt unless `value` is
// printable ASCII with a scheme. The scheme is lowercased.
static std::optional<std::pair<std::string, std::string>> split_scheme(const Json &value) {
    if (!value.is_string())
        return std::nullopt;
    auto s = value.get<std::string>();
    if (s.empty() || !std::all_of(s.begin(), s.end(), [](char c) {
            return static_cast<unsigned char>(c) >= 0x21 && static_cast<unsigned char>(c) <= 0x7e;
        }))
        return std::nullopt;
    static const std::regex scheme("([A-Za-z][A-Za-z0-9+.-]*):([\\s\\S]*)");
    std::smatch m;
    if (!std::regex_match(s, m, scheme))
        return std::nullopt;
    return std::make_pair(lower(m[1].str()), m[2].str());
}

// Checks an http(s) authority (profile §3.1 step 4).
static bool check_authority(const std::string &authority, bool http) {
    if (authority.find('@') != std::string::npos)
        return false;
    std::string host;
    std::optional<std::string> port;
    if (!authority.empty() && authority[0] == '[') {
        auto close = authority.find(']');
        if (close == std::string::npos)
            return false;
        host = authority.substr(0, close + 1);
        auto after = authority.substr(close + 1);
        if (!after.empty()) {
            if (after[0] != ':')
                return false;
            port = after.substr(1);
        }
    } else {
        auto colon = authority.find(':');
        host = authority.substr(0, colon);
        if (colon != std::string::npos)
            port = authority.substr(colon + 1);
    }
    host = lower(host);
    static const std::regex digits("[0-9]{1,5}");
    if (port && !(std::regex_match(*port, digits) && std::stoi(*port) <= 65535))
        return false;
    if (http)
        return is_loopback_host(host);
    return host[0] != '[' && is_domain_name(host);
}

// Checks the segments of a path that starts with '/' (profile §3). Each is
// percent-decoded and must not be . or .. or contain /, \ or NUL. With
// `strict` (the src DID URL parameter), it must also be non-empty and not
// start or end with whitespace.
static bool check_segments(const std::string &path, bool strict) {
    for (const auto &raw : split(path.substr(1), '/')) {
        auto segment = percent_decode(raw);
        if (!segment || *segment == "." || *segment == ".." ||
            segment->find_first_of(std::string("/\\\0", 3)) != std::string::npos)
            return false;
        if (strict) {
            auto cps = *code_points(*segment);
            if (cps.empty() || whitespace(cps.front()) || whitespace(cps.back()))
                return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------- references

std::string check_ref(const Json &ref) {
    auto invalid = [&](const std::string &why) {
        return Error("invalidOptions", "reference " + ref.dump() + ": " + why);
    };
    auto parts = split_scheme(ref);
    if (!parts)
        throw invalid("not a printable-ASCII absolute URL");
    const auto &[scheme, rest] = *parts;
    if (rest.find('#') != std::string::npos)
        throw invalid("must not have a fragment");

    if (scheme == "https" || scheme == "http") {
        if (!starts_with(rest, "//"))
            throw invalid("missing authority");
        auto end = rest.find_first_of("/?", 2);
        auto authority = rest.substr(2, end == std::string::npos ? std::string::npos : end - 2);
        auto after = end == std::string::npos ? "" : rest.substr(end);
        auto path = after.substr(0, after.find('?'));
        if (!check_authority(authority, scheme == "http"))
            throw invalid(scheme == "http" ? "http is only allowed with a loopback host"
                                           : "invalid https host");
        if (path.empty())
            throw invalid("must have a path");
        if (!check_segments(path, false))
            throw invalid("invalid path segment");
        return scheme == "http" ? "loopback" : "web";
    }

    if (scheme == "file") {
        if (rest.find('?') != std::string::npos)
            throw invalid("must not have a query");
        std::string path;
        if (starts_with(rest, "//")) {
            auto slash = rest.find('/', 2);
            if (slash == std::string::npos)
                throw invalid("file URL needs an absolute path");
            auto host = lower(rest.substr(2, slash - 2));
            if (!host.empty() && host != "localhost")
                throw invalid("file URL host must be empty or localhost");
            path = rest.substr(slash);
        } else {
            if (!starts_with(rest, "/"))
                throw invalid("file URL needs an absolute path");
            path = rest;
        }
        if (!check_segments(path, false))
            throw invalid("invalid path segment");
        return "file";
    }

    if (rest.empty())
        throw invalid("empty URL");
    return "other";
}

std::pair<std::string, std::string> src_references(const std::string &src) {
    auto invalid = [&](const std::string &why) {
        return Error("invalidDidUrl", "src " + Json(src).dump() + ": " + why);
    };
    auto parts = split_scheme(Json(src));
    if (!parts)
        throw invalid("not a printable-ASCII absolute URL");
    const auto &[scheme, rest] = *parts;
    if (rest.find_first_of("?#") != std::string::npos)
        throw invalid("must not have a query or fragment");
    if (scheme == "http" || scheme == "file")
        throw invalid(scheme + " is not allowed in a DID URL");
    if (!starts_with(rest, "//") || rest.size() == 2 || rest[2] == '/')
        throw invalid("not a hierarchical URL with an authority");
    auto base = rest.back() == '/' ? rest.substr(0, rest.size() - 1) : rest;
    if (scheme == "https") {
        auto slash = base.find('/', 2);
        auto authority =
            base.substr(2, slash == std::string::npos ? std::string::npos : slash - 2);
        auto path = slash == std::string::npos ? "" : base.substr(slash);
        if (!check_authority(authority, false))
            throw invalid("invalid https host");
        if (!path.empty() && !check_segments(path, true))
            throw invalid("invalid path segment");
    }
    auto location = scheme + ":" + base;
    return {location + "/did.jsonl", location + "/did-witness.json"};
}

// ---------------------------------------------------------------- DID URLs

Json parse_did_url(const Json &did_url) {
    static const std::vector<std::string> url_parameters{"src", "versionId", "versionTime",
                                                         "versionNumber"};
    static const std::vector<std::string> option_only{
        "didLog",        "didWitness",    "srcLog",    "srcWitness",
        "checkWatchers", "extraWatchers", "minCopies", "includeDidLog"};
    auto invalid = [&](const std::string &why) {
        return Error("invalidDidUrl", did_url.dump() + ": " + why);
    };
    if (!did_url.is_string())
        throw invalid("not a string");
    auto url = did_url.get<std::string>();
    auto hash = url.find('#');
    auto before = url.substr(0, hash);
    auto q = before.find('?');
    auto did = before.substr(0, q);
    if (!parse_did(Json(did)))
        throw invalid("not a did:vh DID");
    Json options = Json::object();
    if (q != std::string::npos) {
        std::vector<std::string> seen;
        for (const auto &pair : split(before.substr(q + 1), '&')) {
            auto eq = pair.find('=');
            if (eq == std::string::npos)
                throw invalid("query parameter " + Json(pair).dump() + " has no value");
            auto key = percent_decode(pair.substr(0, eq));
            auto value = percent_decode(pair.substr(eq + 1));
            if (!key || !value)
                throw invalid("malformed percent-encoding");
            if (std::count(option_only.begin(), option_only.end(), *key))
                throw invalid(*key + " is a resolution option, not a DID URL parameter");
            if (!std::count(url_parameters.begin(), url_parameters.end(), *key))
                continue;
            if (std::count(seen.begin(), seen.end(), *key))
                throw invalid(*key + " given more than once");
            seen.push_back(*key);
            if (*key == "src") {
                auto [log, witness] = src_references(*value);
                options["srcLog"] = log;
                options["srcWitness"] = witness;
            } else if (*key == "versionNumber") {
                static const std::regex number("[1-9][0-9]{0,15}");
                if (!std::regex_match(*value, number))
                    throw invalid("versionNumber must be a positive integer");
                options["versionNumber"] = std::stoll(*value);
            } else
                options[*key] = *value;
        }
    }
    Json out = {{"did", did}, {"options", options}};
    if (hash != std::string::npos)
        out["fragment"] = url.substr(hash + 1);
    return out;
}

// ---------------------------------------------------------------- resolve

static bool is_watcher_url(const Json &v) {
    static const std::regex url("[\\x21-\\x7e]+");
    static const std::regex authority("^https?://[^/?#]");
    return v.is_string() && std::regex_match(v.get<std::string>(), url) &&
           std::regex_search(v.get<std::string>(), authority);
}

// did:vh resolution options validation (profile §5 step 2).
static void validate_options(const Json &o, bool remote) {
    auto invalid = [](const std::string &why) { return Error("invalidOptions", why); };
    if (!o.is_object())
        throw invalid("resolution options must be an object");
    if (has(o, "didLog") == has(o, "srcLog"))
        throw invalid("exactly one of didLog and srcLog must be given");
    if (has(o, "didWitness") && has(o, "srcWitness"))
        throw invalid("at most one of didWitness and srcWitness may be given");
    if (has(o, "didLog") && !o.at("didLog").is_string())
        throw invalid("didLog must be a string");
    if (has(o, "didWitness") && !o.at("didWitness").is_array())
        throw invalid("didWitness must be an array");
    for (const auto &key : {"srcLog", "srcWitness"}) {
        if (!has(o, key))
            continue;
        auto kind = check_ref(o.at(key));
        if (remote && (kind == "file" || kind == "loopback"))
            throw invalid(std::string(key) + ": a resolver that serves other systems must not use "
                                             "local file or loopback references");
    }
    if (has(o, "versionId") + has(o, "versionTime") + has(o, "versionNumber") > 1)
        throw invalid("at most one of versionId, versionTime and versionNumber may be given");
    if (has(o, "versionId") && !o.at("versionId").is_string())
        throw invalid("versionId must be a string");
    if (has(o, "versionTime") && !parse_time(o.at("versionTime")))
        throw invalid("versionTime must be a whole-second UTC ISO 8601 time");
    if (has(o, "versionNumber") && !positive_integer(o.at("versionNumber")))
        throw invalid("versionNumber must be a positive integer");
    if (has(o, "checkWatchers")) {
        const auto &c = o.at("checkWatchers");
        if (c != "all" && !(integer(c) && c.get<double>() >= 0))
            throw invalid("checkWatchers must be a non-negative integer or \"all\"");
    }
    if (has(o, "extraWatchers")) {
        const auto &w = o.at("extraWatchers");
        if (!w.is_array() || !std::all_of(w.begin(), w.end(), [](const Json &u) {
                return is_watcher_url(u) && starts_with(u.get<std::string>(), "https://");
            }))
            throw invalid("extraWatchers must be an array of https URLs");
    }
    if (has(o, "minCopies") && !positive_integer(o.at("minCopies")))
        throw invalid("minCopies must be a positive integer");
    if (has(o, "includeDidLog") && !o.at("includeDidLog").is_boolean())
        throw invalid("includeDidLog must be a boolean");
}

static std::string error_code(const std::string &vh_log_code) {
    if (vh_log_code == "not-found")
        return "notFound";
    if (vh_log_code == "invalid-option")
        return "invalidOptions";
    if (vh_log_code == "fork-detected")
        return "logForked";
    if (vh_log_code == "min-copies-not-met")
        return "insufficientCopies";
    if (vh_log_code == "unsupported-log-version")
        return "featureNotSupported";
    return "invalidDid";
}

static std::string current_time() {
    std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buffer[32];
    std::strftime(buffer, sizeof buffer, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buffer;
}

static std::vector<std::string> log_lines(const std::string &log) {
    auto lines = split(log, '\n');
    if (lines.back().empty())
        lines.pop_back();
    return lines;
}

static Json resolve_or_throw(const Json &did, const Json &options, const Json &now_value,
                             bool remote) {
    auto scid = parse_did(did);
    if (!scid)
        throw Error("invalidDid", did.dump() + " is not a did:vh DID");
    validate_options(options, remote);
    if (has(options, "srcLog"))
        throw Error("featureNotSupported", "this resolver does not retrieve srcLog references");
    const auto &cw = get(options, "checkWatchers");
    if ((!cw.is_null() && cw != 0) || !get(options, "extraWatchers").empty())
        throw Error("featureNotSupported", "this resolver does not retrieve copies from watchers");
    auto spec = specialisation(scid);
    Json now = now_value.is_null() ? Json(current_time()) : now_value;
    auto clock = parse_time(now);
    if (!clock)
        clock = parse_time(Json(current_time()));
    const auto log = options.at("didLog").get<std::string>();
    bool witnessed = needs_witnessing(log, *clock, spec);
    if (witnessed && has(options, "srcWitness"))
        throw Error("featureNotSupported", "this resolver does not retrieve srcWitness references");
    Json vh_options = Json::object();
    for (const auto &key : {"versionId", "versionTime", "versionNumber", "minCopies"})
        if (has(options, key))
            vh_options[key] = options.at(key);
    Json input = {{"log", log}, {"now", now}, {"options", vh_options}};
    if (has(options, "didWitness"))
        input["witness"] = options.at("didWitness");
    auto result = resolve(input, spec);
    const auto &error = result.at("error");
    if (result.at("valid") != true)
        throw Error(error_code(error.at("code")), error.at("message"), error);
    bool selected =
        has(options, "versionId") || has(options, "versionTime") || has(options, "versionNumber");
    if (!selected && !error.is_null() && error.at("code") == "unsupported-log-version")
        // Entries after the last valid one may change the document or its keys (profile §5).
        throw Error("featureNotSupported", error.at("message"), error);
    const auto &m = result.at("metadata");
    Json metadata = {{"versionId", m.at("versionId")},
                     {"versionTime", m.at("versionTime")},
                     {"created", m.at("created")},
                     {"updated", m.at("updated")},
                     {"scid", m.at("scid")},
                     {"deactivated", m.at("deactivated")},
                     {"ttl", static_cast<int64_t>(m.at("ttl").get<double>())},
                     {"watchers", m.at("watchers")}};
    if (!m.at("witness").is_null())
        metadata["witness"] = {
            {"threshold", static_cast<int64_t>(m.at("witness").at("threshold").get<double>())},
            {"witnesses", m.at("witness").at("witnesses")}};
    Json meta = {{"contentType", "application/did+json"}};
    if (!m.at("warnings").empty())
        meta["warnings"] = m.at("warnings");
    if (get(options, "includeDidLog") == true) {
        auto lines = log_lines(log);
        const auto &first_invalid = result.at("firstInvalidVersion");
        size_t valid = first_invalid.is_null()
                           ? lines.size()
                           : static_cast<size_t>(first_invalid.get<double>()) - 1;
        std::string kept;
        for (size_t i = 0; i < valid; ++i)
            kept += lines[i] + "\n";
        meta["didLog"] = kept;
        if (witnessed)
            meta["didWitness"] = has(options, "didWitness") ? options.at("didWitness") : Json::array();
    }
    // A deactivated DID's document is not returned; earlier versions still are (profile §5).
    bool last = m.at("versionTime") == m.at("updated");
    return {{"didResolutionMetadata", meta},
            {"didDocument", m.at("deactivated") == true && last ? Json() : result.at("state")},
            {"didDocumentMetadata", metadata}};
}

Json resolve_did(const Json &did, const Json &options, const Json &now, bool remote) {
    try {
        return resolve_or_throw(did, options, now, remote);
    } catch (const Error &e) {
        Json problem = {{"title", e.code}, {"detail", e.what()}};
        if (!e.vh_log.is_null())
            problem["vhLog"] = e.vh_log;
        return {{"didResolutionMetadata", {{"error", e.code}, {"problemDetails", problem}}},
                {"didDocument", nullptr},
                {"didDocumentMetadata", Json::object()}};
    }
}

// Runs `fn`, turning a did:vh error into {valid: false, error}.
template <typename F> static Json rejected(F fn) {
    try {
        return fn();
    } catch (const Error &e) {
        return {{"valid", false}, {"error", e.code}};
    }
}

Json dispatch(const std::string &op, const Json &input) {
    if (op == "create")
        return create_did(input);
    if (op == "update")
        return update_did(input);
    if (op == "resolve")
        return resolve_did(get(input, "did"), has(input, "options") ? input.at("options") : Json::object(),
                           get(input, "now"), get(input, "remote") == true);
    if (op == "ref")
        return rejected([&] { return Json{{"valid", true}, {"kind", check_ref(get(input, "ref"))}}; });
    if (op == "src")
        return rejected([&] {
            const auto &src = get(input, "src");
            if (!src.is_string())
                throw Error("invalidDidUrl", "src must be a string");
            auto [log, witness] = src_references(src.get<std::string>());
            return Json{{"valid", true}, {"srcLog", log}, {"srcWitness", witness}};
        });
    if (op == "did-url")
        return rejected([&] {
            auto out = parse_did_url(get(input, "didUrl"));
            out["valid"] = true;
            return out;
        });
    throw std::invalid_argument("unknown operation didvh-" + op);
}
} // namespace vhlog::didvh
