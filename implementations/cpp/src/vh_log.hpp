#pragma once
#include <cstdint>
#include <functional>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

namespace vhlog {
using Json = nlohmann::json;
// What a specialisation of VH-Log (such as did:vh) changes in verification.
// Hashing, proofs, witnesses and pre-rotation are shared.
struct Specialisation {
    std::string version_parameter; // "logVersion" in plain VH-Log
    std::string version;           // the accepted value
    // When set, a missing or malformed version is invalid-parameter, and only a
    // well-formed value other than `version` is unsupported-log-version.
    std::function<bool(const std::string &)> version_syntax;
    bool closed; // an unknown parameter is invalid-parameter
    // Checks an entry's state once the SCID is known; false is invalid-state.
    std::function<bool(const Json &state, const std::string &scid)> check_state;
};
extern const Specialisation VH_LOG;
Json parse(const std::string &text);
std::string canonicalize(const Json &value);
std::string hash(const std::string &data);
std::string multikey(const std::string &seed);
std::string scid(const Json &entry);
std::string entry_hash(const Json &entry, const std::string &previous);
Json sign(const Json &document, const std::string &seed, const Json &options = Json::object());
bool verify(const Json &document, const Json &proof);
Json create(const Json &input, const Specialisation &spec = VH_LOG);
Json update(const Json &input);
Json resolve(const Json &input, const Specialisation &spec = VH_LOG);
// Whether some entry of the log has an active witness list.
bool needs_witnessing(const std::string &log, int64_t now, const Specialisation &spec);
std::optional<int64_t> parse_time(const Json &value);
Json dispatch(const std::string &op, const Json &input);
} // namespace vhlog
