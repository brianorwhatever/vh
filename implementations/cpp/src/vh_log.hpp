#pragma once
#include <nlohmann/json.hpp>
#include <string>

namespace vhlog {
using Json = nlohmann::json;
Json parse(const std::string &text);
std::string canonicalize(const Json &value);
std::string hash(const std::string &data);
std::string multikey(const std::string &seed);
std::string scid(const Json &entry);
std::string entry_hash(const Json &entry, const std::string &previous);
Json sign(const Json &document, const std::string &seed, const Json &options = Json::object());
bool verify(const Json &document, const Json &proof);
Json create(const Json &input);
Json update(const Json &input);
Json resolve(const Json &input);
Json dispatch(const std::string &op, const Json &input);
} // namespace vhlog
