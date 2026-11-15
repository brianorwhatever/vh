#pragma once
// did:vh (docs/didvh-profile.md). A did:vh DID log has the same format and
// verification as a VH-Log log, so it is verified by the VH-Log code with the
// did:vh specialisation. This module adds the DID syntax, the srcLog/srcWitness
// and DID URL rules, the resolution options, and DID Resolution metadata and
// errors.
#include "vh_log.hpp"
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace vhlog::didvh {
inline const std::string METHOD = "did:vh:1.0";
inline const std::string DID_PREFIX = "did:vh:";

// A did:vh error code (invalidDid, invalidDidUrl, invalidOptions, notFound,
// featureNotSupported, logForked, insufficientCopies), with the VH-Log error
// report behind it where there is one.
struct Error : std::runtime_error {
    std::string code;
    Json vh_log;
    Error(std::string code, const std::string &message, Json vh_log = nullptr)
        : std::runtime_error(message), code(std::move(code)), vh_log(std::move(vh_log)) {}
};

// The SCID of a did:vh DID, or nullopt if it does not match the ABNF.
std::optional<std::string> parse_did(const Json &did);
// The did:vh specialisation of VH-Log. With expected_scid, the log's SCID must
// also be that of the DID being resolved.
Specialisation specialisation(std::optional<std::string> expected_scid = std::nullopt);
// {document, parameters, versionTime, signers} -> {log, did, scid, versionId}.
Json create_did(const Json &input);
// {log, document, parameters?, versionTime, signers} -> {log, versionId}.
Json update_did(const Json &input);
// The kind of a srcLog/srcWitness reference: web, loopback, file or other.
// Throws invalidOptions.
std::string check_ref(const Json &ref);
// srcLog and srcWitness derived from a (percent-decoded) src DID URL
// parameter. Throws invalidDidUrl.
std::pair<std::string, std::string> src_references(const std::string &src);
// {did, options, fragment?} from a did:vh DID URL. Throws invalidDidUrl.
Json parse_did_url(const Json &did_url);
// Offline did:vh resolution: {didResolutionMetadata, didDocument, didDocumentMetadata}.
// `now` is an ISO 8601 time (null for the current time).
Json resolve_did(const Json &did, const Json &options, const Json &now = nullptr,
                 bool remote = false);
// The didvh-* driver operations, with the "didvh-" prefix removed.
Json dispatch(const std::string &op, const Json &input);
} // namespace vhlog::didvh
