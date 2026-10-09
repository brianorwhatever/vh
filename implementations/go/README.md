# vhlog (Go)

A Go implementation of VH-Log for the [interop profile](../../docs/profile.md):
JCS, base58btc/multihash/multikey, `eddsa-jcs-2022` proofs, the Log Controller
operations, log verification and resolution (version selection, partial
validity, witnesses, copy comparison and retained `versionId`s).

Standard library only (`crypto/ed25519`, `crypto/sha256`, `encoding/json`).
Go 1.22+.

```go
import (
	"crypto/ed25519"
	"fmt"
	"time"

	vhlog "github.com/brianorwhatever/vh/implementations/go"
)

key, _ := vhlog.KeyFromSeedHex("0101010101010101010101010101010101010101010101010101010101010101")
signers := []ed25519.PrivateKey{key}

created, _ := vhlog.CreateLog(vhlog.ObjectOf("id", "example:{SCID}"),
	vhlog.ObjectOf("updateKeys", []string{vhlog.Multikey(key)}), "2026-01-01T00:00:00Z", signers)
updated, _ := vhlog.UpdateLog(created.Log,
	vhlog.ObjectOf("id", "example:"+created.SCID, "name", "updated"),
	nil, // no parameter changes; vhlog.ObjectOf("deactivated", true) deactivates
	"2026-01-02T00:00:00Z", signers)

res, err := vhlog.Resolve(vhlog.ResolveInput{
	Log: updated.Log,
	Now: time.Now(),
	// Witness: raw vh-log-witness.json bytes (nil if there is none)
	// Options: vhlog.ResolveOptions{VersionNumber: &n} / VersionID / VersionTime / MinCopies
	// Copies:  watcher copies; RetainedVersionID: a previously seen versionId
})
if err != nil {
	fmt.Println(err.(*vhlog.VHLogError).Code) // e.g. "scid-mismatch"
	return
}
fmt.Println(res.Metadata.VersionID, vhlog.Stringify(res.State))
if res.FirstInvalidVersion != nil { // later entries failed (profile §4)
	fmt.Println("invalid from", *res.FirstInvalidVersion, res.Error.Code)
}
```

`VerifyLog` gives the lower-level view: the valid, witnessed prefix of a log
and its first failure. Failures are `*VHLogError` values whose `Code` is one of
the `ErrorCode` constants from profile §6.

JSON values use the package's own model (`ParseJSON`, `Stringify`,
`Canonicalize`): numbers are `float64`, objects are ordered `*Object`s (last
duplicate key wins) and strings keep lone surrogates, because RFC 8785 and the
vectors need exactly that; `encoding/json`'s generic decoding would sort keys
by bytes and replace lone surrogates.

## Layout

| File | Contents |
| --- | --- |
| `json.go` | JSON parser/serialiser, JCS, ECMAScript number formatting |
| `encoding.go` | base58btc, multikeys, SHA-256 multihashes, key hashes |
| `proof.go` | `eddsa-jcs-2022` proofs |
| `log.go` | `CreateLog`, `UpdateLog`, `WitnessProof`, SCID and entry hashes |
| `verify.go` | per-entry checks and witness verification (`VerifyLog`) |
| `resolve.go` | version selection, partial validity, copies (`Resolve`) |
| `protocol.go` | mapping to/from the interop protocol's `resolve` JSON |
| `cmd/vh-log-driver` | the interop driver (JSON Lines on stdin/stdout) |

## Testing

```sh
go test ./...                 # unit, end-to-end and shared-vector tests (../../vectors)
go vet ./... && gofmt -l .
go build -o bin/vh-log-driver ./cmd/vh-log-driver
node ../../harness/run.ts --impl go    # from anywhere; or --impl typescript --impl go
```
