// Command vh-log-driver is the interop driver for the Go VH-Log library: it
// reads JSON Lines requests on stdin and writes one JSON response per line on
// stdout (docs/interop-protocol.md).
package main

import (
	"bufio"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"unicode/utf8"

	vhlog "github.com/brianorwhatever/vh/implementations/go"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	if err := run(os.Stdin, os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// run serves requests from r until EOF, writing and flushing one response
// line per request.
func run(r io.Reader, w io.Writer) error {
	in := bufio.NewReaderSize(r, 1<<20)
	out := bufio.NewWriter(w)
	for {
		// Split on "\n" only: U+2028/U+2029 and "\r" may appear inside JSON strings.
		line, err := in.ReadString('\n')
		if line = strings.TrimSuffix(line, "\n"); strings.TrimSpace(line) != "" {
			out.WriteString(handle(line))
			out.WriteByte('\n')
			if ferr := out.Flush(); ferr != nil {
				return fmt.Errorf("writing response: %w", ferr)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("reading request: %w", err)
		}
	}
}

// sanitize replaces invalid UTF-8 bytes with U+FFFD, as a UTF-8 text decoder would.
func sanitize(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		b.WriteRune(r)
		i += n
	}
	return b.String()
}

// handle processes one request line and returns the response line.
func handle(line string) (response string) {
	var id any
	defer func() {
		if r := recover(); r != nil {
			response = vhlog.Stringify(vhlog.ObjectOf("id", id, "ok", false, "error", fmt.Sprint(r)))
		}
	}()
	parsed, err := vhlog.ParseJSON(sanitize(line))
	if err != nil {
		return vhlog.Stringify(vhlog.ObjectOf("id", nil, "ok", false, "error", err.Error()))
	}
	req, ok := parsed.(*vhlog.Object)
	if !ok {
		return vhlog.Stringify(vhlog.ObjectOf("id", nil, "ok", false, "error", "request is not an object"))
	}
	id, _ = req.Get("id")
	opValue, _ := req.Get("op")
	opName, _ := opValue.(string)
	input := vhlog.NewObject()
	if v, _ := req.Get("input"); v != nil {
		if obj, ok := v.(*vhlog.Object); ok {
			input = obj
		}
	}
	op, ok := ops[opName]
	if !ok {
		return vhlog.Stringify(vhlog.ObjectOf("id", id, "ok", false, "error", "unknown op "+vhlog.Stringify(opValue)))
	}
	result, err := op(input)
	if err != nil {
		return vhlog.Stringify(vhlog.ObjectOf("id", id, "ok", false, "error", err.Error()))
	}
	return vhlog.Stringify(vhlog.ObjectOf("id", id, "ok", true, "result", result))
}

type opFunc func(input *vhlog.Object) (any, error)

var ops = map[string]opFunc{
	"jcs": func(in *vhlog.Object) (any, error) {
		text, err := str(in, "text")
		if err != nil {
			return nil, err
		}
		out, err := vhlog.CanonicalizeText(text)
		if err != nil {
			return nil, err
		}
		return vhlog.ObjectOf("output", out), nil
	},
	"hash": func(in *vhlog.Object) (any, error) {
		data, err := str(in, "data")
		if err != nil {
			return nil, err
		}
		return vhlog.ObjectOf("output", vhlog.HashString(data)), nil
	},
	"multikey": func(in *vhlog.Object) (any, error) {
		key, err := seed(in, "seed")
		if err != nil {
			return nil, err
		}
		return vhlog.ObjectOf("multikey", vhlog.Multikey(key)), nil
	},
	"key-hash": func(in *vhlog.Object) (any, error) {
		mk, err := str(in, "multikey")
		if err != nil {
			return nil, err
		}
		return vhlog.ObjectOf("output", vhlog.KeyHash(mk)), nil
	},
	"scid": func(in *vhlog.Object) (any, error) {
		entry, err := obj(in, "entry")
		if err != nil {
			return nil, err
		}
		scid, err := vhlog.ComputeSCID(entry)
		if err != nil {
			return nil, err
		}
		return vhlog.ObjectOf("scid", scid), nil
	},
	"entry-hash": func(in *vhlog.Object) (any, error) {
		entry, err := obj(in, "entry")
		if err != nil {
			return nil, err
		}
		prev, err := str(in, "previousVersionId")
		if err != nil {
			return nil, err
		}
		hash, err := vhlog.ComputeEntryHash(entry, prev)
		if err != nil {
			return nil, err
		}
		return vhlog.ObjectOf("hash", hash), nil
	},
	"sign": func(in *vhlog.Object) (any, error) {
		key, err := seed(in, "seed")
		if err != nil {
			return nil, err
		}
		document, _ := in.Get("document")
		opts := vhlog.ProofOptions{}
		opts.VerificationMethod, _ = optionalStr(in, "verificationMethod")
		opts.Created, _ = optionalStr(in, "created")
		proof, err := vhlog.CreateProof(document, key, opts)
		if err != nil {
			return nil, err
		}
		return vhlog.ObjectOf("proof", proof), nil
	},
	"verify": func(in *vhlog.Object) (any, error) {
		document, _ := in.Get("document")
		proof, _ := in.Get("proof")
		return vhlog.ObjectOf("valid", vhlog.VerifyProof(document, proof)), nil
	},
	"create": func(in *vhlog.Object) (any, error) {
		state, _ := in.Get("state")
		params, err := optionalObj(in, "parameters")
		if err != nil {
			return nil, err
		}
		versionTime, err := str(in, "versionTime")
		if err != nil {
			return nil, err
		}
		signers, err := seeds(in)
		if err != nil {
			return nil, err
		}
		created, err := vhlog.CreateLog(state, params, versionTime, signers)
		if err != nil {
			return nil, err
		}
		return vhlog.ObjectOf("log", created.Log, "scid", created.SCID, "versionId", created.VersionID), nil
	},
	"update": func(in *vhlog.Object) (any, error) {
		logText, err := str(in, "log")
		if err != nil {
			return nil, err
		}
		state, _ := in.Get("state")
		params, err := optionalObj(in, "parameters")
		if err != nil {
			return nil, err
		}
		versionTime, err := str(in, "versionTime")
		if err != nil {
			return nil, err
		}
		signers, err := seeds(in)
		if err != nil {
			return nil, err
		}
		updated, err := vhlog.UpdateLog(logText, state, params, versionTime, signers)
		if err != nil {
			return nil, err
		}
		return vhlog.ObjectOf("log", updated.Log, "versionId", updated.VersionID), nil
	},
	"witness": func(in *vhlog.Object) (any, error) {
		versionID, err := str(in, "versionId")
		if err != nil {
			return nil, err
		}
		key, err := seed(in, "seed")
		if err != nil {
			return nil, err
		}
		created, _ := optionalStr(in, "created")
		proof, err := vhlog.WitnessProof(versionID, key, created)
		if err != nil {
			return nil, err
		}
		return vhlog.ObjectOf("proof", proof), nil
	},
	"resolve": resolve,
}

func resolve(in *vhlog.Object) (any, error) { return vhlog.ResolveRequest(in) }

func str(o *vhlog.Object, key string) (string, error) {
	v, _ := o.Get(key)
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return s, nil
}

func optionalStr(o *vhlog.Object, key string) (string, bool) {
	v, _ := o.Get(key)
	s, ok := v.(string)
	return s, ok
}

func obj(o *vhlog.Object, key string) (*vhlog.Object, error) {
	v, _ := o.Get(key)
	x, ok := v.(*vhlog.Object)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", key)
	}
	return x, nil
}

func optionalObj(o *vhlog.Object, key string) (*vhlog.Object, error) {
	v, ok := o.Get(key)
	if !ok || v == nil {
		return nil, nil
	}
	x, isObject := v.(*vhlog.Object)
	if !isObject {
		return nil, fmt.Errorf("%s must be an object", key)
	}
	return x, nil
}

func seed(o *vhlog.Object, key string) (ed25519.PrivateKey, error) {
	s, err := str(o, key)
	if err != nil {
		return nil, err
	}
	return vhlog.KeyFromSeedHex(s)
}

func seeds(o *vhlog.Object) ([]ed25519.PrivateKey, error) {
	v, _ := o.Get("signers")
	list, ok := v.([]any)
	if !ok {
		return nil, errors.New("signers must be an array")
	}
	keys := make([]ed25519.PrivateKey, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, errors.New("signers must be hex seeds")
		}
		key, err := vhlog.KeyFromSeedHex(s)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}
