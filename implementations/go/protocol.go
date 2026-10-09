package vhlog

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ParseResolveRequest converts the input of an interop-protocol "resolve"
// request (docs/interop-protocol.md) to a ResolveInput. An unusable option or
// clock is reported as a *VHLogError with ErrInvalidOption, which callers
// should report as a failed resolution; any other error means the request
// itself is malformed.
func ParseResolveRequest(in *Object) (ResolveInput, error) {
	var input ResolveInput
	logValue, _ := in.Get("log")
	logText, ok := logValue.(string)
	if !ok {
		return input, errors.New("log must be a string")
	}
	input.Log = logText
	input.Witness = rawMember(in, "witness")
	nowValue, _ := in.Get("now")
	nowText, _ := nowValue.(string)
	now, ok := ParseVersionTime(nowText)
	if !ok {
		return input, newError(ErrInvalidOption, 0, "now must be a whole-second UTC ISO 8601 time")
	}
	input.Now = now
	optionsValue, _ := in.Get("options")
	options, err := ParseResolveOptions(optionsValue)
	if err != nil {
		return input, err
	}
	input.Options = options
	if v, ok := in.Get("copies"); ok {
		input.Copies = []CopyInput{}
		list, _ := v.([]any)
		for _, item := range list {
			c, ok := item.(*Object)
			if !ok {
				return input, errors.New("copies must be objects")
			}
			source, _ := c.Get("source")
			copyInput := CopyInput{}
			copyInput.Source, _ = source.(string)
			if reason, ok := c.Get("unavailable"); ok {
				copyInput.Unavailable = true
				copyInput.Reason, _ = reason.(string)
			} else {
				log, _ := c.Get("log")
				if copyInput.Log, ok = log.(string); !ok {
					return input, fmt.Errorf("copy %q: log must be a string", copyInput.Source)
				}
				copyInput.Witness = rawMember(c, "witness")
			}
			input.Copies = append(input.Copies, copyInput)
		}
	}
	if v, ok := in.Get("retainedVersionId"); ok {
		s, _ := v.(string) // a non-string is not a versionId and fails with invalid-option
		input.RetainedVersionID = &s
	}
	return input, nil
}

// rawMember returns member key re-serialised as JSON text, or nil if absent.
func rawMember(o *Object, key string) []byte {
	v, ok := o.Get(key)
	if !ok {
		return nil
	}
	return []byte(Stringify(v))
}

// ResolveResultJSON converts the outcome of Resolve to the protocol's result
// object: {"valid": true, "state", "metadata", "firstInvalidVersion",
// "error"} or {"valid": false, "error"}. err must be nil or a *VHLogError.
func ResolveResultJSON(res *Resolution, err error) (*Object, error) {
	if err != nil {
		var vErr *VHLogError
		if !errors.As(err, &vErr) {
			return nil, err
		}
		report, _ := ParseJSON(Stringify(vErr))
		return ObjectOf("valid", false, "error", report), nil
	}
	data, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	v, err := ParseJSON(string(data))
	if err != nil {
		return nil, err
	}
	out := ObjectOf("valid", true)
	obj := v.(*Object)
	for _, k := range obj.keys {
		out.Set(k, obj.values[k])
	}
	return out, nil
}

// ResolveRequest runs an interop-protocol "resolve" request and returns its
// result object. A non-nil error means the request was malformed.
func ResolveRequest(in *Object) (*Object, error) {
	input, err := ParseResolveRequest(in)
	if err != nil {
		return ResolveResultJSON(nil, err)
	}
	return ResolveResultJSON(Resolve(input))
}
