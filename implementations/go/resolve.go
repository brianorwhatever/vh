package vhlog

import (
	"fmt"
	"math"
	"strconv"
	"time"
)

// PrimarySource is the source name of the primary copy of a log.
const PrimarySource = "primary"

// ResolveOptions selects a version and sets copy requirements. At most one of
// VersionID, VersionTime and VersionNumber may be set.
type ResolveOptions struct {
	VersionID     *string
	VersionTime   *string
	VersionNumber *int
	// MinCopies is the number of copies that must be current or behind
	// (default 1).
	MinCopies *int
}

// ParseResolveOptions converts a JSON options object (as in the interop
// protocol) to ResolveOptions. Unknown members and members of the wrong type
// fail with ErrInvalidOption. A nil value means no options.
func ParseResolveOptions(v any) (ResolveOptions, error) {
	var opts ResolveOptions
	if v == nil {
		return opts, nil
	}
	obj, ok := v.(*Object)
	if !ok {
		return opts, newError(ErrInvalidOption, 0, "options must be an object")
	}
	for _, k := range obj.keys {
		value := obj.values[k]
		switch k {
		case "versionId", "versionTime":
			s, ok := value.(string)
			if !ok {
				return opts, newError(ErrInvalidOption, 0, "%s must be a string", k)
			}
			if k == "versionId" {
				opts.VersionID = &s
			} else {
				opts.VersionTime = &s
			}
		case "versionNumber", "minCopies":
			f, ok := value.(float64)
			if !ok || !isInteger(f) || f < 1 {
				return opts, newError(ErrInvalidOption, 0, "%s must be a positive integer", k)
			}
			n := math.MaxInt
			if f < float64(math.MaxInt32) {
				n = int(f)
			}
			if k == "versionNumber" {
				opts.VersionNumber = &n
			} else {
				opts.MinCopies = &n
			}
		default:
			return opts, newError(ErrInvalidOption, 0, "unsupported option %s", k)
		}
	}
	return opts, nil
}

func (o ResolveOptions) validate() error {
	selectors := 0
	for _, set := range []bool{o.VersionID != nil, o.VersionTime != nil, o.VersionNumber != nil} {
		if set {
			selectors++
		}
	}
	if selectors > 1 {
		return newError(ErrInvalidOption, 0, "at most one version selector may be given")
	}
	if o.VersionTime != nil {
		if _, ok := ParseVersionTime(*o.VersionTime); !ok {
			return newError(ErrInvalidOption, 0, "versionTime must be a whole-second UTC ISO 8601 time")
		}
	}
	if o.VersionNumber != nil && *o.VersionNumber < 1 {
		return newError(ErrInvalidOption, 0, "versionNumber must be a positive integer")
	}
	if o.MinCopies != nil && *o.MinCopies < 1 {
		return newError(ErrInvalidOption, 0, "minCopies must be a positive integer")
	}
	return nil
}

func (o ResolveOptions) minCopies() int {
	if o.MinCopies == nil {
		return 1
	}
	return *o.MinCopies
}

// CopyInput is a copy of the log obtained from a watcher.
type CopyInput struct {
	// Source identifies the copy, e.g. the watcher URL.
	Source string
	// Log is the copy's log file. Ignored if Unavailable.
	Log string
	// Witness is the copy's raw witness file, or nil if there is none.
	Witness []byte
	// Unavailable marks a copy that could not be fetched; Reason says why.
	Unavailable bool
	Reason      string
}

// ResolveInput is the input to Resolve.
type ResolveInput struct {
	// Log is the primary copy of the log file.
	Log string
	// Witness is the raw primary witness file, or nil if none was found.
	Witness []byte
	// Now is the resolver's clock.
	Now time.Time
	// Options select a version and set copy requirements.
	Options ResolveOptions
	// Copies are watcher copies to compare. A non-nil (even empty) slice
	// enables copy comparison, as does MinCopies > 1.
	Copies []CopyInput
	// RetainedVersionID is a versionId the resolver retained from an earlier
	// resolution; if set, the log must agree with it.
	RetainedVersionID *string
}

// CopyStatus is the outcome of comparing one copy of a log.
type CopyStatus string

// Copy statuses.
const (
	CopyCurrent     CopyStatus = "current"
	CopyBehind      CopyStatus = "behind"
	CopyInvalid     CopyStatus = "invalid"
	CopyUnavailable CopyStatus = "unavailable"
)

// CopyReport describes one copy in the resolution metadata.
type CopyReport struct {
	Source    string     `json:"source"`
	VersionID string     `json:"versionId,omitempty"`
	Status    CopyStatus `json:"status"`
}

// Warning is a non-fatal resolution finding.
type Warning struct {
	Code    string `json:"code"`
	Source  string `json:"source,omitempty"`
	Message string `json:"message"`
}

// Warning codes.
const (
	WarningInvalidEntries          = "invalid-entries"
	WarningCopyUnavailable         = "copy-unavailable"
	WarningCopyInvalid             = "copy-invalid"
	WarningCopyBehind              = "copy-behind"
	WarningRetainedVersionNotFound = "retained-version-not-found"
)

// Metadata is the resolution metadata.
type Metadata struct {
	VersionID     string `json:"versionId"`
	VersionTime   string `json:"versionTime"`
	VersionNumber int    `json:"versionNumber"`
	// Created is the first entry's versionTime.
	Created string `json:"created"`
	// Updated is the last valid entry's versionTime.
	Updated     string `json:"updated"`
	SCID        string `json:"scid"`
	Deactivated bool   `json:"deactivated"`
	TTL         int64  `json:"ttl"`
	// Witness is the witness configuration active at the last valid entry,
	// or nil if none.
	Witness  *WitnessConfig `json:"witness"`
	Watchers []string       `json:"watchers"`
	// UpdateKeys and NextKeyHashes are those active at the resolved entry.
	UpdateKeys    []string     `json:"updateKeys"`
	NextKeyHashes []string     `json:"nextKeyHashes"`
	Copies        []CopyReport `json:"copies,omitempty"`
	Warnings      []Warning    `json:"warnings"`
}

// Resolution is a successful resolution.
type Resolution struct {
	// State is the resolved entry's state.
	State    any      `json:"state"`
	Metadata Metadata `json:"metadata"`
	// FirstInvalidVersion is the version number of the first entry that
	// failed verification (or witnessing), or nil if the log is fully valid.
	FirstInvalidVersion *int `json:"firstInvalidVersion"`
	// Error is the failure that invalidated FirstInvalidVersion.
	Error *VHLogError `json:"error"`
}

// lineVersionID returns the versionId of a raw log line, or false.
func lineVersionID(lines []string, index int) (string, bool) {
	if index < 0 || index >= len(lines) {
		return "", false
	}
	v, err := ParseJSON(lines[index])
	if err != nil {
		return "", false
	}
	obj, ok := v.(*Object)
	if !ok {
		return "", false
	}
	id, _ := obj.Get("versionId")
	s, ok := id.(string)
	return s, ok
}

// selectEntry picks the target entry (Selecting a Version). A target at or
// after the first invalid entry fails with that entry's error (profile §4).
func selectEntry(v *VerifiedLog, o ResolveOptions) (*VerifiedEntry, error) {
	invalid := func() error {
		return &VHLogError{Code: v.Failure.Code, Version: v.Failure.Version,
			Message: "requested version is invalid: " + v.Failure.Message}
	}
	entries := v.Entries
	switch {
	case o.VersionID != nil:
		for _, e := range entries {
			if e.VersionID == *o.VersionID {
				return e, nil
			}
		}
		for i := len(entries); i < len(v.Lines); i++ {
			if id, ok := lineVersionID(v.Lines, i); ok && id == *o.VersionID {
				return nil, invalid()
			}
		}
		return nil, newError(ErrNotFound, 0, "no entry with versionId %s", *o.VersionID)
	case o.VersionNumber != nil:
		n := *o.VersionNumber
		if n <= len(entries) {
			return entries[n-1], nil
		}
		if n <= len(v.Lines) {
			return nil, invalid()
		}
		return nil, newError(ErrNotFound, 0, "no entry with version number %d", n)
	case o.VersionTime != nil:
		t, _ := ParseVersionTime(*o.VersionTime)
		if v.Failure != nil && len(entries) < len(v.Lines) {
			if raw, err := ParseJSON(v.Lines[len(entries)]); err == nil {
				if obj, ok := raw.(*Object); ok {
					vt, _ := obj.Get("versionTime")
					if s, ok := vt.(string); ok {
						if ft, ok := ParseVersionTime(s); ok && !ft.After(t) {
							return nil, invalid()
						}
					}
				}
			}
		}
		for i := len(entries) - 1; i >= 0; i-- {
			if !entries[i].Time.After(t) {
				return entries[i], nil
			}
		}
		return nil, newError(ErrNotFound, 0, "no entry active at %s", *o.VersionTime)
	}
	return entries[len(entries)-1], nil
}

func buildResolution(v *VerifiedLog, o ResolveOptions, warnings []Warning, copies []CopyReport) (*Resolution, error) {
	target, err := selectEntry(v, o)
	if err != nil {
		return nil, err
	}
	first, last := v.Entries[0], v.Entries[len(v.Entries)-1]
	if v.Failure != nil {
		warnings = append(warnings, Warning{
			Code:    WarningInvalidEntries,
			Message: fmt.Sprintf("entries from version %d fail verification: %s", v.Failure.Version, v.Failure.Message),
		})
	}
	if warnings == nil {
		warnings = []Warning{}
	}
	r := &Resolution{
		State: target.State(),
		Metadata: Metadata{
			VersionID:     target.VersionID,
			VersionTime:   target.VersionTime,
			VersionNumber: target.VersionNumber,
			Created:       first.VersionTime,
			Updated:       last.VersionTime,
			SCID:          first.Parameters.SCID,
			Deactivated:   last.Parameters.Deactivated,
			TTL:           last.Parameters.TTL,
			Witness:       last.Parameters.Witness,
			Watchers:      last.Parameters.Watchers,
			UpdateKeys:    target.Parameters.UpdateKeys,
			NextKeyHashes: target.Parameters.NextKeyHashes,
			Copies:        copies,
			Warnings:      warnings,
		},
		Error: v.Failure,
	}
	if v.Failure != nil {
		n := len(v.Entries) + 1
		r.FirstInvalidVersion = &n
	}
	return r, nil
}

func checkRetained(reference *VerifiedLog, source, retained string, warnings *[]Warning) error {
	n := 0
	i := 0
	for i < len(retained) && isDigit(retained[i]) {
		i++
	}
	if i == 0 || retained[0] == '0' || i >= len(retained) || retained[i] != '-' {
		return newError(ErrInvalidOption, 0, "retainedVersionId is not a versionId")
	}
	n, err := strconv.Atoi(retained[:i])
	if err != nil {
		n = math.MaxInt
	}
	if len(reference.Entries) < n {
		*warnings = append(*warnings, Warning{
			Code:    WarningRetainedVersionNotFound,
			Message: fmt.Sprintf("the log has %d valid entries, fewer than retained version %d", len(reference.Entries), n),
		})
		return nil
	}
	versionID := reference.Entries[n-1].VersionID
	if versionID != retained {
		return &VHLogError{
			Code: ErrForkDetected, Version: n,
			Message: fmt.Sprintf("retained versionId differs at version %d", n),
			Fork: &ForkReport{Version: n, Copies: []ForkCopy{
				{Source: "retained", VersionID: retained},
				{Source: source, VersionID: versionID},
			}},
		}
	}
	return nil
}

// divergence returns the first version number at which two logs' versionIds differ.
func divergence(a, b []string) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		x, okx := lineVersionID(a, i)
		y, oky := lineVersionID(b, i)
		if okx != oky || x != y {
			return i + 1
		}
	}
	return n + 1
}

// resolveCopies implements Comparing Copies of a Log, with the copies
// supplied by the caller instead of fetched.
func resolveCopies(in ResolveInput) (*Resolution, error) {
	all := append([]CopyInput{{Source: PrimarySource, Log: in.Log, Witness: in.Witness}}, in.Copies...)
	var warnings []Warning
	status := map[int]CopyStatus{}
	verified := map[int]*VerifiedLog{}
	verify := func(i int) *VerifiedLog {
		if v, ok := verified[i]; ok {
			return v
		}
		v := VerifyLog(all[i].Log, all[i].Witness, in.Now)
		verified[i] = v
		return v
	}
	markInvalid := func(i int) {
		status[i] = CopyInvalid
		f := verify(i).Failure
		msg := "copy fails verification at version ?: "
		if f != nil {
			version := "?"
			if f.Version > 0 {
				version = strconv.Itoa(f.Version)
			}
			msg = fmt.Sprintf("copy fails verification at version %s: %s", version, f.Message)
		}
		warnings = append(warnings, Warning{Code: WarningCopyInvalid, Source: all[i].Source, Message: msg})
	}

	for i, c := range all {
		if c.Unavailable {
			status[i] = CopyUnavailable
			warnings = append(warnings, Warning{Code: WarningCopyUnavailable, Source: c.Source, Message: c.Reason})
		}
	}

	ref := -1
	for i := range all {
		if _, done := status[i]; done {
			continue
		}
		if verify(i).FullyValid() {
			ref = i
			break
		}
		markInvalid(i)
	}
	if ref == -1 {
		if f := verify(0).Failure; f != nil {
			return nil, f
		}
		return nil, newError(ErrInvalidLog, 0, "no copy verifies")
	}

	matched := map[int]bool{ref: true}
	for i := range all {
		if _, done := status[i]; done || matched[i] {
			continue
		}
		reference := verify(ref)
		refLines, copyLines := reference.Lines, verify(i).Lines
		if len(copyLines) == 0 {
			markInvalid(i)
			continue
		}
		same, extends := false, false
		if len(copyLines) <= len(refLines) {
			id, ok := lineVersionID(copyLines, len(copyLines)-1)
			same = ok && id == reference.Entries[len(copyLines)-1].VersionID
		} else {
			id, ok := lineVersionID(copyLines, len(refLines)-1)
			extends = ok && id == reference.Entries[len(reference.Entries)-1].VersionID
		}
		switch {
		case same:
			matched[i] = true
		case extends:
			if verify(i).FullyValid() {
				matched[i] = true
				ref = i
			} else {
				markInvalid(i)
			}
		case !verify(i).FullyValid():
			markInvalid(i)
		default:
			version := divergence(refLines, copyLines)
			refID, _ := lineVersionID(refLines, version-1)
			copyID, _ := lineVersionID(copyLines, version-1)
			return nil, &VHLogError{
				Code: ErrForkDetected, Version: version,
				Message: fmt.Sprintf("copies diverge at version %d", version),
				Fork: &ForkReport{Version: version, Copies: []ForkCopy{
					{Source: all[ref].Source, VersionID: refID},
					{Source: all[i].Source, VersionID: copyID},
				}},
			}
		}
	}

	reference := verify(ref)
	if in.RetainedVersionID != nil {
		if err := checkRetained(reference, all[ref].Source, *in.RetainedVersionID, &warnings); err != nil {
			return nil, err
		}
	}
	copies := make([]CopyReport, len(all))
	usable := 0
	for i, c := range all {
		if s, ok := status[i]; ok {
			copies[i] = CopyReport{Source: c.Source, Status: s}
			if s == CopyInvalid {
				lines := verify(i).Lines
				copies[i].VersionID, _ = lineVersionID(lines, len(lines)-1)
			}
			continue
		}
		lines := verify(i).Lines
		id, _ := lineVersionID(lines, len(lines)-1)
		copies[i] = CopyReport{Source: c.Source, VersionID: id, Status: CopyCurrent}
		if behind := len(reference.Lines) - len(lines); behind > 0 {
			copies[i].Status = CopyBehind
			warnings = append(warnings, Warning{Code: WarningCopyBehind, Source: c.Source,
				Message: fmt.Sprintf("copy is %d entries behind", behind)})
		}
		usable++
	}
	if usable < in.Options.minCopies() {
		return nil, newError(ErrMinCopiesNotMet, 0, "%d matching copies, %d required", usable, in.Options.minCopies())
	}
	return buildResolution(reference, in.Options, warnings, copies)
}

// Resolve verifies a log and resolves a version of it (the spec's Read
// operation, with profile §4's partial validity, deactivation and copy
// rules). A log that cannot be resolved returns a *VHLogError; a log whose
// later entries are invalid resolves with Resolution.FirstInvalidVersion and
// Resolution.Error set.
func Resolve(in ResolveInput) (*Resolution, error) {
	if err := in.Options.validate(); err != nil {
		return nil, err
	}
	if in.Copies != nil || in.Options.minCopies() > 1 {
		return resolveCopies(in)
	}
	verified := VerifyLog(in.Log, in.Witness, in.Now)
	if len(verified.Entries) == 0 {
		return nil, verified.Failure
	}
	var warnings []Warning
	if in.RetainedVersionID != nil {
		if err := checkRetained(verified, PrimarySource, *in.RetainedVersionID, &warnings); err != nil {
			return nil, err
		}
	}
	return buildResolution(verified, in.Options, warnings, nil)
}
