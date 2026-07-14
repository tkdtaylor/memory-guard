// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"path"
	"strings"
)

// keys_config.go is the config-driven construction point for a KeyPolicy, the key-policy analogue
// of store_config.go (ADR-012) and detector_config.go. It mirrors that fail-closed pattern exactly:
// the SELECTION site (main.go) names only the two env-var STRINGS plus this generic factory, and a
// malformed pattern is a CONSTRUCTION ERROR, never a silently-dropped pattern that would leave a
// protected/immutable slot unguarded without the operator knowing.

// NewKeyPolicyFromConfig parses two comma-separated glob-pattern lists (path.Match syntax) into a
// KeyPolicy. protectedCSV sources KeyPolicy.Protected (from MEMGUARD_PROTECTED_KEYS); immutableCSV
// sources KeyPolicy.Immutable (from MEMGUARD_IMMUTABLE_KEYS). Whitespace around each entry is
// trimmed and empty entries are dropped (so "config:*," yields one pattern, not a stray
// match-everything entry). An empty/absent value on either knob yields an empty pattern list for
// that knob, leaving only the always-on reserved "memguard:" namespace active downstream.
//
// Fail-closed construction (mirroring NewStoreFromConfig): a malformed pattern is validated via
// path.Match and returned as a CONSTRUCTION ERROR wrapping path.ErrBadPattern (matchable with
// errors.Is), never silently dropped. On error the returned KeyPolicy is the zero value and must
// not be used by a caller that checks the error first.
func NewKeyPolicyFromConfig(protectedCSV, immutableCSV string) (KeyPolicy, error) {
	protected, err := parsePatternList("MEMGUARD_PROTECTED_KEYS", protectedCSV)
	if err != nil {
		return KeyPolicy{}, err
	}
	immutable, err := parsePatternList("MEMGUARD_IMMUTABLE_KEYS", immutableCSV)
	if err != nil {
		return KeyPolicy{}, err
	}
	return KeyPolicy{Protected: protected, Immutable: immutable}, nil
}

// parsePatternList splits a comma-separated pattern list, trims whitespace, drops empty entries,
// and validates each remaining pattern with path.Match. A malformed pattern is a construction error
// naming the offending knob and pattern and wrapping path.ErrBadPattern. An empty input yields a nil
// slice (no patterns). knob is the env-var name, included in the error for operator diagnostics.
func parsePatternList(knob, csv string) ([]string, error) {
	var out []string
	for _, raw := range strings.Split(csv, ",") {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue // drop empty / trailing entries; an empty pattern is never a wildcard here
		}
		// path.Match reports a malformed pattern via ErrBadPattern; validate against an empty
		// candidate purely to surface the syntax error at construction (the match result is unused).
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("%s: malformed key pattern %q: %w", knob, p, err)
		}
		out = append(out, p)
	}
	return out, nil
}
