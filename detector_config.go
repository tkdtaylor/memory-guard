// SPDX-License-Identifier: Apache-2.0
package main

import "fmt"

// detector backend names — the config-driven selection keys. These are stable, generic
// strings (NOT Go types), so the SELECTION site (main.go) names only a backend string and
// the generic factory below — never a Presidio/ONNX Go type. That keeps the seam-isolation
// fitness gate (F-004) clean: guard.go / ipc.go / main.go / CONTRACT.md carry no backend type.
const (
	BackendRegex    = "regex"    // v0 RegexDetector
	BackendNative   = "native"   // v1 Go-native NativeDetector (ADR-002 default)
	BackendPresidio = "presidio" // v1 Presidio-backed sidecar (ADR-009)
)

// NewDetectorFromConfig is the single config-driven construction point for a Detector
// backend (REQ-006). It returns the Detector behind the unchanged seam, selected by a generic
// backend NAME — so the caller (main.go) stays backend-agnostic and no backend Go type leaks
// into the seam-protected files. An unknown name is a fail-closed construction error (not a
// silent fallback that would hide a misconfiguration); the error is generic, never
// Presidio-typed.
//
// The Presidio backend is constructed but NOT eagerly started here (the sidecar spawns lazily
// on first use); callers that want the model-load cold-start paid up front type-assert and
// call Start — but that is an optimization, not a seam concern, and lives outside this file's
// generic surface only where a backend type is already legitimately in scope (tests / a
// dedicated serve path), never in the generic guard/IPC plumbing.
func NewDetectorFromConfig(backend string) (Detector, error) {
	switch backend {
	case "", BackendNative:
		return NewNativeDetector(), nil
	case BackendRegex:
		return NewRegexDetector(), nil
	case BackendPresidio:
		return NewPresidioDetector(presidioConfig{}), nil
	default:
		return nil, fmt.Errorf("unknown detector backend %q (want one of: %s, %s, %s)",
			backend, BackendRegex, BackendNative, BackendPresidio)
	}
}
