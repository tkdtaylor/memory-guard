// SPDX-License-Identifier: Apache-2.0

// Command memory-guard gates all agent memory I/O (ASI06): PII redaction + a write-gate
// that rejects suspected context-poisoning + post-deletion verification.
//
// Contract (docs/CONTRACT.md):
//
//	validate_write(entry, identity) -> { allow, stored_id, flags }
//	validate_read(query, identity)  -> { allow, content_redacted, flags }
//	verify_delete(id)               -> { confirmed, residue_detected, residue_summary?, deletion_hash }
//
// PII/injection detection sits behind the Detector seam (detector.go) so Presidio can be
// swapped in for v1 without changing this block.
//
// Usage:
//
//	memory-guard serve --socket /run/memguard.sock
//	memory-guard write "contact alice@example.com"
//	memory-guard read  "contact"
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

// detectorBackend returns the configured detection backend NAME, defaulting to the Go-native
// backend (ADR-002). Selection is via the MEMGUARD_DETECTOR env var ("regex" | "native" |
// "presidio"); the actual backend object is built by the generic NewDetectorFromConfig factory
// (detector_config.go) so this file names only a backend STRING — no backend Go type appears
// here, keeping the seam-isolation gate clean.
func detectorBackend() string {
	if b := os.Getenv("MEMGUARD_DETECTOR"); b != "" {
		return b
	}
	return BackendNative
}

// buildDetector constructs the configured backend behind the seam, exiting with a clear error
// on an unknown backend name (fail-closed — never a silent fallback that hides a typo).
func buildDetector() Detector {
	det, err := NewDetectorFromConfig(detectorBackend())
	if err != nil {
		fmt.Fprintln(os.Stderr, "detector:", err)
		os.Exit(2)
	}
	return det
}

// storeBackend returns the configured store backend NAME, defaulting to the ephemeral
// in-memory map (ADR-012). Selection is via MEMGUARD_STORE ("memory" | "file"); the actual
// store object is built by the generic NewStoreFromConfig factory (store_config.go) so this
// file names only a backend STRING — no store Go type appears here, keeping the seam gate clean.
func storeBackend() string {
	if b := os.Getenv("MEMGUARD_STORE"); b != "" {
		return b
	}
	return StoreMemory
}

// storePath returns the configured store path (MEMGUARD_STORE_PATH), required when the
// backend is "file". Empty for the in-memory default.
func storePath() string { return os.Getenv("MEMGUARD_STORE_PATH") }

// buildStore constructs the configured store behind the seam, exiting 2 on a config error
// (unknown backend, or file without a path — fail-closed, never a silent fallback).
func buildStore() MemoryStore {
	store, err := NewStoreFromConfig(storeBackend(), storePath())
	if err != nil {
		fmt.Fprintln(os.Stderr, "store:", err)
		os.Exit(2)
	}
	return store
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: memory-guard <serve|write|read> …")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ExitOnError)
		socket := fs.String("socket", "", "unix socket path (required)")
		fs.Parse(os.Args[2:])
		if *socket == "" {
			fmt.Fprintln(os.Stderr, "serve: --socket is required")
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "memory-guard serving on %s (detector: %s, store: %s)\n",
			*socket, detectorBackend(), storeBackend())
		if err := serve(*socket, NewMemoryGuard(buildDetector(), buildStore())); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "write":
		g := NewMemoryGuard(buildDetector(), buildStore())
		printJSON(g.ValidateWrite(arg(2), nil))
	case "read":
		g := NewMemoryGuard(buildDetector(), buildStore())
		g.ValidateWrite(arg(2), nil) // seed so the one-shot demo has something to read
		printJSON(g.ValidateRead(arg(2), nil))
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		os.Exit(2)
	}
}

func arg(i int) string {
	if len(os.Args) > i {
		return os.Args[i]
	}
	return ""
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}
