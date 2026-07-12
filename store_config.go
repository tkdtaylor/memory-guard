// SPDX-License-Identifier: Apache-2.0
package main

import "fmt"

// store_config.go is the config-driven construction point for a MemoryStore backend, the
// storage analogue of detector_config.go (ADR-012). It mirrors that pattern exactly so the
// SELECTION site (main.go) names only a backend STRING plus this generic factory, never a
// store Go type — keeping the seam-isolation fitness gate (F-004) clean.

// store backend names — the config-driven selection keys (stable, generic strings, NOT Go
// types). Selected via MEMGUARD_STORE; the path comes from MEMGUARD_STORE_PATH.
const (
	StoreMemory = "memory" // default: the in-memory map (InMemoryStore); ephemeral
	StoreFile   = "file"   // file-backed persistent snapshot (FileStore, ADR-012)
)

// NewStoreFromConfig is the single construction point for a MemoryStore backend. It returns
// the store behind the unchanged seam, selected by a generic backend NAME. Selection is
// fail-closed: an unknown backend, or "file" without a path, is a construction ERROR (never
// a silent fallback that would hide a misconfiguration or persist to a default location the
// operator never chose). The error is generic — no FileStore internals beyond the name.
func NewStoreFromConfig(backend, path string) (MemoryStore, error) {
	switch backend {
	case "", StoreMemory:
		return NewInMemoryStore(), nil
	case StoreFile:
		if path == "" {
			return nil, fmt.Errorf("MEMGUARD_STORE_PATH is required when MEMGUARD_STORE=%s", StoreFile)
		}
		return NewFileStore(path)
	default:
		return nil, fmt.Errorf("unknown store backend %q (want one of: %s, %s)",
			backend, StoreMemory, StoreFile)
	}
}
