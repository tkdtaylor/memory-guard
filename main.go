// SPDX-License-Identifier: Apache-2.0

// Command memory-guard gates all agent memory I/O (ASI06): PII redaction + a write-gate
// that rejects suspected context-poisoning + post-deletion verification.
//
// Contract (interface-contracts.md §2):
//
//	validate_write(entry, identity) -> { allow, stored_id, flags }
//	validate_read(query, identity)  -> { allow, content_redacted, flags }
//	verify_delete(id)               -> { confirmed }
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
		fmt.Fprintf(os.Stderr, "memory-guard serving on %s\n", *socket)
		if err := serve(*socket, NewMemoryGuard(NewNativeDetector())); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "write":
		g := NewMemoryGuard(NewNativeDetector())
		printJSON(g.ValidateWrite(arg(2), nil))
	case "read":
		g := NewMemoryGuard(NewNativeDetector())
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
