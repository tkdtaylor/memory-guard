// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
)

// serve runs the JSON-over-Unix-socket IPC form of the contract (interface-contracts §1).
func serve(socketPath string, guard *MemoryGuard) error {
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	_ = os.Chmod(socketPath, 0o600)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleConn(conn, guard)
	}
}

func handleConn(conn net.Conn, guard *MemoryGuard) {
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req map[string]any
	if err := json.Unmarshal(line, &req); err != nil {
		writeJSON(conn, errShape("bad_request", err.Error()))
		return
	}
	identity, _ := req["identity"].(map[string]any)
	switch req["op"] {
	case "validate_write":
		writeJSON(conn, guard.ValidateWrite(str(req["entry"]), identity))
	case "validate_read":
		writeJSON(conn, guard.ValidateRead(str(req["query"]), identity))
	case "verify_delete":
		writeJSON(conn, guard.VerifyDelete(str(req["id"])))
	case "ping":
		writeJSON(conn, map[string]any{"ok": true})
	default:
		writeJSON(conn, errShape("unknown_op", "unsupported op"))
	}
}

func writeJSON(conn net.Conn, v any) {
	b, _ := json.Marshal(v)
	conn.Write(append(b, '\n'))
}

func errShape(code, msg string) map[string]any {
	return map[string]any{"error": map[string]any{
		"code": code, "message": msg, "retryable": false}}
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
