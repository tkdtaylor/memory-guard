// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// store_file.go is the first PERSISTENT MemoryStore adapter (ADR-012), behind the
// unchanged store.go seam. Where InMemoryStore and TwoIndexStore die with the process,
// FileStore keeps entries in a single JSONL snapshot file on disk, so verify_delete's
// absence proof and the residue scan run against ACTUAL persistence: "the entry is gone"
// becomes "the bytes are gone from disk-backed state", not "the key is gone from a map".
//
// Layout: one JSON object per line ({id, content, bound_identity, source_class?, flags}). Every mutation
// (Put/Delete) rewrites the WHOLE snapshot crash-safely (temp file + fsync + atomic
// os.Rename over the canonical path, mode 0600), so a delete PHYSICALLY removes the
// deleted entry's bytes from the canonical path — an append-only log would leave them as
// pre-tombstone history and make the byte-level delete proof false by construction. Every
// verb reads THROUGH to disk (no in-memory cache), so a second handle or a restarted
// process always sees persisted truth. See ADR-012 for the rejected append-only /
// per-entry-file / vector-dependency layouts and the default-stays-memory decision.
//
// No backend specifics cross the seam: only string / entry / []entry shaped values pass
// through, exactly like the other two adapters. The wire-record type (fileRecord) and the
// FileStore type live ONLY in this file.

// fileRecord is the on-disk wire form of an entry (one per JSONL line). It is internal to
// this file and never crosses the MemoryStore seam. bound_identity carries the ADR-004
// isolation key ("" for an unbound/unattested writer); flags carries the guard-computed
// flag labels; source_class carries the write provenance (ADR-015, optional/omitempty). All
// four entry fields round-trip faithfully (task 016 depends on bound_identity persisting).
type fileRecord struct {
	ID            string `json:"id"`
	Content       string `json:"content"`
	BoundIdentity string `json:"bound_identity"`
	// SourceClass is the write's provenance tag (ADR-015). Optional on the wire: a record
	// written before this field existed has no source_class key, which unmarshals to "" and
	// is treated as sourceClassUnknown by consumers (no backfill migration). omitempty keeps
	// pre-existing snapshots byte-identical when the field is empty.
	SourceClass string   `json:"source_class,omitempty"`
	Flags       []string `json:"flags"`
}

func (r fileRecord) toEntry() entry {
	return entry{content: r.Content, boundIdentity: r.BoundIdentity, sourceClass: r.SourceClass, flags: r.Flags}
}

func recordFrom(id string, e entry) fileRecord {
	return fileRecord{ID: id, Content: e.content, BoundIdentity: e.boundIdentity, SourceClass: e.sourceClass, Flags: e.flags}
}

// FileStore is the file-backed MemoryStore adapter. It holds ONLY the canonical path; all
// state lives in the file on disk (read-through-disk, no cache). Concurrent access is
// serialized by the guard's own mutex (same model as the other adapters); FileStore adds
// no internal locking.
type FileStore struct {
	path string
}

// NewFileStore constructs a FileStore over path, validating any EXISTING file up front: a
// corrupt or field-incomplete file is a construction ERROR (fail-closed — never silently
// an empty store, which would orphan real data), and the file is left untouched. A missing
// or empty file is a valid empty store (the first construction on a fresh path).
func NewFileStore(path string) (*FileStore, error) {
	if _, err := parseStoreFile(path); err != nil {
		return nil, err
	}
	return &FileStore{path: path}, nil
}

// parseStoreFile reads and parses the JSONL snapshot at path. A missing file yields an
// empty (nil) record set with no error and NO side effect (a pure read never creates the
// file). An unparseable line, or a record missing the required id field, is an error
// naming the path and the failing line. This is the single parse path shared by the
// constructor (which surfaces the error) and load (which panics on it post-construction).
func parseStoreFile(path string) ([]fileRecord, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // missing file = valid empty store
	}
	if err != nil {
		return nil, fmt.Errorf("open store file %q: %w", path, err)
	}
	defer f.Close()

	var records []fileRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // tolerate long redacted lines
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue // tolerate blank lines / a trailing newline after the last record
		}
		var r fileRecord
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("parse store file %q line %d: %w", path, lineNum, err)
		}
		if r.ID == "" {
			return nil, fmt.Errorf("store file %q line %d: record missing required field \"id\"", path, lineNum)
		}
		records = append(records, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read store file %q: %w", path, err)
	}
	return records, nil
}

// load parses the current file. A post-construction I/O or parse failure panics with
// context (fail fast, crash loudly — the guard cannot serve safely off a broken store).
func (s *FileStore) load() []fileRecord {
	records, err := parseStoreFile(s.path)
	if err != nil {
		panic(fmt.Sprintf("FileStore: reading %q failed after construction: %v", s.path, err))
	}
	return records
}

// save writes records as a full JSONL snapshot crash-safely: marshal to <path>.tmp in the
// SAME directory (so the rename cannot cross filesystems), fsync, then atomically
// os.Rename over the canonical path at mode 0600. The canonical path never holds a
// partially-written snapshot; a stale <path>.tmp is overwritten (O_TRUNC) and consumed by
// the rename, so it never lingers. Any I/O failure panics with context.
func (s *FileStore) save(records []fileRecord) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf) // Encode writes one object + '\n' per record
	for _, r := range records {
		if err := enc.Encode(r); err != nil {
			panic(fmt.Sprintf("FileStore: marshalling record %q failed: %v", r.ID, err))
		}
	}

	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		panic(fmt.Sprintf("FileStore: opening temp file %q failed: %v", tmp, err))
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		_ = f.Close()
		panic(fmt.Sprintf("FileStore: writing temp file %q failed: %v", tmp, err))
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		panic(fmt.Sprintf("FileStore: fsync of temp file %q failed: %v", tmp, err))
	}
	if err := f.Close(); err != nil {
		panic(fmt.Sprintf("FileStore: closing temp file %q failed: %v", tmp, err))
	}
	if err := os.Rename(tmp, s.path); err != nil {
		panic(fmt.Sprintf("FileStore: atomic rename %q -> %q failed: %v", tmp, s.path, err))
	}
	// Rename preserves the temp file's mode, but umask may have masked the O_CREATE mode;
	// force 0600 so the snapshot's mode is exact (TC-003 edge).
	if err := os.Chmod(s.path, 0o600); err != nil {
		panic(fmt.Sprintf("FileStore: chmod %q failed: %v", s.path, err))
	}
}

// Put stores (or overwrites) the entry under id, then rewrites the snapshot atomically.
func (s *FileStore) Put(id string, e entry) {
	records := s.load()
	replaced := false
	for i := range records {
		if records[i].ID == id {
			records[i] = recordFrom(id, e)
			replaced = true
			break
		}
	}
	if !replaced {
		records = append(records, recordFrom(id, e))
	}
	s.save(records)
}

// Get returns the entry under id and whether it was present, read through to disk. An
// unknown id (or a never-written store) returns (zero entry, false) with no file created.
func (s *FileStore) Get(id string) (entry, bool) {
	for _, r := range s.load() {
		if r.ID == id {
			return r.toEntry(), true
		}
	}
	return entry{}, false
}

// Delete removes id from the snapshot and rewrites it. Deleting an absent id is an
// idempotent no-op that does NOT rewrite (a pure delete of an unknown id creates no file).
func (s *FileStore) Delete(id string) {
	records := s.load()
	kept := make([]fileRecord, 0, len(records))
	found := false
	for _, r := range records {
		if r.ID == id {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if !found {
		return
	}
	s.save(kept)
}

// Scan returns every entry whose content contains query (substring), read through to disk.
func (s *FileStore) Scan(query string) []entry {
	var hits []entry
	for _, r := range s.load() {
		if substringContains(r.Content, query) {
			hits = append(hits, r.toEntry())
		}
	}
	return hits
}

// ScanScoped returns entries whose content contains query AND whose bound_identity is an
// exact member of visibleKeys (ADR-013), read through to disk. Empty visibleKeys yields no
// entries. This is what makes identity isolation a property of the PERSISTED data: an
// independently constructed FileStore over the same path enforces the same visible-key set.
func (s *FileStore) ScanScoped(query string, visibleKeys []string) []entry {
	var hits []entry
	for _, r := range s.load() {
		if substringContains(r.Content, query) && keyIn(r.BoundIdentity, visibleKeys) {
			hits = append(hits, r.toEntry())
		}
	}
	return hits
}

// All returns every surviving entry as a non-nil (possibly empty) slice, read through disk.
func (s *FileStore) All() []entry {
	records := s.load()
	out := make([]entry, 0, len(records))
	for _, r := range records {
		out = append(out, r.toEntry())
	}
	return out
}

// AllByIndex exposes the single on-disk snapshot as one named index ("primary"). With
// exactly one index, the multi-index residue scan reduces to the task-003 single-map scan.
func (s *FileStore) AllByIndex() map[string][]entry {
	return map[string][]entry{primaryIndexName: s.All()}
}
