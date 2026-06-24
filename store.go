// SPDX-License-Identifier: Apache-2.0
package main

// store.go is the MemoryStore seam — the storage analogue of the Detector seam
// (detector.go). The guard talks to whatever backs agent memory ONLY through these
// stable verbs; no backend-specific type (a vector-client handle, a SQL connection,
// a file path) ever crosses this boundary into guard.go, ipc.go, or the contract.
// Only string / entry / []entry shaped values pass through, so swapping the default
// in-memory map for a richer multi-index backing is a one-line construction change
// (NewMemoryGuard(det, store)) with zero guard/IPC/contract impact — the same
// property (ADR-002) that made the Detector backend choice cheap to revisit.
//
// Why a seam now (roadmap T1): a real memory store keeps entries in MORE THAN ONE
// backing index/copy. Post-deletion residue verification (ADR-003 / task 008) is
// "prove the entry is absent from EVERY index/copy" — meaningless against a single
// flat map. The seam, proven by a second adapter with a genuinely different backing
// (TwoIndexStore — a primary id→entry map PLUS a secondary content-keyed index),
// is what makes "every index/copy" a concrete, testable claim. See ADR-005.

// MemoryStore is the pluggable backing store for agent memory. The guard's three
// verbs map onto it directly: ValidateWrite -> Put, ValidateRead -> Scan, and
// VerifyDelete -> Delete + All (the survivors the residue scan iterates) and Get
// (the post-delete absence proof). All implementations must be safe for concurrent
// use by the guard, which serializes calls under its own mutex; a backing that has
// its own internal indexes keeps them consistent across these verbs.
type MemoryStore interface {
	// Put stores (or overwrites) the entry under id. The guard only ever Puts the
	// REDACTED content (PII never reaches the store raw) and only AFTER the
	// write-gate has cleared the write (a poisoned write calls no Put at all).
	Put(id string, e entry)
	// Get returns the entry under id and whether it was present. An unknown id
	// returns (zero entry, false). This is the absence proof verify_delete reads
	// AFTER deleting — not the Delete return value.
	Get(id string) (entry, bool)
	// Delete removes id from the store and every secondary index/copy of it.
	// Deleting an absent id is a no-op (idempotent).
	Delete(id string)
	// Scan returns every entry whose content contains query (substring match), in
	// any order. Callers compare on content membership, not slice order.
	Scan(query string) []entry
	// All returns every surviving entry, in any order, as a non-nil (possibly
	// empty) slice so the residue scan iterates cleanly over an empty store.
	All() []entry
	// AllByIndex returns the surviving entries grouped by the name of the backing
	// index/copy they live in: a map from an index name (a plain string label the
	// store chooses — backend-agnostic, no backend type) to that index's entries.
	// This is the seam the residue scan (task 008 / ADR-006) uses to prove "no
	// residue survives in ANY backing index/copy", and to NAME which index a residue
	// survives in. A single-index store returns exactly one entry in this map (keyed
	// "primary"), so the multi-index scan reduces exactly to the task-003 single-map
	// scan (REQ-005). Every []entry value is non-nil (possibly empty). The union of
	// the values equals All() for stores whose secondary indexes hold no copy beyond
	// the primary; a store whose secondary index can retain a copy the primary does
	// not (the multi-index residue case) surfaces that copy here, where All() — keyed
	// off the primary — would miss it.
	AllByIndex() map[string][]entry
}

// primaryIndexName is the canonical label for a store's authoritative id->entry
// index. A single-index store exposes only this index through AllByIndex, so the
// residue scan over it reduces exactly to the task-003 single-map scan.
const primaryIndexName = "primary"

// --- InMemoryStore: the default adapter (the extracted v0 map) --------------------

// InMemoryStore is the default MemoryStore: the single in-memory map that backed the
// guard in v0, extracted unchanged in behavior behind the seam. NewMemoryGuard
// constructs it when no store is supplied, so the CLI / serve defaults are identical
// to v0. It is a named map type (not a struct wrapping a map) so the guard can hold a
// MemoryStore while the v0 residue tests still index the concrete map directly.
type InMemoryStore map[string]entry

// NewInMemoryStore returns an empty default store.
func NewInMemoryStore() InMemoryStore { return InMemoryStore{} }

func (s InMemoryStore) Put(id string, e entry) { s[id] = e }

func (s InMemoryStore) Get(id string) (entry, bool) {
	e, ok := s[id]
	return e, ok
}

func (s InMemoryStore) Delete(id string) { delete(s, id) }

func (s InMemoryStore) Scan(query string) []entry {
	var hits []entry
	for _, e := range s {
		if substringContains(e.content, query) {
			hits = append(hits, e)
		}
	}
	return hits
}

func (s InMemoryStore) All() []entry {
	out := make([]entry, 0, len(s))
	for _, e := range s {
		out = append(out, e)
	}
	return out
}

// AllByIndex exposes the single in-memory map as one named index ("primary"). With
// exactly one index, the multi-index residue scan reduces to the task-003 single-map
// scan (REQ-005 backward-compat).
func (s InMemoryStore) AllByIndex() map[string][]entry {
	return map[string][]entry{primaryIndexName: s.All()}
}

// --- TwoIndexStore: the second real adapter (stdlib-only, multi-index) ------------

// TwoIndexStore is the second concrete MemoryStore proving the seam under a genuinely
// different backing representation (ADR-005), with ZERO new third-party dependency —
// go.mod stays require-free, so the dep-scan / code-scanner gate (REQ-006) is trivially
// satisfied. Unlike InMemoryStore's single map, it keeps entries in MORE THAN ONE
// backing index:
//
//   - primary:    id -> entry            (the authoritative copy)
//   - byContent:  content -> set of ids  (a secondary content-keyed index)
//
// This is the smallest store that makes task 008's "residue absent from EVERY
// index/copy" a concrete claim: a Delete must purge BOTH indexes, and All() must
// reflect the purge consistently. A bare delete from the primary that left the
// secondary index populated would be exactly the multi-index residue that
// memory-guard exists to catch — so Delete here is deliberately written to keep both
// indexes consistent, and the parameterized guard-behavior suite asserts that parity
// against InMemoryStore.
type TwoIndexStore struct {
	primary   map[string]entry
	byContent map[string]map[string]struct{} // content -> set of ids holding it
}

// NewTwoIndexStore returns an empty two-index store.
func NewTwoIndexStore() *TwoIndexStore {
	return &TwoIndexStore{
		primary:   map[string]entry{},
		byContent: map[string]map[string]struct{}{},
	}
}

func (s *TwoIndexStore) Put(id string, e entry) {
	// If id already held different content, drop the stale secondary-index link first
	// so the content index never retains a copy of overwritten content (residue).
	if old, ok := s.primary[id]; ok {
		s.unindexContent(old.content, id)
	}
	s.primary[id] = e
	ids := s.byContent[e.content]
	if ids == nil {
		ids = map[string]struct{}{}
		s.byContent[e.content] = ids
	}
	ids[id] = struct{}{}
}

func (s *TwoIndexStore) Get(id string) (entry, bool) {
	e, ok := s.primary[id]
	return e, ok
}

func (s *TwoIndexStore) Delete(id string) {
	e, ok := s.primary[id]
	if !ok {
		return
	}
	delete(s.primary, id)
	s.unindexContent(e.content, id)
}

// unindexContent removes the (content -> id) link from the secondary index, pruning the
// content key entirely once no id holds it — so a deleted entry leaves NO copy of its
// content lingering in the second index (the multi-index residue case).
func (s *TwoIndexStore) unindexContent(content, id string) {
	ids, ok := s.byContent[content]
	if !ok {
		return
	}
	delete(ids, id)
	if len(ids) == 0 {
		delete(s.byContent, content)
	}
}

func (s *TwoIndexStore) Scan(query string) []entry {
	var hits []entry
	for _, e := range s.primary {
		if substringContains(e.content, query) {
			hits = append(hits, e)
		}
	}
	return hits
}

func (s *TwoIndexStore) All() []entry {
	out := make([]entry, 0, len(s.primary))
	for _, e := range s.primary {
		out = append(out, e)
	}
	return out
}

// AllByIndex exposes BOTH backing indexes as separately-named copies so the residue
// scan can prove "no residue in ANY index" and NAME the index a residue survives in
// (task 008 / ADR-006):
//
//   - "primary":                 the authoritative id->entry copy (== All()).
//   - "secondary-content-index": the content the secondary content-keyed index still
//     holds, reconstructed from its surviving (content -> ids) links.
//
// Under a correct Delete both indexes stay consistent, so this names which index a
// surviving residue copy lives in; were Delete ever to purge only the primary, the
// stale content would surface HERE (and only here), which is exactly the multi-index
// residue an All()-only (primary-keyed) scan would miss. The index *name* is a plain
// string label chosen by the store — no backend type crosses the seam.
func (s *TwoIndexStore) AllByIndex() map[string][]entry {
	secondary := make([]entry, 0, len(s.byContent))
	for content, ids := range s.byContent {
		// Reconstruct the entry the secondary index still indexes. Carry the primary
		// entry's identity/flags when the id is still present; the content is the
		// residue-relevant payload the scan compares against.
		for id := range ids {
			if e, ok := s.primary[id]; ok {
				secondary = append(secondary, e)
			} else {
				secondary = append(secondary, entry{content: content})
			}
		}
	}
	return map[string][]entry{
		primaryIndexName:          s.All(),
		"secondary-content-index": secondary,
	}
}

// substringContains is the store-side substring predicate Scan uses. It is a thin alias
// for the stdlib so the two adapters share one definition and the seam stays the only
// thing the guard talks to (the guard does not reach into strings.Contains across the
// store boundary).
func substringContains(haystack, needle string) bool {
	return indexOfStore(haystack, needle) >= 0
}

func indexOfStore(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
