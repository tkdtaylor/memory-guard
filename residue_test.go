// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// residue_test.go — task 003 / test-spec 003.
//
// Covers: TC-001 (verify_delete returns residue fields), TC-002 (the confirmed/residue_detected
// truth table incl. self-residue), TC-003 (>80% detection on a labelled residue corpus, recorded
// per residue class), TC-004 (deletion_hash present + deterministic), TC-005 (v0 backward compat —
// see TestVerifyDeleteConfirmsAbsence in guard_test.go), TC-006 (no new dependency — note only).

// seedEntry writes content directly into the store (bypassing the write-gate / PII redaction so
// the residue scan is tested on the literal content the corpus specifies) and returns its id.
func seedEntry(g *MemoryGuard, content string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	id := "mem-" + randHex(6)
	g.store[id] = entry{content: content}
	return id
}

// ---- TC-001: verify_delete scans for residue and returns the residue fields ------------------

func TestVerifyDeleteReturnsResidueFields(t *testing.T) {
	g := NewMemoryGuard(nil)
	primary := seedEntry(g, "user John's balance is $5000")
	seedEntry(g, "note: John's balance is $5k as of Friday") // surviving residue

	out := g.VerifyDelete(primary)

	if out["confirmed"] != true {
		t.Fatalf("TC-001: expected confirmed:true, got %v", out["confirmed"])
	}
	if out["residue_detected"] != true {
		t.Fatalf("TC-001: expected residue_detected:true ($5000→$5k), got %v", out)
	}
	if _, ok := out["residue_summary"].(string); !ok || out["residue_summary"] == "" {
		t.Fatalf("TC-001: expected a non-empty residue_summary, got %v", out["residue_summary"])
	}
	if h, ok := out["deletion_hash"].(string); !ok || len(h) != 64 {
		t.Fatalf("TC-001: expected a 64-hex deletion_hash, got %v", out["deletion_hash"])
	}
}

func TestVerifyDeleteNoResidueOmitsSummary(t *testing.T) {
	g := NewMemoryGuard(nil)
	primary := seedEntry(g, "user John's balance is $5000")
	seedEntry(g, "the weather in Lisbon is mild this week") // unrelated control

	out := g.VerifyDelete(primary)

	if out["confirmed"] != true || out["residue_detected"] != false {
		t.Fatalf("TC-001 edge: expected confirmed:true residue_detected:false, got %v", out)
	}
	if _, present := out["residue_summary"]; present {
		t.Fatalf("TC-001 edge: residue_summary must be absent when no residue, got %v", out["residue_summary"])
	}
}

// ---- TC-002: the confirmed / residue_detected truth table ------------------------------------

func TestVerifyDeleteTruthTable(t *testing.T) {
	// (a) delete with no residue
	t.Run("a_no_residue", func(t *testing.T) {
		g := NewMemoryGuard(nil)
		id := seedEntry(g, "remember to water the office plants")
		seedEntry(g, "the quarterly report ships next Tuesday")
		out := g.VerifyDelete(id)
		if out["confirmed"] != true || out["residue_detected"] != false {
			t.Fatalf("(a): want confirmed:true residue_detected:false, got %v", out)
		}
	})

	// (b) delete with surviving residue
	t.Run("b_with_residue", func(t *testing.T) {
		g := NewMemoryGuard(nil)
		id := seedEntry(g, "API endpoint is https://internal.example.com/v2/admin")
		seedEntry(g, "ping https://internal.example.com/v2/admin for the admin panel")
		out := g.VerifyDelete(id)
		if out["confirmed"] != true || out["residue_detected"] != true {
			t.Fatalf("(b): want confirmed:true residue_detected:true, got %v", out)
		}
		if out["residue_summary"] == nil || out["residue_summary"] == "" {
			t.Fatalf("(b): want a residue_summary, got %v", out["residue_summary"])
		}
	})

	// (c) delete of an absent id
	t.Run("c_absent_id", func(t *testing.T) {
		g := NewMemoryGuard(nil)
		seedEntry(g, "some surviving entry that should not be scanned for an absent delete")
		out := g.VerifyDelete("mem-doesnotexist")
		if out["confirmed"] != true || out["residue_detected"] != false {
			t.Fatalf("(c): want confirmed:true residue_detected:false, got %v", out)
		}
		if _, present := out["residue_summary"]; present {
			t.Fatalf("(c): absent delete must not report residue, got %v", out["residue_summary"])
		}
	})

	// edge: an entry whose own content is the residue source is itself deleted → no self-FP.
	t.Run("d_no_self_residue", func(t *testing.T) {
		g := NewMemoryGuard(nil)
		id := seedEntry(g, "the launch codes are 8829-ZULU-DELTA-4471 do not share")
		out := g.VerifyDelete(id) // it is the ONLY entry; after delete the store is empty
		if out["confirmed"] != true || out["residue_detected"] != false {
			t.Fatalf("(d): a deleted entry must not flag itself, got %v", out)
		}
	})
}

// ---- TC-004: deletion_hash present and deterministic -----------------------------------------

func TestDeletionHashDeterministic(t *testing.T) {
	// Same logical deletion (same id + content) on a fresh store → same hash.
	g1 := NewMemoryGuard(nil)
	g1.store["mem-fixed"] = entry{content: "delete me exactly"}
	h1 := g1.VerifyDelete("mem-fixed")["deletion_hash"].(string)

	g2 := NewMemoryGuard(nil)
	g2.store["mem-fixed"] = entry{content: "delete me exactly"}
	h2 := g2.VerifyDelete("mem-fixed")["deletion_hash"].(string)

	if h1 != h2 {
		t.Fatalf("TC-004: same logical deletion must hash equal: %s != %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("TC-004: expected SHA-256 hex (64 chars), got %d", len(h1))
	}

	// Different deleted content → different hash.
	g3 := NewMemoryGuard(nil)
	g3.store["mem-fixed"] = entry{content: "a different secret entirely"}
	h3 := g3.VerifyDelete("mem-fixed")["deletion_hash"].(string)
	if h3 == h1 {
		t.Fatalf("TC-004: different deleted content must hash differently, both %s", h1)
	}

	// Pure helper-level determinism.
	if deletionHash("x", "y") != deletionHash("x", "y") {
		t.Fatal("TC-004: deletionHash is not deterministic")
	}
	if deletionHash("x", "y") == deletionHash("x", "z") {
		t.Fatal("TC-004: deletionHash collides on different content")
	}
}

// ---- TC-003: residue method meets >80% detection on a labelled corpus ------------------------

type residueCase struct {
	name    string
	deleted string   // the content being deleted
	store   []string // surviving entries (the residue or clean controls)
	class   string   // "verbatim" | "normalized-numeric" | "paraphrase" | "clean"
	want    bool     // expected residue_detected
}

// residueCorpus — labelled triples (deletion target + surviving entries) plus clean controls.
// class records the kind of residue so the rate can be reported per class (ADR-003: paraphrase is
// the documented known-miss class of a substring/token method; the corpus is NOT padded to hide it).
func residueCorpus() []residueCase {
	return []residueCase{
		// --- verbatim residue (the credential / secret copy case) ---
		{"verbatim_secret", "the root password is hunter2-Xq9-prod",
			[]string{"reminder: the root password is hunter2-Xq9-prod"}, "verbatim", true},
		{"verbatim_url", "deploy hook https://ci.example.com/hook/9f3a2b",
			[]string{"the deploy hook https://ci.example.com/hook/9f3a2b is in the wiki"}, "verbatim", true},
		{"verbatim_token", "session token: sk-live-AB12CD34EF56GH78",
			[]string{"old note mentions sk-live-AB12CD34EF56GH78 somewhere"}, "verbatim", true},
		{"verbatim_phrase", "patient Maria Gomez has a peanut allergy",
			[]string{"chart: patient Maria Gomez has a peanut allergy, flag it"}, "verbatim", true},
		{"verbatim_fragment", "the merger with Acme Corp closes in March",
			[]string{"unrelated preamble — merger with Acme Corp — trailing text"}, "verbatim", true},

		// --- normalized-numeric residue ($5000 → $5k, 5,000 → 5000, casing/punct) ---
		{"currency_5k", "user John's balance is $5000",
			[]string{"note: John's balance is $5k as of Friday"}, "normalized-numeric", true},
		{"comma_thousands", "the contract value is 1,250,000 dollars",
			[]string{"contract value 1250000 dollars confirmed"}, "normalized-numeric", true},
		{"k_magnitude", "the breach exposed 12000 records",
			[]string{"breach exposed 12k records per the report"}, "normalized-numeric", true},
		{"case_punct_fold", "Account: ACME-9931 / Status=ACTIVE",
			[]string{"the account acme 9931 status active was seen again"}, "normalized-numeric", true},
		{"million_short", "the fund holds 3000000 in reserve",
			[]string{"fund holds 3m in reserve per the memo"}, "normalized-numeric", true},

		// --- token-overlap residue (reordered / partial distinctive fragments) ---
		{"reordered", "transfer 4500 to account Zephyr Holdings tomorrow",
			[]string{"Zephyr Holdings account — transfer tomorrow — 4500 amount"}, "normalized-numeric", true},
		{"partial_overlap", "the codename for project nightingale is BLUEHERON",
			[]string{"BLUEHERON nightingale codename project leaked"}, "normalized-numeric", true},

		// --- paraphrase residue (the DOCUMENTED known-miss class — not padded) ---
		{"paraphrase_money", "user John's balance is $5000",
			[]string{"the customer named John has five thousand dollars saved up"}, "paraphrase", false},
		{"paraphrase_concept", "the server room key is under the third potted plant",
			[]string{"to get in, check beneath the planter near the rack closet"}, "paraphrase", false},

		// --- clean controls (must stay residue_detected:false) ---
		{"clean_weather", "user John's balance is $5000",
			[]string{"the weather in Lisbon is mild this week"}, "clean", false},
		{"clean_unrelated", "the root password is hunter2-Xq9-prod",
			[]string{"remember to renew the office plants subscription"}, "clean", false},
		{"clean_common_words", "please review the report and the budget for the team",
			[]string{"the team will review the agenda and the schedule"}, "clean", false},
		{"clean_short", "ok done",
			[]string{"ok the task is now done and shipped"}, "clean", false},
	}
}

func TestResidueCorpusDetectionRate(t *testing.T) {
	corpus := residueCorpus()

	// Per-class tallies for residue cases; precision tracked over clean controls.
	type tally struct{ hit, total int }
	classRate := map[string]*tally{}
	residueHit, residueTotal := 0, 0
	falsePositives, cleanTotal := 0, 0

	for _, c := range corpus {
		g := NewMemoryGuard(nil)
		target := seedEntry(g, c.deleted)
		for _, s := range c.store {
			seedEntry(g, s)
		}
		got := g.VerifyDelete(target)["residue_detected"] == true

		if c.class == "clean" {
			cleanTotal++
			if got {
				falsePositives++
				t.Errorf("TC-003 precision: clean control %q wrongly flagged residue", c.name)
			}
			continue
		}

		// residue case
		residueTotal++
		if classRate[c.class] == nil {
			classRate[c.class] = &tally{}
		}
		classRate[c.class].total++
		if got == c.want && got {
			residueHit++
			classRate[c.class].hit++
		} else if c.want && !got {
			// a residue case the method missed — expected only for the paraphrase class
			if c.class != "paraphrase" {
				t.Errorf("TC-003: %s residue %q expected to be caught but was missed", c.class, c.name)
			}
		}
	}

	overall := float64(residueHit) / float64(residueTotal)

	// Report the rate per class (ADR-003 requires the breakdown; paraphrase is the known miss).
	classes := make([]string, 0, len(classRate))
	for k := range classRate {
		classes = append(classes, k)
	}
	sort.Strings(classes)
	var b strings.Builder
	fmt.Fprintf(&b, "\nresidue-detection rate (TC-003):\n")
	for _, cl := range classes {
		tl := classRate[cl]
		fmt.Fprintf(&b, "  %-20s %d/%d = %.0f%%\n", cl, tl.hit, tl.total,
			100*float64(tl.hit)/float64(tl.total))
	}
	fmt.Fprintf(&b, "  %-20s %d/%d = %.1f%% (bar: >80%%)\n", "OVERALL", residueHit, residueTotal,
		100*overall)
	fmt.Fprintf(&b, "  %-20s %d FP / %d clean controls (precision %.0f%%)\n", "PRECISION",
		falsePositives, cleanTotal, 100*float64(cleanTotal-falsePositives)/float64(cleanTotal))
	t.Log(b.String())

	if overall <= 0.80 {
		t.Fatalf("TC-003: residue-detection rate %.1f%% does not clear the >80%% bar", 100*overall)
	}
	if falsePositives != 0 {
		t.Fatalf("TC-003: %d false positives on clean controls (precision must hold)", falsePositives)
	}
}

// TestResidueCorpusSummary prints the per-class rate without an assertion, for `-run` reproduction.
func TestResidueCorpusSummary(t *testing.T) {
	if testing.Short() {
		t.Skip("summary print")
	}
	TestResidueCorpusDetectionRate(t)
}
