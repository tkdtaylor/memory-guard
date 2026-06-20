// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// residue.go is GUARD-SIDE orchestration, not a Detector concern.
//
// Post-deletion verification (ADR-001 §5, ADR-003) must prove a deleted entry leaves no
// surviving *residue* — a verbatim or near-verbatim fragment of the deleted content that
// lingers in another store entry (the documented industry gap a bare delete() misses). The
// residue scan is deterministic, stdlib-only string matching over the remaining store; it is
// NOT PII/injection detection, so it deliberately lives here, not behind the Detector seam.
//
// Method (ADR-003 — normalized substring/token-overlap, zero new dependency), tiered:
//  1. exact-substring of distinctive fragments (verbatim copies — the credential/secret case);
//  2. normalized match — lowercase, fold whitespace/punctuation, canonicalize numbers/currency
//     ($5000 ⇆ $5k, 5,000 ⇆ 5000) (catches the named $5000 → $5k fragment + near-verbatim);
//  3. token-overlap threshold (catches reordered / partial fragments).
//
// Full semantic paraphrase is the known miss class of a substring/token method (ADR-003) — it
// is recorded honestly per residue class in the corpus harness, not hidden.

// tokenOverlapThreshold is the fraction of the deleted content's distinctive tokens that must
// also appear in a surviving entry for tier-3 to flag residue. Tuned to catch reordered/partial
// fragments (most distinctive tokens survive) without firing on entries that merely share a few
// common words. 0.7 = "a strong majority of the distinctive tokens reappear".
const tokenOverlapThreshold = 0.7

// minDistinctiveTokens guards tier-3 against firing on very short deleted content, where a high
// overlap fraction is cheap to hit by coincidence (e.g. a 2-token entry sharing one word).
const minDistinctiveTokens = 3

// phraseMinTokens is the number of consecutive distinctive tokens that, appearing verbatim
// (normalized) and contiguously in a survivor, constitute residue (tier 2b). 3 keeps a single
// short shared word or coincidental pair from flagging while catching real multi-word fragments.
const phraseMinTokens = 3

// strongTokenMinLen is the length at which a single shared *alphabetic* token is distinctive
// enough to be residue on its own (secrets, codenames, URL fragments). Below it, a single shared
// word is too common to flag — residue then requires either a digit-bearing token (numbers, IDs)
// or tier-3 token overlap. This is what keeps shared common words ("balance", "review", "done")
// from being false positives while verbatim secrets/URLs still flag.
const strongTokenMinLen = 8

// residueScan scans the surviving entries for residue of the just-deleted content. It returns
// whether residue was detected and a human-readable summary of the first (highest-confidence)
// match. survivors is the remaining store AFTER the target entry has been removed, so an entry
// whose own content is the residue source cannot flag itself once deleted (no self-residue FP).
func residueScan(deletedContent string, survivors map[string]entry) (detected bool, summary string) {
	deletedContent = strings.TrimSpace(deletedContent)
	if deletedContent == "" {
		return false, ""
	}

	normDeleted := normalizeForResidue(deletedContent)
	delTokens := distinctiveTokens(deletedContent)

	// Deterministic iteration order so the reported summary is stable across runs.
	ids := make([]string, 0, len(survivors))
	for id := range survivors {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		survivor := survivors[id].content

		// Tier 1: exact substring of the distinctive fragment.
		if frag := exactFragmentMatch(deletedContent, survivor); frag != "" {
			return true, residueSummary("verbatim", id, frag)
		}

		// Tier 2: normalized (number/currency-canonicalized) substring.
		if frag := normalizedFragmentMatch(normDeleted, survivor); frag != "" {
			return true, residueSummary("normalized", id, frag)
		}

		// Tier 2b: contiguous distinctive phrase — a contiguous span of the deleted content (kept
		// intact, stopwords included for contiguity) that carries >=phraseMinTokens distinctive
		// tokens and appears verbatim (normalized) in the survivor. Catches a multi-word secret
		// phrase ("merger with Acme Corp") whose individual tokens are too short to be strong on
		// their own, while staying precise (a 3-distinctive-token contiguous phrase is rarely
		// coincidental).
		if frag := phraseMatch(normDeleted, survivor); frag != "" {
			return true, residueSummary("phrase", id, frag)
		}

		// Tier 3: distinctive-token overlap above threshold.
		if ratio, ok := tokenOverlapMatch(delTokens, survivor); ok {
			return true, residueSummary(
				fmt.Sprintf("token-overlap %.0f%%", ratio*100), id, survivor)
		}
	}
	return false, ""
}

// residueSummary renders the operator-visible summary string. It quotes the matched fragment so
// a human can see WHAT survived and WHERE — without restating the full (already-deleted) content.
func residueSummary(class, survivorID, fragment string) string {
	frag := fragment
	const maxFrag = 80
	if len(frag) > maxFrag {
		frag = frag[:maxFrag] + "…"
	}
	return fmt.Sprintf("%s residue of deleted content survives in entry %s: %q",
		class, survivorID, frag)
}

// --- tier 1: exact fragment match -------------------------------------------------------------

// exactFragmentMatch returns a distinctive fragment of deleted that appears verbatim in survivor,
// or "" if none. It flags on the full deleted string, or on a single *strong* token (one that is
// genuinely distinctive — see isStrongToken). A single shared common word never flags here; that
// is left to tier-3 token overlap, which requires many shared tokens.
func exactFragmentMatch(deleted, survivor string) string {
	if strings.Contains(survivor, deleted) {
		return deleted
	}
	best := ""
	for _, tok := range distinctiveTokens(deleted) {
		if isStrongToken(tok) && strings.Contains(survivor, tok) && len(tok) > len(best) {
			best = tok
		}
	}
	return best
}

// isStrongToken reports whether a single token is distinctive enough that its lone appearance in
// another entry is residue: any digit-bearing token (numbers, IDs, magnitudes, secrets) or a long
// alphabetic token (codenames, URL fragments, unusual proper nouns). Short common words are not.
func isStrongToken(tok string) bool {
	if len(tok) >= strongTokenMinLen {
		return true
	}
	for _, r := range tok {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

// --- tier 2: normalized fragment match --------------------------------------------------------

// normalizedFragmentMatch returns a matched fragment if the normalized deleted content (or one of
// its normalized distinctive fragments) is a substring of the normalized survivor. This is what
// catches $5000 → $5k and 5,000 → 5000 after currency/number canonicalization.
func normalizedFragmentMatch(normDeleted, survivor string) string {
	normSurvivor := normalizeForResidue(survivor)
	if normDeleted != "" && strings.Contains(normSurvivor, normDeleted) {
		return normDeleted
	}
	// Try normalized distinctive fragments — only *strong* ones (digit-bearing magnitudes like the
	// canonicalized "$5k" → "$5000", or long unique tokens). A lone short word does not flag.
	for _, frag := range distinctiveTokens(normDeleted) {
		if isStrongToken(frag) && strings.Contains(normSurvivor, frag) {
			return frag
		}
	}
	return ""
}

// --- tier 2b: contiguous distinctive phrase ---------------------------------------------------

// phraseMatch returns the longest contiguous span of the (already-normalized) deleted content that
// (a) appears verbatim as a substring of the normalized survivor and (b) carries at least
// phraseMinTokens distinctive (non-stopword) tokens, or "" if none. Stopwords are kept inside the
// span for contiguity ("merger with acme corp" stays intact) but do not count toward the
// distinctiveness floor, so a run of pure stopwords ("the for and the") never flags.
func phraseMatch(normDeleted, survivor string) string {
	words := strings.Fields(normDeleted)
	if len(words) < phraseMinTokens {
		return ""
	}
	normSurvivor := normalizeForResidue(survivor)
	// Try the longest windows first so the reported fragment is the most complete phrase.
	for size := len(words); size >= phraseMinTokens; size-- {
		for start := 0; start+size <= len(words); start++ {
			window := words[start : start+size]
			if countDistinctive(window) < phraseMinTokens {
				continue
			}
			phrase := strings.Join(window, " ")
			if strings.Contains(normSurvivor, phrase) {
				return phrase
			}
		}
	}
	return ""
}

// countDistinctive counts the non-stopword, >=3-char (or numeric) tokens in a window.
func countDistinctive(window []string) int {
	n := 0
	for _, w := range window {
		w = strings.Trim(w, ".$%")
		if stopWords[w] {
			continue
		}
		if len(w) < 3 {
			if _, err := strconv.Atoi(w); err != nil {
				continue
			}
		}
		n++
	}
	return n
}

// --- tier 3: token overlap --------------------------------------------------------------------

// tokenOverlapMatch returns (overlapRatio, true) if a clear majority of the deleted content's
// distinctive tokens (after normalization) reappear in the survivor. It catches reordered/partial
// fragments the substring tiers miss (e.g. "balance $5000 John" vs "John ... $5k balance").
func tokenOverlapMatch(delTokens []string, survivor string) (float64, bool) {
	if len(delTokens) < minDistinctiveTokens {
		return 0, false
	}
	survSet := map[string]struct{}{}
	for _, t := range distinctiveTokens(survivor) {
		survSet[normalizeForResidue(t)] = struct{}{}
	}
	hits := 0
	for _, t := range delTokens {
		if _, ok := survSet[normalizeForResidue(t)]; ok {
			hits++
		}
	}
	ratio := float64(hits) / float64(len(delTokens))
	return ratio, ratio >= tokenOverlapThreshold
}

// --- normalization ----------------------------------------------------------------------------

var (
	punctFold      = regexp.MustCompile(`[^\w$%.]+`) // keep $ % . (currency / decimals); fold the rest to space
	wsFold         = regexp.MustCompile(`\s+`)
	currencyKShort = regexp.MustCompile(`\$?(\d+(?:\.\d+)?)\s*([kmb])\b`) // $5k, 5k, 1.5m, 2b
	numWithCommas  = regexp.MustCompile(`\d{1,3}(?:,\d{3})+`)             // 5,000 / 1,234,567
)

// normalizeForResidue lowercases, folds whitespace/punctuation, and canonicalizes numbers and
// currency so $5000 ⇆ $5k and 5,000 ⇆ 5000 compare equal. The canonical form of a magnitude is
// its plain integer digits (5000), with a leading $ preserved when present so currency context
// is not lost. Deterministic and stdlib-only (ADR-003).
func normalizeForResidue(s string) string {
	s = strings.ToLower(s)

	// Strip thousands separators: 5,000 -> 5000.
	s = numWithCommas.ReplaceAllStringFunc(s, func(m string) string {
		return strings.ReplaceAll(m, ",", "")
	})

	// Expand k/m/b magnitudes: $5k -> $5000, 1.5m -> 1500000.
	s = currencyKShort.ReplaceAllStringFunc(s, func(m string) string {
		sub := currencyKShort.FindStringSubmatch(m)
		val, _ := strconv.ParseFloat(sub[1], 64)
		switch sub[2] {
		case "k":
			val *= 1e3
		case "m":
			val *= 1e6
		case "b":
			val *= 1e9
		}
		prefix := ""
		if strings.HasPrefix(m, "$") {
			prefix = "$"
		}
		return prefix + strconv.FormatInt(int64(val), 10)
	})

	// Fold remaining punctuation (but keep $ % . for currency/decimals) and collapse whitespace.
	s = punctFold.ReplaceAllString(s, " ")
	s = wsFold.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

// distinctiveTokens splits text into lowercased word tokens, dropping very common stop-words and
// 1–2 char fragments so a shared "the"/"is"/"a" can never carry a residue match on its own. The
// surviving tokens are the ones that actually identify the content (names, numbers, nouns).
func distinctiveTokens(text string) []string {
	raw := strings.Fields(strings.ToLower(punctFold.ReplaceAllString(text, " ")))
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		t = strings.Trim(t, ".$%")
		if len(t) < 3 {
			// keep short tokens only if they are numeric (e.g. magnitudes already expanded)
			if _, err := strconv.Atoi(t); err != nil {
				continue
			}
		}
		if stopWords[t] {
			continue
		}
		out = append(out, t)
	}
	return out
}

var stopWords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "that": true, "this": true,
	"are": true, "was": true, "has": true, "have": true, "from": true, "you": true,
	"your": true, "his": true, "her": true, "our": true, "their": true, "but": true,
	"not": true, "all": true, "any": true, "can": true, "may": true, "will": true,
}

// deletionHash is a deterministic SHA-256 over the canonical deletion operation (id + deleted
// content), suitable for later audit-trail (RFC-6962-style) chaining (ADR-003). The same logical
// deletion yields the same hash; different deleted content yields a different hash.
func deletionHash(id, deletedContent string) string {
	h := sha256.Sum256([]byte("delete\x00" + id + "\x00" + deletedContent))
	return hex.EncodeToString(h[:])
}
