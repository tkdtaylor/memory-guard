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
//     ($5000 ⇆ $5k, 5,000 ⇆ 5000) AND spelled-out number-words (five thousand ⇆ 5000) (catches the
//     named $5000 → $5k fragment, near-verbatim, and the number-word paraphrase class — ADR-006);
//  3. token-overlap threshold (catches reordered / partial fragments).
//
// Across EVERY backing index/copy (task 008 / ADR-006): the scan runs over the store's
// AllByIndex() — each named backing index — so a residue surviving in a SECONDARY index (one the
// primary-keyed All() would miss) is caught, and the summary NAMES the index it survives in.
//
// Full free-form semantic paraphrase (synonym substitution with no shared distinctive token —
// "potted plant" → "planter near the rack closet") remains the residual known-miss class of a
// stdlib substring/token/number-word method (ADR-006) — recorded honestly per residue class in the
// corpus harness, not hidden. The number-word class IS now caught.

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

// residueScan scans a single index's surviving entries for residue of the just-deleted content
// (the task-003 single-map scan). It is preserved as a thin wrapper over residueScanIndexes so the
// task-003 residue tests, which pass one survivor slice, behave UNCHANGED (REQ-005): a single index
// keyed "primary". survivors is the remaining store AFTER the target entry has been removed, so an
// entry whose own content is the residue source cannot flag itself once deleted (no self-residue
// FP). It receives []entry rather than the raw map so it stays decoupled from the MemoryStore
// backing.
func residueScan(deletedContent string, survivors []entry) (detected bool, summary string) {
	return residueScanIndexes(deletedContent, map[string][]entry{primaryIndexName: survivors})
}

// residueScanIndexes scans EVERY backing index/copy for residue of the just-deleted content (task
// 008 / ADR-006). byIndex maps an index name (a plain string label from the MemoryStore seam's
// AllByIndex()) to that index's survivors. It returns whether residue was detected in ANY index and
// a human-readable summary of the first (highest-confidence, deterministic) match — the summary
// NAMES the index the residue survives in. Scanning every index means a residue surviving only in a
// SECONDARY copy (which a primary-keyed All() scan would miss) is caught. For a single-index store
// (one "primary" entry in byIndex) this reduces exactly to the task-003 single-map scan.
func residueScanIndexes(deletedContent string, byIndex map[string][]entry) (detected bool, summary string) {
	deletedContent = strings.TrimSpace(deletedContent)
	if deletedContent == "" {
		return false, ""
	}

	normDeleted := normalizeForResidue(deletedContent)
	delTokens := distinctiveTokens(deletedContent)

	// Deterministic index order: "primary" first (so a residue present in both the primary and a
	// secondary index reports against "primary" for parity with the single-index scan), then the rest
	// alphabetically. This keeps the reported summary stable across runs and store backings.
	indexNames := make([]string, 0, len(byIndex))
	for name := range byIndex {
		indexNames = append(indexNames, name)
	}
	sort.Slice(indexNames, func(i, j int) bool {
		if indexNames[i] == primaryIndexName {
			return true
		}
		if indexNames[j] == primaryIndexName {
			return false
		}
		return indexNames[i] < indexNames[j]
	})

	for _, indexName := range indexNames {
		// Deterministic scan order within an index so the reported summary is stable across runs and
		// identical across store backings (different native map iteration orders must not change the
		// result). Sort survivors by content.
		contents := make([]string, 0, len(byIndex[indexName]))
		for _, e := range byIndex[indexName] {
			contents = append(contents, e.content)
		}
		sort.Strings(contents)

		for _, survivor := range contents {
			class, frag := matchSurvivor(deletedContent, normDeleted, delTokens, survivor)
			if class != "" {
				return true, residueSummaryInIndex(class, indexName, survivorRef(survivor), frag)
			}
		}
	}
	return false, ""
}

// matchSurvivor runs the tiered residue match of the deleted content against ONE surviving entry,
// returning the match class and the matched fragment (or "" class for no match). Factored out of the
// scan loop so it runs identically per survivor in every backing index.
func matchSurvivor(deleted, normDeleted string, delTokens []string, survivor string) (class, fragment string) {
	// Tier 1: exact substring of the distinctive fragment.
	if frag := exactFragmentMatch(deleted, survivor); frag != "" {
		return "verbatim", frag
	}

	// Tier 2: normalized (number/currency/number-word-canonicalized) substring.
	if frag := normalizedFragmentMatch(normDeleted, survivor); frag != "" {
		return "normalized", frag
	}

	// Tier 2b: contiguous distinctive phrase — a contiguous span of the deleted content (kept intact,
	// stopwords included for contiguity) that carries >=phraseMinTokens distinctive tokens and appears
	// verbatim (normalized) in the survivor. Catches a multi-word secret phrase ("merger with Acme
	// Corp") whose individual tokens are too short to be strong on their own, while staying precise.
	if frag := phraseMatch(normDeleted, survivor); frag != "" {
		return "phrase", frag
	}

	// Tier 3: distinctive-token overlap above threshold.
	if ratio, ok := tokenOverlapMatch(delTokens, survivor); ok {
		return fmt.Sprintf("token-overlap %.0f%%", ratio*100), survivor
	}
	return "", ""
}

// residueSummaryInIndex renders the operator-visible summary string. It quotes the matched fragment
// so a human can see WHAT survived and WHERE — the surviving entry (a short content snippet, since
// the scan operates over the store's AllByIndex() survivors, which carry no map id) AND the named
// backing index/copy the residue survives in (task 008 / ADR-006). The full (already-deleted)
// content is not restated.
func residueSummaryInIndex(class, indexName, survivorRef, fragment string) string {
	frag := fragment
	const maxFrag = 80
	if len(frag) > maxFrag {
		frag = frag[:maxFrag] + "…"
	}
	return fmt.Sprintf("%s residue of deleted content survives in index %q, entry %s: %q",
		class, indexName, survivorRef, frag)
}

// survivorRef renders a short, stable label for a surviving entry from its content (a quoted
// snippet), used in the residue summary now that survivors arrive as []entry across the seam
// rather than as id-keyed map values.
func survivorRef(content string) string {
	const maxRef = 32
	snippet := content
	if len(snippet) > maxRef {
		snippet = snippet[:maxRef] + "…"
	}
	return fmt.Sprintf("%q", snippet)
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
// currency so $5000 ⇆ $5k, 5,000 ⇆ 5000, and the spelled-out "five thousand" ⇆ 5000 compare equal.
// The canonical form of a magnitude is its plain integer digits (5000), with a leading $ preserved
// when present so currency context is not lost. Deterministic and stdlib-only (ADR-003 / ADR-006).
func normalizeForResidue(s string) string {
	s = strings.ToLower(s)

	// Canonicalize spelled-out number-words to digits BEFORE the digit-based passes, so "five
	// thousand" -> "5000" then flows through the same magnitude/currency canonicalization (ADR-006,
	// the number-word paraphrase class). Stdlib-only; no dependency.
	s = canonicalizeNumberWords(s)

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

// --- number-word canonicalization (ADR-006, the number-word paraphrase class) ----------------

// numberWordUnits maps spelled-out cardinal number-words (units and tens) to their integer value.
var numberWordUnits = map[string]int64{
	"zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
	"six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
	"eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
	"sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19,
	"twenty": 20, "thirty": 30, "forty": 40, "fifty": 50, "sixty": 60,
	"seventy": 70, "eighty": 80, "ninety": 90,
}

// numberWordScales maps spelled-out magnitude words to their multiplier.
var numberWordScales = map[string]int64{
	"hundred": 100, "thousand": 1000, "million": 1000000, "billion": 1000000000,
}

// canonicalizeNumberWords rewrites runs of spelled-out cardinal number-words ("five thousand",
// "twenty five thousand", "three hundred forty two") to their plain integer digits ("5000", "25000",
// "342"), so a deleted "$5000" and a paraphrased "five thousand dollars" share the strong token
// "5000" after normalization. It is intentionally conservative — only contiguous runs of recognized
// number-words (with optional "and") are folded; any other word ends the run and is passed through
// unchanged. This makes it precision-safe: text with no spelled-out numbers is returned verbatim, so
// it adds no false positives on the clean controls. Deterministic, stdlib-only (no dependency).
func canonicalizeNumberWords(s string) string {
	tokens := strings.Fields(s)
	out := make([]string, 0, len(tokens))
	i := 0
	for i < len(tokens) {
		w := strings.Trim(tokens[i], ".,$%")
		_, isUnit := numberWordUnits[w]
		_, isScale := numberWordScales[w]
		if !isUnit && !isScale {
			out = append(out, tokens[i])
			i++
			continue
		}
		// Consume the contiguous run of number-words (units, scales, and connective "and").
		var current, total int64
		consumed, seen := 0, 0
		for i+consumed < len(tokens) {
			tw := strings.Trim(tokens[i+consumed], ".,$%")
			if v, ok := numberWordUnits[tw]; ok {
				current += v
				consumed++
				seen++
			} else if sc, ok := numberWordScales[tw]; ok {
				if current == 0 {
					current = 1
				}
				if sc == 100 {
					current *= 100
				} else {
					total += current * sc
					current = 0
				}
				consumed++
				seen++
			} else if tw == "and" && seen > 0 {
				consumed++
			} else {
				break
			}
		}
		total += current
		out = append(out, strconv.FormatInt(total, 10))
		i += consumed
	}
	return strings.Join(out, " ")
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
