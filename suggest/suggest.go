// Package suggest provides fuzzy-matching helpers and a typed telemetry
// channel for unknown-name events. See §4.5 + §4.11 of the v0.8.0 plan.
package suggest

import (
	"math"
	"sort"
	"strings"
)

// Match is a candidate paired with its edit distance from the query.
type Match struct {
	Name     string
	Distance int
}

// maxQueryRunes caps the query length fed to the Levenshtein DP. Inputs
// above this are almost certainly adversarial — real MCP tool and
// parameter names are sub-64 runes. At the 1 MB params cap a caller could
// otherwise drive ~(1 MB × avg-candidate-length) DP cell operations per
// unknown-name call, turning the fuzzy suggester into a cheap DoS surface
// (Closest runs on every unknown mux-execute tool name). 256 is
// generous enough that any honest typo still matches.
const maxQueryRunes = 256

// Closest returns up to n candidates closest to query by Levenshtein
// distance, filtered to a similarity threshold.
//
// The threshold mirrors the Node mux-tools.mjs findClosestMatch semantics:
// a candidate qualifies iff distance(query, candidate) ≤ max(3, ceil(maxLen * 0.4))
// where maxLen = max(len(query), len(candidate)). Comparison is
// case-insensitive, but returned names preserve the candidate's original case.
// Results are sorted ascending by distance, ties broken alphabetically.
func Closest(query string, candidates []string, n int) []string {
	matches := ClosestWithScores(query, candidates, n)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, len(matches))
	for i, m := range matches {
		out[i] = m.Name
	}
	return out
}

// ClosestWithScores is like Closest but returns (name, distance) pairs.
//
// DoS guards: queries longer than maxQueryRunes (256) return no matches
// — they're either adversarial or a copy-paste mistake, and running the
// DP on them makes this function a trivial CPU sink. For each candidate,
// a length-delta gate skips the DP when |qLen - cLen| already exceeds
// the similarity threshold (the minimum achievable distance is at least
// the length delta, so no further work can improve it). Together these
// bring the worst-case from O(Q·C·max(q,c)) cell operations to
// O(C · max(q,c)) — the length-gate alone kills pathological inputs
// even when q is pinned at 256.
func ClosestWithScores(query string, candidates []string, n int) []Match {
	if n <= 0 || query == "" || len(candidates) == 0 {
		return nil
	}

	qLower := strings.ToLower(query)
	qRunes := []rune(qLower)
	qLen := len(qRunes)
	if qLen > maxQueryRunes {
		return nil
	}

	matches := make([]Match, 0, len(candidates))
	for _, c := range candidates {
		cLower := strings.ToLower(c)
		cRunes := []rune(cLower)
		cLen := len(cRunes)

		maxLen := qLen
		if cLen > maxLen {
			maxLen = cLen
		}
		// Threshold: max(3, ceil(maxLen * 0.4)).
		threshold := int(math.Ceil(float64(maxLen) * 0.4))
		if threshold < 3 {
			threshold = 3
		}

		// Length-gate: the edit distance is always at least the
		// absolute length difference. If that already exceeds the
		// threshold, the DP cannot produce a qualifying match.
		delta := qLen - cLen
		if delta < 0 {
			delta = -delta
		}
		if delta > threshold {
			continue
		}

		d := levenshteinRunes(qRunes, cRunes)
		if d <= threshold {
			matches = append(matches, Match{Name: c, Distance: d})
		}
	}

	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Distance != matches[j].Distance {
			return matches[i].Distance < matches[j].Distance
		}
		return matches[i].Name < matches[j].Name
	})

	if len(matches) > n {
		matches = matches[:n]
	}
	if len(matches) == 0 {
		return nil
	}
	return matches
}

// levenshtein computes the Levenshtein edit distance between a and b,
// counting runes rather than bytes so non-ASCII inputs behave correctly.
func levenshtein(a, b string) int {
	return levenshteinRunes([]rune(a), []rune(b))
}

// levenshteinRunes is the rune-slice variant used internally to avoid
// re-decoding UTF-8 in the Closest hot path.
func levenshteinRunes(a, b []rune) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	// Two-row DP. prev = row i-1, curr = row i.
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			// min(delete, insert, substitute)
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}
