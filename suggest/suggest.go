// Package suggest provides fuzzy-matching helpers and a typed telemetry
// channel for unknown-name events. See §4.5 + §4.11 of the v0.8.0 plan.
package suggest

// Match is a candidate paired with its edit distance from the query.
type Match struct {
	Name     string
	Distance int
}

// Closest returns up to n candidates closest to query by Levenshtein
// distance, filtered to a minimum similarity threshold.
//
// Phase 0 minimal impl: returns nil. Session 3 (track 2A) replaces with
// the full Levenshtein + threshold logic mirroring Node mux-tools.mjs
// findClosestMatch — threshold = max(3, ceil(maxLen * 0.4)).
func Closest(query string, candidates []string, n int) []string {
	return nil
}

// ClosestWithScores is like Closest but returns (name, distance) pairs.
//
// Phase 0: returns nil; track 2A fills in.
func ClosestWithScores(query string, candidates []string, n int) []Match {
	return nil
}
