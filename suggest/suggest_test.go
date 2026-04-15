package suggest

import (
	"reflect"
	"testing"
)

func TestLevenshtein_Basics(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"kitten", "sitting", 3},
		{"flaw", "lawn", 2},
		{"a", "b", 1},
		{"", "abc", 3},
		{"abc", "", 3},
		{"", "", 0},
		{"identical", "identical", 0},
		// Unicode: café vs cafe — one substitution at the last rune.
		{"café", "cafe", 1},
		// Full rune swap — "héllo" vs "hello" — one substitution.
		{"héllo", "hello", 1},
	}
	for _, c := range cases {
		got := levenshtein(c.a, c.b)
		if got != c.want {
			t.Errorf("levenshtein(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestClosest_HappyPath(t *testing.T) {
	candidates := []string{
		"jiraGetIssue", "jiraGetIssueType", "jiraGetIssues",
		"jiraCreateIssue", "jiraUpdateIssue", "jiraDeleteIssue",
		"jiraSearchIssues", "jiraListIssues", "jiraAssignIssue",
		"confluenceGetPage", "confluenceCreatePage", "confluenceUpdatePage",
		"slackSendMessage", "slackReadChannel", "slackSearchMessages",
		"githubCreatePR", "githubGetPR", "githubMergePR", "githubListPRs",
		"genericEcho",
	}
	got := Closest("jiraGetIsue", candidates, 3)
	if len(got) == 0 {
		t.Fatalf("Closest returned empty; want matches")
	}
	if got[0] != "jiraGetIssue" {
		t.Errorf("Closest first = %q, want jiraGetIssue", got[0])
	}
}

func TestClosest_ThresholdFloor(t *testing.T) {
	// "foo" vs "fog" is distance 1 — should match.
	got := Closest("foo", []string{"fog"}, 5)
	if len(got) != 1 || got[0] != "fog" {
		t.Errorf("Closest(foo, [fog]) = %v, want [fog]", got)
	}
	// "foo" vs "bar" is distance 3. maxLen=3 → ceil(3*0.4)=2 → but floor 3
	// means threshold=3. Distance 3 ≤ 3, so this *does* match. Use a pair
	// with distance 4 to check rejection.
	got = Closest("foo", []string{"xyzzy"}, 5)
	if len(got) != 0 {
		t.Errorf("Closest(foo, [xyzzy]) = %v, want nil (distance exceeds threshold)", got)
	}
	// Confirm the floor direction: "jira"/"jiraGet" has distance 3, both
	// short, maxLen=7, threshold=max(3, ceil(7*0.4))=max(3,3)=3 → matches.
	got = Closest("jira", []string{"jiraGet"}, 5)
	if len(got) != 1 {
		t.Errorf("Closest(jira, [jiraGet]) = %v, want match (floor=3)", got)
	}
}

func TestClosest_CaseInsensitive(t *testing.T) {
	got := Closest("JIRAGETISSUE", []string{"jiraGetIssue", "other"}, 5)
	if len(got) == 0 || got[0] != "jiraGetIssue" {
		t.Errorf("Closest returned %v, want [jiraGetIssue] (preserving original case)", got)
	}
}

func TestClosest_TieBreakAlphabetical(t *testing.T) {
	// "foo" vs "bar" and "foo" vs "baz" both have distance 3.
	// Expect alphabetical: bar before baz.
	got := Closest("foo", []string{"baz", "bar"}, 5)
	if len(got) < 2 {
		t.Fatalf("Closest returned %v, want 2 matches", got)
	}
	if got[0] != "bar" || got[1] != "baz" {
		t.Errorf("Closest ordering = %v, want [bar baz]", got)
	}
}

func TestClosest_NLimit(t *testing.T) {
	// 5 exact matches (distance 0) — n=2 should cap to 2.
	cands := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	// Use "alpha" as query — only "alpha" is exact, but others may still
	// pass threshold. Switch strategy: build 5 near-identical candidates.
	cands = []string{"foox", "fooy", "fooz", "fooa", "foob"}
	got := Closest("foo", cands, 2)
	if len(got) != 2 {
		t.Errorf("Closest n=2 returned %d results, want 2", len(got))
	}
}

func TestClosest_EmptyInputs(t *testing.T) {
	if got := Closest("", []string{"a", "b"}, 3); got != nil {
		t.Errorf("empty query: got %v, want nil", got)
	}
	if got := Closest("foo", nil, 3); got != nil {
		t.Errorf("nil candidates: got %v, want nil", got)
	}
	if got := Closest("foo", []string{}, 3); got != nil {
		t.Errorf("empty candidates: got %v, want nil", got)
	}
	if got := Closest("foo", []string{"foo"}, 0); got != nil {
		t.Errorf("n=0: got %v, want nil", got)
	}
	if got := Closest("foo", []string{"foo"}, -1); got != nil {
		t.Errorf("n=-1: got %v, want nil", got)
	}
}

func TestClosestWithScores_ReturnsDistances(t *testing.T) {
	got := ClosestWithScores("kitten", []string{"sitting", "kitten"}, 5)
	if len(got) != 2 {
		t.Fatalf("got %d matches, want 2: %v", len(got), got)
	}
	// kitten=0 should come first.
	if got[0].Name != "kitten" || got[0].Distance != 0 {
		t.Errorf("first = %+v, want {kitten, 0}", got[0])
	}
	if got[1].Name != "sitting" || got[1].Distance != 3 {
		t.Errorf("second = %+v, want {sitting, 3}", got[1])
	}
}

func TestClosest_UnicodeRunes(t *testing.T) {
	// "café" (4 runes, 5 bytes) vs "cafe" (4 runes, 4 bytes). If comparison
	// were byte-level, the lengths would differ (5 vs 4) and the distance
	// computation would be off. With rune-level, distance = 1.
	got := ClosestWithScores("café", []string{"cafe"}, 1)
	if len(got) != 1 {
		t.Fatalf("got %v, want one match", got)
	}
	if got[0].Distance != 1 {
		t.Errorf("distance = %d, want 1", got[0].Distance)
	}
	// And a longer mixed unicode case: "naïve" vs "naive".
	got = ClosestWithScores("naïve", []string{"naive"}, 1)
	if len(got) != 1 || got[0].Distance != 1 {
		t.Errorf("naïve/naive: got %+v, want distance 1", got)
	}
}

func TestClosest_ReturnsNilWhenNoneQualify(t *testing.T) {
	// Totally unrelated words; verify we return nil (not empty slice).
	got := Closest("supercalifragilistic", []string{"hello", "world"}, 3)
	if got != nil {
		t.Errorf("got %v, want nil (none qualify)", got)
	}
}

func TestClosest_ExactMatchFirst(t *testing.T) {
	got := Closest("echo", []string{"echo2", "echo", "echoo"}, 3)
	want := []string{"echo", "echo2", "echoo"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
