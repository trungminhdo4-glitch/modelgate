package finding

import "testing"

func TestParseSeverity(t *testing.T) {
	t.Parallel()
	valid := []struct {
		in   string
		want Severity
	}{
		{"info", SeverityInfo},
		{"LOW", SeverityLow},
		{" medium ", SeverityMedium},
		{"high", SeverityHigh},
		{"Critical", SeverityCritical},
	}
	for _, tc := range valid {
		got, err := ParseSeverity(tc.in)
		if err != nil {
			t.Fatalf("ParseSeverity(%q): unexpected error %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseSeverity(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, bad := range []string{"", "warn", "criticalish", "blocker", "1"} {
		if _, err := ParseSeverity(bad); err == nil {
			t.Fatalf("ParseSeverity(%q): expected error", bad)
		}
	}
}

func TestSeverityRanksAreAscending(t *testing.T) {
	t.Parallel()
	prev := -1
	for _, s := range Severities() {
		r, err := s.Rank()
		if err != nil {
			t.Fatalf("Rank(%q): %v", s, err)
		}
		if r <= prev {
			t.Fatalf("severity %q rank %d not ascending", s, r)
		}
		prev = r
	}
}

func TestRankUnknownSeverity(t *testing.T) {
	t.Parallel()
	if _, err := Severity("bogus").Rank(); err == nil {
		t.Fatal("expected error for unknown severity")
	}
	if _, err := Severity("bogus").AtLeast(SeverityInfo); err == nil {
		t.Fatal("expected error from AtLeast for unknown severity")
	}
}

func TestAtLeast(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s, min Severity
		want   bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityHigh, true},
		{SeverityMedium, SeverityHigh, false},
		{SeverityInfo, SeverityInfo, true},
	}
	for _, tc := range cases {
		got, err := tc.s.AtLeast(tc.min)
		if err != nil {
			t.Fatalf("AtLeast(%q,%q): %v", tc.s, tc.min, err)
		}
		if got != tc.want {
			t.Fatalf("AtLeast(%q,%q) = %t, want %t", tc.s, tc.min, got, tc.want)
		}
	}
}

func TestSortFindings(t *testing.T) {
	t.Parallel()
	fs := []Finding{
		{Rule: "B", Severity: SeverityInfo, File: "a.py", Line: 1},
		{Rule: "A", Severity: SeverityCritical, File: "b.py", Line: 2},
		{Rule: "A", Severity: SeverityCritical, File: "b.py", Line: 1},
		{Rule: "A", Severity: SeverityHigh, File: "a.py", Line: 9},
	}
	SortFindings(fs)
	wantRules := []string{"A", "A", "A", "B"}
	wantLines := []int{1, 2, 9, 1}
	for i := range fs {
		if fs[i].Rule != wantRules[i] || fs[i].Line != wantLines[i] {
			t.Fatalf("position %d = %s:%d, want %s:%d", i, fs[i].Rule, fs[i].Line, wantRules[i], wantLines[i])
		}
	}
}

func TestFindingKey(t *testing.T) {
	t.Parallel()
	a := Finding{Rule: "R", File: "f.py", Evidence: "x"}
	b := Finding{Rule: "R", File: "f.py", Evidence: "y"}
	if a.Key() == b.Key() {
		t.Fatal("different evidence must yield different keys")
	}
	if a.Key() != (Finding{Rule: "R", File: "f.py", Evidence: "x"}).Key() {
		t.Fatal("identical findings must yield equal keys")
	}
}
