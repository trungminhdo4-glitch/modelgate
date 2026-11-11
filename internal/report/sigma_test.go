package report

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/trung-dev/modelgate/internal/finding"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files")

func TestSigmaStructure(t *testing.T) {
	t.Parallel()
	rep := build(t, fixtureResult(), finding.SeverityHigh)
	data, err := rep.Sigma()
	if err != nil {
		t.Fatalf("sigma: %v", err)
	}
	out := string(data)

	uuidRe := regexp.MustCompile(`(?m)^id: [0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !uuidRe.MatchString(out) {
		t.Fatalf("sigma id is not a version-5 uuid:\n%s", out)
	}
	for _, want := range []string{
		"title: ",
		"status: experimental",
		"description: '",
		"references:",
		"author: 'trung-dev'",
		"date: 2026-11-11",
		"logsource:",
		"  category: file_scan",
		"  product: modelgate",
		"detection:",
		"  condition: 1 of sel_*",
		"falsepositives:",
		"level: high",
		"  - attack.t1059.006",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sigma output missing %q", want)
		}
	}
	if strings.Contains(out, "\t") {
		t.Fatal("sigma output must not contain tabs")
	}
	// Every keyword and string value must be single-quoted.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "    - ") && !strings.HasPrefix(line, "    - '") {
			t.Errorf("unquoted keyword line: %q", line)
		}
	}
	// Tags must be sorted.
	tagBlock := false
	prev := ""
	for _, line := range strings.Split(out, "\n") {
		switch {
		case line == "tags:":
			tagBlock = true
			continue
		case tagBlock && strings.HasPrefix(line, "  - "):
			tag := strings.TrimPrefix(line, "  - ")
			if prev != "" && tag < prev {
				t.Fatalf("tags not sorted: %q after %q", tag, prev)
			}
			prev = tag
			continue
		case tagBlock:
			tagBlock = false
		}
	}
}

func TestSigmaDeterministic(t *testing.T) {
	t.Parallel()
	rep := build(t, fixtureResult(), finding.SeverityHigh)
	a, err := rep.Sigma()
	if err != nil {
		t.Fatal(err)
	}
	b, err := rep.Sigma()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("sigma export must be byte-stable for a fixed report")
	}
}

func TestSigmaGolden(t *testing.T) {
	rep := build(t, fixtureResult(), finding.SeverityHigh)
	data, err := rep.Sigma()
	if err != nil {
		t.Fatalf("sigma: %v", err)
	}
	golden := filepath.Join("testdata", "findings.sigma.yml")
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("reading golden (run go test -update to create): %v", err)
	}
	if string(want) != string(data) {
		t.Fatalf("sigma golden mismatch:\n--- want ---\n%s\n--- got ---\n%s", want, data)
	}
}

func TestStableSigmaID(t *testing.T) {
	t.Parallel()
	a := stableSigmaID("org/name")
	b := stableSigmaID("org/name")
	c := stableSigmaID("org/other")
	if a != b {
		t.Fatal("same seed must yield same id")
	}
	if a == c {
		t.Fatal("different seed must yield different id")
	}
	if len(a) != 36 {
		t.Fatalf("id = %q", a)
	}
}

func TestYQEscaping(t *testing.T) {
	t.Parallel()
	if got := yq("it's"); got != "'it''s'" {
		t.Fatalf("yq = %q", got)
	}
	if got := yq("plain: value"); got != "'plain: value'" {
		t.Fatalf("yq colon = %q", got)
	}
}
