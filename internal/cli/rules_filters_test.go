package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/trungminhdo4-glitch/modelgate/internal/hf"
	"github.com/trungminhdo4-glitch/modelgate/internal/scan"
)

func TestRulesFilters(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"exact-id", []string{"--id", "MG-CMD-001"}, []string{"MG-CMD-001"}},
		{"critical", []string{"--min-severity", "critical"}, []string{"MG-CMD-001", "MG-CMD-002", "MG-ENC-002", "MG-EXEC-001", "MG-EXEC-002"}},
		{"combined", []string{"--id=MG-EXEC-003", "--min-severity=HIGH"}, []string{"MG-EXEC-003"}},
		{"no-match", []string{"--id", "MG-EXEC-003", "--min-severity", "critical"}, []string{}},
	} {
		for _, format := range []string{"text", "json"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				app, out, errBuf := newTestApp(t)
				app.NewFetcher = func(string, time.Duration) (hf.Fetcher, error) {
					t.Fatal("rules must remain offline")
					return nil, errBoom
				}
				args := append([]string{"rules", "--format", format}, tc.args...)
				if code := run(t, app, args...); code != ExitOK || errBuf.Len() != 0 {
					t.Fatalf("exit=%d stderr=%q", code, errBuf)
				}
				var ids []string
				if format == "json" {
					var rules []scan.RuleInfo
					if err := json.Unmarshal(out.Bytes(), &rules); err != nil || rules == nil {
						t.Fatalf("expected JSON array: %s (%v)", out, err)
					}
					for _, rule := range rules {
						ids = append(ids, rule.ID)
						if rule.Remediation == "" || len(rule.References) == 0 {
							t.Fatalf("rule detail lost: %+v", rule)
						}
					}
				} else {
					for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
						if fields := strings.Fields(line); len(fields) > 0 {
							ids = append(ids, fields[0])
						}
					}
				}
				if strings.Join(ids, ",") != strings.Join(tc.want, ",") {
					t.Fatalf("got IDs %v, want %v", ids, tc.want)
				}
			})
		}
	}
}

func TestRulesRejectInvalidFiltersAndPositionals(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--id", "MG-MISSING-999"}, "unknown rule ID"},
		{[]string{"--id", "mg-cmd-001"}, "unknown rule ID"},
		{[]string{"--id="}, "unknown rule ID"},
		{[]string{"--min-severity", "urgent"}, "--min-severity"},
		{[]string{"--min-severity="}, "--min-severity"},
		{[]string{"unexpected"}, "does not accept positional arguments"},
		{[]string{"--", "--id", "MG-CMD-001"}, "does not accept positional arguments"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			app, out, errBuf := newTestApp(t)
			if code := run(t, app, append([]string{"rules"}, tc.args...)...); code != ExitError || out.Len() != 0 || !strings.Contains(errBuf.String(), tc.want) {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, out, errBuf)
			}
		})
	}
}

func TestRulesFiltersPreserveDefaultCatalogue(t *testing.T) {
	app, out, errBuf := newTestApp(t)
	if code := run(t, app, "rules", "--format", "json"); code != ExitOK {
		t.Fatalf("exit=%d stderr=%q", code, errBuf)
	}
	original := out.String()
	out.Reset()
	if code := run(t, app, "rules", "--id", "MG-CMD-001"); code != ExitOK {
		t.Fatalf("filtered exit=%d stderr=%q", code, errBuf)
	}
	out.Reset()
	if code := run(t, app, "rules", "--format", "json", "--min-severity", "info"); code != ExitOK || out.String() != original {
		t.Fatalf("catalogue changed after filtering: exit=%d stderr=%q", code, errBuf)
	}
}
