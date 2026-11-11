package report

import (
	"crypto/sha1"
	"fmt"
	"sort"
	"strings"

	"github.com/trungminhdo4-glitch/modelgate/internal/scan"
)

// Sigma renders the ModelGate rule catalogue as a Sigma YAML rule. The rule
// is a detection artefact for reviewing Python files in cloned repositories;
// it contains signatures only, never executable content.
func (r *Report) Sigma() ([]byte, error) {
	rules := scan.Rules()
	author := "trung-dev"
	date := r.Analysis.GeneratedAt.Format("2006-01-02")

	var b strings.Builder
	title := fmt.Sprintf("ModelGate dangerous pattern catalogue - %s", r.Repo.ID)
	fmt.Fprintf(&b, "title: %s\n", yq(title))
	fmt.Fprintf(&b, "id: %s\n", stableSigmaID(r.Repo.ID))
	b.WriteString("status: experimental\n")
	desc := fmt.Sprintf(
		"Static detection catalogue emitted by ModelGate %s after checking %s at revision %s. "+
			"The keywords are review signatures for Hugging Face repository source files; the rule is meant for "+
			"log or file scanning pipelines and is not executable against any system.",
		r.Tool.Version, r.Repo.ID, short(r.Repo.Revision),
	)
	fmt.Fprintf(&b, "description: %s\n", yq(desc))
	b.WriteString("references:\n")
	fmt.Fprintf(&b, "  - %s\n", yq(r.Tool.Homepage))
	fmt.Fprintf(&b, "  - %s\n", yq(r.Repo.URL))
	fmt.Fprintf(&b, "author: %s\n", yq(author))
	fmt.Fprintf(&b, "date: %s\n", date)
	b.WriteString("tags:\n")
	for _, t := range attackTags(rules) {
		fmt.Fprintf(&b, "  - %s\n", t)
	}
	b.WriteString("logsource:\n")
	b.WriteString("  category: file_scan\n")
	b.WriteString("  product: modelgate\n")
	b.WriteString("detection:\n")
	for _, rule := range rules {
		if len(rule.Keywords) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  sel_%s:\n", selName(rule.ID))
		for _, kw := range rule.Keywords {
			fmt.Fprintf(&b, "    - %s\n", yq(kw))
		}
	}
	b.WriteString("  condition: 1 of sel_*\n")
	b.WriteString("falsepositives:\n")
	b.WriteString("  - Reviewed research code that legitimately uses dynamic evaluation\n")
	b.WriteString("  - Vendor model code that was audited and pinned by the consumer\n")
	b.WriteString("level: high\n")
	return []byte(b.String()), nil
}

// selName converts "MG-CMD-001" into a Sigma-safe selection name.
func selName(ruleID string) string {
	s := strings.ToLower(ruleID)
	s = strings.ReplaceAll(s, "-", "_")
	return strings.NewReplacer(".", "_", " ", "_").Replace(s)
}

// yq renders a YAML single-quoted scalar. Single quotes are doubled; no
// escape sequence interpretation can happen inside the scalar.
func yq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// attackTags collects the sorted, deduplicated ATT&CK tags of all rules.
func attackTags(rules []scan.RuleInfo) []string {
	seen := map[string]bool{}
	var out []string
	for _, rule := range rules {
		for _, t := range rule.Attack {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

// stableSigmaID derives a deterministic RFC 4122 version-5 style UUID from
// the repository id so repeated exports of the same repo are byte-identical.
func stableSigmaID(seed string) string {
	sum := sha1.Sum([]byte("modelgate:sigma:" + seed))
	b := sum[:]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
