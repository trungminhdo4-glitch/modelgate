package scan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/trung-dev/modelgate/internal/finding"
)

// pyRule describes one static detection rule for Python source.
//
// Structural rules run on masked source (strings and comments blanked out),
// Raw rules run on the original source where string content matters (for
// example exfiltration endpoints embedded in literals).
type pyRule struct {
	ID          string
	Title       string
	Severity    finding.Severity
	Structural  []*regexp.Regexp
	Raw         []*regexp.Regexp
	Filter      func(src []byte, start int) bool
	Remediation string
	References  []string
	Keywords    []string
	Attack      []string
}

// pyRules is the complete ModelGate pattern catalogue. Every entry is a
// detection signature only: nothing here is executable against a target.
var pyRules = []pyRule{
	{
		ID:       "MG-CMD-001",
		Title:    "Shell command execution via the os module",
		Severity: finding.SeverityCritical,
		Structural: []*regexp.Regexp{
			regexp.MustCompile(`\bos\.(system|popen)\s*\(`),
			regexp.MustCompile(`\bos\.exec\w*\s*\(`),
			regexp.MustCompile(`\bos\.spawn\w*\s*\(`),
		},
		Remediation: "Remove OS command execution from model code, or vendor and review the file before enabling trust_remote_code.",
		References:  []string{"https://cwe.mitre.org/data/definitions/78.html", "https://attack.mitre.org/techniques/T1059/006/"},
		Keywords:    []string{"os.system(", "os.popen(", "os.exec"},
		Attack:      []string{"attack.t1059.006"},
	},
	{
		ID:       "MG-CMD-002",
		Title:    "Shell command execution via subprocess",
		Severity: finding.SeverityCritical,
		Structural: []*regexp.Regexp{
			regexp.MustCompile(`\bsubprocess\.(Popen|run|call|check_output|check_call|getoutput|getstatusoutput)\s*\(`),
		},
		Remediation: "Remove subprocess calls from model code, or vendor and review the file before enabling trust_remote_code.",
		References:  []string{"https://cwe.mitre.org/data/definitions/78.html", "https://attack.mitre.org/techniques/T1059/006/"},
		Keywords:    []string{"subprocess.Popen(", "subprocess.run(", "subprocess.check_output("},
		Attack:      []string{"attack.t1059.006"},
	},
	{
		ID:       "MG-EXEC-001",
		Title:    "Dynamic evaluation via eval()",
		Severity: finding.SeverityCritical,
		Structural: []*regexp.Regexp{
			regexp.MustCompile(`\beval\s*\(`),
		},
		Filter:      builtinCallFilter("eval"),
		Remediation: "Remove eval(); use explicit parsing. Legitimate method calls such as model.eval() are ignored by this rule.",
		References:  []string{"https://cwe.mitre.org/data/definitions/95.html", "https://attack.mitre.org/techniques/T1059/006/"},
		Keywords:    []string{"eval(", "builtins.eval("},
		Attack:      []string{"attack.t1059.006"},
	},
	{
		ID:       "MG-EXEC-002",
		Title:    "Dynamic execution via exec()",
		Severity: finding.SeverityCritical,
		Structural: []*regexp.Regexp{
			regexp.MustCompile(`\bexec\s*\(`),
		},
		Filter:      builtinCallFilter("exec"),
		Remediation: "Remove exec(); load code through reviewed modules only.",
		References:  []string{"https://cwe.mitre.org/data/definitions/95.html", "https://attack.mitre.org/techniques/T1059/006/"},
		Keywords:    []string{"exec(", "builtins.exec("},
		Attack:      []string{"attack.t1059.006"},
	},
	{
		ID:       "MG-EXEC-003",
		Title:    "Dynamic import via __import__()",
		Severity: finding.SeverityHigh,
		Structural: []*regexp.Regexp{
			regexp.MustCompile(`\b__import__\s*\(`),
		},
		Remediation: "Replace __import__() with static imports so dependencies are reviewable.",
		References:  []string{"https://cwe.mitre.org/data/definitions/470.html"},
		Keywords:    []string{"__import__("},
		Attack:      []string{"attack.t1059.006"},
	},
	{
		ID:       "MG-ENC-001",
		Title:    "Base64 payload decoding",
		Severity: finding.SeverityHigh,
		Structural: []*regexp.Regexp{
			regexp.MustCompile(`\bb64decode\s*\(`),
			regexp.MustCompile(`\bbase64\.decodebytes\s*\(`),
			regexp.MustCompile(`\bbinascii\.a2b_base64\s*\(`),
		},
		Remediation: "Review the decoded blob. Encoded payloads inside remote model code are a documented malware pattern.",
		References:  []string{"https://cwe.mitre.org/data/definitions/506.html"},
		Keywords:    []string{"b64decode(", "base64.b64decode(", "binascii.a2b_base64("},
		Attack:      []string{"attack.t1059.006"},
	},
	{
		ID:          "MG-ENC-002",
		Title:       "Base64-decoded data handed to the interpreter",
		Severity:    finding.SeverityCritical,
		Remediation: "This combination (encoded blob + eval/exec in one file) almost never appears in legitimate model code. Do not load this revision.",
		References:  []string{"https://cwe.mitre.org/data/definitions/95.html"},
		Keywords:    []string{"b64decode(", "eval(", "exec("},
		Attack:      []string{"attack.t1059.006"},
	},
	{
		ID:       "MG-NET-001",
		Title:    "Outbound data transmission (exfiltration path)",
		Severity: finding.SeverityHigh,
		Structural: []*regexp.Regexp{
			regexp.MustCompile(`\brequests\.(post|put|patch)\s*\(`),
			regexp.MustCompile(`\bhttpx\.(post|put|patch)\s*\(`),
			regexp.MustCompile(`\bhttp\.client\.(HTTP|HTTPS)Connection\s*\(`),
			regexp.MustCompile(`\.sendmail\s*\(`),
			regexp.MustCompile(`\.storbinary\s*\(`),
			regexp.MustCompile(`\.storlines\s*\(`),
			regexp.MustCompile(`\.sendall\s*\(`),
		},
		Remediation: "Model code must not send data outbound. Remove the call or block egress for the loading process.",
		References:  []string{"https://attack.mitre.org/techniques/T1041/", "https://cwe.mitre.org/data/definitions/200.html"},
		Keywords:    []string{"requests.post(", "httpx.post(", ".sendmail(", ".storbinary("},
		Attack:      []string{"attack.t1041"},
	},
	{
		ID:       "MG-NET-002",
		Title:    "Outbound network client usage",
		Severity: finding.SeverityMedium,
		Structural: []*regexp.Regexp{
			regexp.MustCompile(`\burllib\.request\.urlopen\s*\(`),
			regexp.MustCompile(`\bsocket\.socket\s*\(`),
			regexp.MustCompile(`\baiohttp\.ClientSession\s*\(`),
			regexp.MustCompile(`\bhttpx\.AsyncClient\s*\(`),
			regexp.MustCompile(`\bftplib\.FTP\s*\(`),
			regexp.MustCompile(`\bsmtplib\.SMTP\b`),
		},
		Remediation: "Confirm the network access is required for model operation; prefer offline artifacts.",
		References:  []string{"https://attack.mitre.org/techniques/T1095/"},
		Keywords:    []string{"urllib.request.urlopen(", "socket.socket(", "aiohttp.ClientSession("},
		Attack:      []string{"attack.t1095"},
	},
	{
		ID:       "MG-NET-003",
		Title:    "Hard-coded exfiltration or paste endpoint",
		Severity: finding.SeverityHigh,
		Raw: []*regexp.Regexp{
			regexp.MustCompile(`(?i)discord(?:app)?\.com/api/webhooks/`),
			regexp.MustCompile(`(?i)hooks\.slack\.com/services/`),
			regexp.MustCompile(`(?i)webhook\.site`),
			regexp.MustCompile(`(?i)pipedream\.net`),
			regexp.MustCompile(`(?i)transfer\.sh`),
			regexp.MustCompile(`(?i)pastebin\.com/api`),
			regexp.MustCompile(`(?i) requestbin`),
		},
		Remediation: "Do not load model code that embeds a data-drop endpoint.",
		References:  []string{"https://attack.mitre.org/techniques/T1041/"},
		Keywords:    []string{"discord.com/api/webhooks", "hooks.slack.com/services", "webhook.site"},
		Attack:      []string{"attack.t1041"},
	},
	{
		ID:       "MG-DESER-001",
		Title:    "Unsafe deserialization (pickle/marshal/shelve)",
		Severity: finding.SeverityHigh,
		Structural: []*regexp.Regexp{
			regexp.MustCompile(`\b(?:c?Pickle|pickle)\.loads?\s*\(`),
			regexp.MustCompile(`\bmarshal\.loads\s*\(`),
			regexp.MustCompile(`\bshelve\.open\s*\(`),
		},
		Remediation: "Pickle-family loaders can execute arbitrary code from the file. Load weights with safe formats or verify signatures first.",
		References:  []string{"https://cwe.mitre.org/data/definitions/502.html"},
		Keywords:    []string{"pickle.loads(", "marshal.loads(", "shelve.open("},
		Attack:      []string{"attack.t1562.001"},
	},
	{
		ID:       "MG-DESER-002",
		Title:    "torch.load without safe weights loading",
		Severity: finding.SeverityMedium,
		Structural: []*regexp.Regexp{
			regexp.MustCompile(`\btorch\.load\s*\(`),
		},
		Remediation: "Call torch.load(..., weights_only=True) so pickled code paths are not reachable.",
		References:  []string{"https://cwe.mitre.org/data/definitions/502.html"},
		Keywords:    []string{"torch.load("},
		Attack:      []string{"attack.t1562.001"},
	},
	{
		ID:       "MG-LIB-001",
		Title:    "Native library loading via ctypes",
		Severity: finding.SeverityMedium,
		Structural: []*regexp.Regexp{
			regexp.MustCompile(`\bctypes\.(CDLL|WinDLL|windll|cdll)\s*\(`),
		},
		Remediation: "Review why the model loads native libraries at runtime.",
		References:  []string{"https://cwe.mitre.org/data/definitions/114.html"},
		Keywords:    []string{"ctypes.CDLL(", "ctypes.windll("},
		Attack:      []string{"attack.t1106"},
	},
}

// builtinCallFilter accepts a bare call like eval(...) but ignores method
// calls such as model.eval() or cursor.exec(...), which are common in
// legitimate code. Only an explicit builtins receiver counts.
func builtinCallFilter(name string) func(src []byte, start int) bool {
	allowed := map[string]bool{"builtins": true, "__builtins__": true}
	return func(src []byte, start int) bool {
		p := start - 1
		for p >= 0 && (src[p] == ' ' || src[p] == '\t') {
			p--
		}
		if p < 0 || src[p] != '.' {
			return true // bare call
		}
		q := p - 1
		for q >= 0 && (isIdentByte(src[q]) || src[q] == '.') {
			q--
		}
		receiver := string(src[q+1 : p])
		return allowed[receiver]
	}
}

func isIdentByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// RuleInfo is the read-only view of a rule used by the `rules` command and
// the Sigma export.
type RuleInfo struct {
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Severity    finding.Severity `json:"severity"`
	Remediation string           `json:"remediation"`
	References  []string         `json:"references,omitempty"`
	Keywords    []string         `json:"keywords,omitempty"`
	Attack      []string         `json:"attack,omitempty"`
}

// Rules returns a copy of the rule catalogue in stable ID order.
func Rules() []RuleInfo {
	out := make([]RuleInfo, 0, len(pyRules))
	for _, r := range pyRules {
		out = append(out, RuleInfo{
			ID: r.ID, Title: r.Title, Severity: r.Severity,
			Remediation: r.Remediation,
			References:  append([]string(nil), r.References...),
			Keywords:    append([]string(nil), r.Keywords...),
			Attack:      append([]string(nil), r.Attack...),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// AnalyzePython runs every static rule over one Python file. The file is
// read as bytes only; it is never parsed by an interpreter, imported, or
// executed in any form.
func AnalyzePython(path string, src []byte) []finding.Finding {
	if len(src) == 0 {
		return nil
	}
	masked := maskPython(src)
	lines := newLineIndex(src)

	var out []finding.Finding
	seen := map[string]bool{}
	add := func(f finding.Finding) {
		if seen[f.Rule] {
			return
		}
		seen[f.Rule] = true
		out = append(out, f)
	}

	var hitEnc, hitEval, hitExec bool
	for _, rule := range pyRules {
		if rule.ID == "MG-ENC-002" {
			continue // chain rule is evaluated after the individual rules
		}
		count, first := matchRule(rule, src, masked)
		if count == 0 {
			continue
		}
		switch rule.ID {
		case "MG-ENC-001":
			hitEnc = true
		case "MG-EXEC-001":
			hitEval = true
		case "MG-EXEC-002":
			hitExec = true
		}
		line := lines.lineAt(first)
		add(finding.Finding{
			Rule:        rule.ID,
			Severity:    rule.Severity,
			Title:       rule.Title,
			Message:     fmt.Sprintf("%s: %d occurrence(s) in this file.", rule.Title, count),
			File:        path,
			Line:        line,
			Evidence:    lines.excerpt(src, line),
			Remediation: rule.Remediation,
			References:  append([]string(nil), rule.References...),
		})
	}
	if hitEnc && (hitEval || hitExec) {
		add(finding.Finding{
			Rule:        "MG-ENC-002",
			Severity:    finding.SeverityCritical,
			Title:       "Base64-decoded data handed to the interpreter",
			Message:     "Base64 decoding combined with eval()/exec() in one file indicates an obfuscated code path.",
			File:        path,
			Remediation: "Do not load this revision; report the model to the vendor and upstream host.",
			References:  []string{"https://cwe.mitre.org/data/definitions/95.html"},
		})
	}
	return out
}

// matchRule returns the number of matches and the index of the first match
// across structural (masked) and raw (string content) patterns.
func matchRule(rule pyRule, src, masked []byte) (int, int) {
	count := 0
	first := -1
	consider := func(idx int) {
		count++
		if first == -1 || idx < first {
			first = idx
		}
	}
	for _, re := range rule.Structural {
		for _, loc := range re.FindAllIndex(masked, -1) {
			if rule.Filter != nil && !rule.Filter(masked, loc[0]) {
				continue
			}
			consider(loc[0])
		}
	}
	for _, re := range rule.Raw {
		for _, loc := range re.FindAllIndex(src, -1) {
			consider(loc[0])
		}
	}
	return count, first
}

// lineIndex maps byte offsets to 1-based line numbers and excerpts.
type lineIndex struct {
	starts []int // byte offset of the start of each line
}

func newLineIndex(src []byte) *lineIndex {
	starts := []int{0}
	for i, c := range src {
		if c == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &lineIndex{starts: starts}
}

func (l *lineIndex) lineAt(offset int) int {
	if offset < 0 {
		return 0
	}
	// Binary search: last start <= offset.
	lo, hi := 0, len(l.starts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if l.starts[mid] <= offset {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1
}

const maxEvidence = 200

// excerpt returns the 1-based line trimmed and length-capped for reporting.
func (l *lineIndex) excerpt(src []byte, line int) string {
	if line < 1 || line > len(l.starts) {
		return ""
	}
	start := l.starts[line-1]
	end := len(src)
	if line < len(l.starts) {
		end = l.starts[line]
	}
	text := strings.TrimRight(string(src[start:end]), "\r\n")
	text = strings.ReplaceAll(text, "\t", " ")
	if len(text) > maxEvidence {
		// Cut on a rune boundary so the appended ellipsis cannot split a
		// multi-byte character (invalid UTF-8 would break JSON reports).
		cut := maxEvidence
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		text = text[:cut] + "…"
	}
	return strings.TrimSpace(text)
}
