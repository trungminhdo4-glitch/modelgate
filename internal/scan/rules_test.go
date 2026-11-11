package scan

import (
	"regexp"
	"strings"
	"testing"

	"github.com/trungminhdo4-glitch/modelgate/internal/finding"
)

func hasRule(fs []finding.Finding, rule string) bool {
	for _, f := range fs {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func ruleFor(fs []finding.Finding, rule string) finding.Finding {
	for _, f := range fs {
		if f.Rule == rule {
			return f
		}
	}
	return finding.Finding{}
}

func TestAnalyzePythonDetectsEachRule(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		code string
		rule string
	}{
		{"os_system", "import os\nos.system('id')\n", "MG-CMD-001"},
		{"os_popen", "import os\nhandle = os.popen('id')\n", "MG-CMD-001"},
		{"subprocess_popen", "import subprocess\nsubprocess.Popen(['id'])\n", "MG-CMD-002"},
		{"subprocess_run", "import subprocess\nsubprocess.run(['id'])\n", "MG-CMD-002"},
		{"eval_bare", "value = eval('1+1')\n", "MG-EXEC-001"},
		{"eval_builtin", "value = builtins.eval('1')\n", "MG-EXEC-001"},
		{"exec_bare", "exec('pass')\n", "MG-EXEC-002"},
		{"dunder_import", "mod = __import__('os')\n", "MG-EXEC-003"},
		{"b64decode", "import base64\nraw = base64.b64decode('aGk=')\n", "MG-ENC-001"},
		{"binascii", "import binascii\nraw = binascii.a2b_base64('aGk=')\n", "MG-ENC-001"},
		{"chain", "import base64\nraw = base64.b64decode('aGk=')\nexec(raw)\n", "MG-ENC-002"},
		{"requests_post", "import requests\nrequests.post('http://x.invalid', data={})\n", "MG-NET-001"},
		{"httpx_put", "import httpx\nhttpx.put('http://x.invalid', content=b'x')\n", "MG-NET-001"},
		{"sendmail", "client.sendmail('a@x.invalid', 'b@x.invalid', 'data')\n", "MG-NET-001"},
		{"storbinary", "ftp.storbinary('STOR x', handle)\n", "MG-NET-001"},
		{"urlopen", "import urllib.request\nurllib.request.urlopen('http://x.invalid')\n", "MG-NET-002"},
		{"socket", "import socket\nsock = socket.socket(socket.AF_INET)\n", "MG-NET-002"},
		{"webhook_string", "DROP = 'https://discord.com/api/webhooks/000000000000000000/x'\n", "MG-NET-003"},
		{"paste_endpoint", "url = 'https://pastebin.com/api/api_post.php'\n", "MG-NET-003"},
		{"pickle_loads", "import pickle\nobj = pickle.loads(blob)\n", "MG-DESER-001"},
		{"marshal_loads", "import marshal\nobj = marshal.loads(blob)\n", "MG-DESER-001"},
		{"torch_load", "import torch\nstate = torch.load('w.bin')\n", "MG-DESER-002"},
		{"ctypes_cdll", "import ctypes\nlib = ctypes.CDLL('x.dll')\n", "MG-LIB-001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fs := AnalyzePython("fixture.py", []byte(tc.code))
			if !hasRule(fs, tc.rule) {
				t.Fatalf("expected rule %s, got %+v", tc.rule, fs)
			}
			f := ruleFor(fs, tc.rule)
			if f.File != "fixture.py" {
				t.Fatalf("finding file = %q", f.File)
			}
			if f.Severity == "" || f.Remediation == "" || f.Title == "" {
				t.Fatalf("incomplete finding: %+v", f)
			}
		})
	}
}

func TestAnalyzePythonIgnoresMethodEval(t *testing.T) {
	t.Parallel()
	for _, code := range []string{
		"model.eval()\n",
		"self.eval()\n",
		"cursor.exec('select 1')\n",
	} {
		fs := AnalyzePython("fixture.py", []byte(code))
		if hasRule(fs, "MG-EXEC-001") || hasRule(fs, "MG-EXEC-002") {
			t.Fatalf("method call in %q wrongly flagged: %+v", code, fs)
		}
	}
}

func TestAnalyzePythonIgnoresCommentsAndStrings(t *testing.T) {
	t.Parallel()
	src := `# eval("os.system('id')")
"""docstring with subprocess.Popen(['id'])"""
text = "b64decode('aGk=') and requests.post('http://x.invalid')"
`
	fs := AnalyzePython("fixture.py", []byte(src))
	if len(fs) != 0 {
		t.Fatalf("expected no findings, got %+v", fs)
	}
}

func TestAnalyzePythonCleanFixtureHasNoFindings(t *testing.T) {
	t.Parallel()
	src := `"""Clean fixture model."""
import torch


class FixtureModel(torch.nn.Module):
    def evaluate_in_eval_mode(self):
        # eval("os.system('id')") in a comment must never fire
        self.eval()
        return self.config
`
	fs := AnalyzePython("modeling_clean.py", []byte(src))
	if len(fs) != 0 {
		t.Fatalf("expected zero findings, got %+v", fs)
	}
}

func TestAnalyzePythonLineAndEvidence(t *testing.T) {
	t.Parallel()
	src := "import os\n\nos.system('id')\n"
	fs := AnalyzePython("x.py", []byte(src))
	f := ruleFor(fs, "MG-CMD-001")
	if f.Line != 3 {
		t.Fatalf("line = %d, want 3", f.Line)
	}
	if !strings.Contains(f.Evidence, "os.system") {
		t.Fatalf("evidence = %q", f.Evidence)
	}
}

func TestAnalyzePythonDeduplicatesPerRule(t *testing.T) {
	t.Parallel()
	src := "import os\nos.system('a')\nos.system('b')\nos.system('c')\n"
	fs := AnalyzePython("x.py", []byte(src))
	n := 0
	for _, f := range fs {
		if f.Rule == "MG-CMD-001" {
			n++
			if !strings.Contains(f.Message, "3 occurrence(s)") {
				t.Fatalf("message = %q", f.Message)
			}
		}
	}
	if n != 1 {
		t.Fatalf("want exactly 1 finding, got %d", n)
	}
}

func TestAnalyzePythonEmptyInput(t *testing.T) {
	t.Parallel()
	if fs := AnalyzePython("x.py", nil); fs != nil {
		t.Fatalf("empty file must yield no findings: %+v", fs)
	}
}

func TestAnalyzePythonEvidenceIsLengthCapped(t *testing.T) {
	t.Parallel()
	long := "import os\nos.system('" + strings.Repeat("a", 500) + "')\n"
	fs := AnalyzePython("x.py", []byte(long))
	f := ruleFor(fs, "MG-CMD-001")
	if len(f.Evidence) > maxEvidence+3 { // +3 bytes for the "…" ellipsis in UTF-8
		t.Fatalf("evidence not capped: %d bytes", len(f.Evidence))
	}
}

func TestRulesCatalogueIsWellFormed(t *testing.T) {
	t.Parallel()
	rules := Rules()
	if len(rules) < 10 {
		t.Fatalf("rule catalogue too small: %d", len(rules))
	}
	idPattern := regexp.MustCompile(`^MG-[A-Z]+-\d{3}$`)
	seen := map[string]bool{}
	prev := ""
	for _, r := range rules {
		if !idPattern.MatchString(r.ID) {
			t.Fatalf("rule id %q does not follow MG-<CAT>-<NNN>", r.ID)
		}
		if seen[r.ID] {
			t.Fatalf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if prev != "" && r.ID < prev {
			t.Fatalf("rules not sorted: %q after %q", r.ID, prev)
		}
		prev = r.ID
		if _, err := r.Severity.Rank(); err != nil {
			t.Fatalf("rule %s: %v", r.ID, err)
		}
		if r.Title == "" || r.Remediation == "" {
			t.Fatalf("rule %s missing title/remediation", r.ID)
		}
		if len(r.Keywords) == 0 || len(r.References) == 0 || len(r.Attack) == 0 {
			t.Fatalf("rule %s missing keywords/references/attack tags", r.ID)
		}
	}
}

func TestRulesReturnsCopies(t *testing.T) {
	t.Parallel()
	first := Rules()
	first[0].Keywords[0] = "mutated"
	second := Rules()
	if second[0].Keywords[0] == "mutated" {
		t.Fatal("Rules() must return defensive copies")
	}
}

func FuzzAnalyzePython(f *testing.F) {
	f.Add([]byte("import os\nos.system('id')\n"))
	f.Add([]byte("# just a comment\n"))
	f.Add([]byte("x = '''\n'''\n"))
	f.Add([]byte{0x00, 0xff, 0x27, 0x22})
	f.Add([]byte("eval(exec(os.system")) // intentionally unclosed
	f.Fuzz(func(t *testing.T, src []byte) {
		fs := AnalyzePython("fuzz.py", src)
		for _, fi := range fs {
			if fi.Rule == "" {
				t.Fatal("finding without rule")
			}
			if _, err := fi.Severity.Rank(); err != nil {
				t.Fatalf("invalid severity: %v", err)
			}
			if fi.Line < 0 || fi.Remediation == "" {
				t.Fatalf("malformed finding: %+v", fi)
			}
			if fi.File != "fuzz.py" {
				t.Fatalf("wrong file: %q", fi.File)
			}
		}
	})
}
