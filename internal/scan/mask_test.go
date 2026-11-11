package scan

import (
	"bytes"
	"strings"
	"testing"
)

// maskLines reports whether a and b have identical newline positions and length.
func sameShape(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if (a[i] == '\n') != (b[i] == '\n') {
			return false
		}
	}
	return true
}

func TestMaskPythonPreservesShape(t *testing.T) {
	t.Parallel()
	cases := []string{
		"import os\nos.system('id')\n",
		"x = 'os.system('\n",
		"# eval(\nimport os\n",
		"a = '''multi\nline os.system(\n'''\n",
		"b = \"\"\"triple \"inside\" and \\\" end\"\"\"\n",
		"s = 'unterminated\ny = 1\n",
		"c = r'\\'os.system('\n",
		"f = rf\"value {x}\"\n",
		"z = 'esc\\\\' + 'q'\n",
		"# comment with 'quote and os.system(\n",
		"",
		"\n\n\n",
		"no strings at all",
	}
	for _, in := range cases {
		got := maskPython([]byte(in))
		if !sameShape([]byte(in), got) {
			t.Fatalf("shape changed for %q: got %q", in, got)
		}
	}
}

func TestMaskPythonBlanksStringsAndComments(t *testing.T) {
	t.Parallel()
	src := "import os  # os.system('x')\nmsg = 'os.system('\nt = \"eval(\"\n"
	out := maskPython([]byte(src))
	if !sameShape([]byte(src), out) {
		t.Fatalf("shape changed: got %q", out)
	}
	if bytes.Contains(out, []byte("os.system(")) {
		t.Fatalf("comment/string content leaked into masked text: %q", out)
	}
	if bytes.Contains(out, []byte("eval(")) {
		t.Fatalf("string literal content leaked into masked text: %q", out)
	}
	if !bytes.Contains(out, []byte("import os")) {
		t.Fatalf("code must remain visible: %q", out)
	}
}

func TestMaskPythonKeepsCodeIntact(t *testing.T) {
	t.Parallel()
	src := "os.system(cmd)  # trailing comment"
	out := maskPython([]byte(src))
	// Only the trailing comment is blanked; code and layout stay identical.
	want := "os.system(cmd)" + strings.Repeat(" ", len(src)-len("os.system(cmd)"))
	if string(out) != want {
		t.Fatalf("masked = %q, want %q", out, want)
	}
}

func FuzzMaskPython(f *testing.F) {
	seeds := []string{
		"import os\nos.system('id')\n",
		"x = '''a\nb''' \n",
		"# comment \n\"unterminated",
		"'\\",
		"\"\"\"\\",
		"r'\\'' + \"\\\"\"",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		out := maskPython(src)
		if !sameShape(src, out) {
			t.Fatalf("shape changed for %q", src)
		}
	})
}
