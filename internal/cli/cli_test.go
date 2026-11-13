package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/trungminhdo4-glitch/modelgate/internal/hf"
	"github.com/trungminhdo4-glitch/modelgate/internal/testserver"
)

const (
	fixtureRev = "rev01abcdef01abcdef01abcdef01abcdef01"
	testdata   = ".." + string(filepath.Separator) + ".." + string(filepath.Separator) + "testdata"
)

var errBoom = errors.New("boom")

type deadlineFetcher struct {
	hf.Fetcher
	metaDeadline time.Time
	treeDeadline time.Time
}

func (f *deadlineFetcher) Meta(ctx context.Context, _, _, _ string) (*hf.Meta, error) {
	f.metaDeadline, _ = ctx.Deadline()
	return &hf.Meta{Sha: fixtureRev}, nil
}

func (f *deadlineFetcher) Tree(ctx context.Context, _, _, _ string) ([]hf.TreeEntry, error) {
	f.treeDeadline, _ = ctx.Deadline()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(time.Second):
		return nil, errBoom
	}
}

func TestCheckTimeoutIsSharedAcrossRequests(t *testing.T) {
	app, out, errBuf := newTestApp(t)
	fetcher := &deadlineFetcher{}
	app.NewFetcher = func(_ string, _ time.Duration) (hf.Fetcher, error) {
		return fetcher, nil
	}
	code := run(t, app, "check", "fixture/benign", "--timeout", "10ms")
	if code != ExitError || out.Len() != 0 || !strings.Contains(errBuf.String(), "deadline exceeded") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, out, errBuf)
	}
	if fetcher.metaDeadline.IsZero() || !fetcher.metaDeadline.Equal(fetcher.treeDeadline) {
		t.Fatalf("metadata deadline %v, tree deadline %v", fetcher.metaDeadline, fetcher.treeDeadline)
	}
}

func TestCheckRejectsNonPositiveTimeoutBeforeCreatingFetcher(t *testing.T) {
	for _, timeout := range []string{"0", "-1s"} {
		t.Run(timeout, func(t *testing.T) {
			app, _, errBuf := newTestApp(t)
			app.NewFetcher = func(_ string, _ time.Duration) (hf.Fetcher, error) {
				t.Fatal("invalid timeout reached fetcher creation")
				return nil, errBoom
			}
			if code := run(t, app, "check", "fixture/benign", "--timeout", timeout); code != ExitError {
				t.Fatalf("exit=%d stderr=%q", code, errBuf)
			}
			if !strings.Contains(errBuf.String(), "--timeout") {
				t.Fatalf("timeout error missing: %s", errBuf)
			}
		})
	}
}

func newTestApp(t *testing.T) (*App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	out, errBuf := &bytes.Buffer{}, &bytes.Buffer{}
	app := &App{
		Out:     out,
		Err:     errBuf,
		Version: "1.0.0-test",
		Now:     func() time.Time { return time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC) },
		NewFetcher: func(baseURL string, timeout time.Duration) (hf.Fetcher, error) {
			return hf.NewClient(baseURL, timeout)
		},
	}
	return app, out, errBuf
}

func run(t *testing.T, app *App, args ...string) int {
	t.Helper()
	return app.Run(context.Background(), args)
}

func fixture(t *testing.T, dir, repoType, id string) *testserver.Server {
	t.Helper()
	cfg, err := testserver.FromDir(repoType, id, fixtureRev, filepath.Join(testdata, "hf", dir))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	srv, err := testserver.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckBenignModelExit0(t *testing.T) {
	srv := fixture(t, "benign", "model", "fixture/benign")
	app, out, errBuf := newTestApp(t)

	code := run(t, app, "check", "fixture/benign", "--api-url", srv.URL())
	if code != ExitOK {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "ModelGate") || !strings.Contains(out.String(), "→ exit 0") {
		t.Fatalf("report missing:\n%s", out.String())
	}
	if !strings.Contains(errBuf.String(), "worst=") {
		t.Fatalf("summary missing: %s", errBuf.String())
	}
	if strings.Contains(errBuf.String(), "WARNING") {
		t.Fatalf("clean run must not warn: %s", errBuf.String())
	}
}

func TestCheckMaliciousModelExit1(t *testing.T) {
	srv := fixture(t, "malicious", "model", "fixture/malicious")
	app, out, errBuf := newTestApp(t)

	code := run(t, app, "check", "fixture/malicious", "--api-url", srv.URL())
	if code != ExitFindings {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	report := out.String()
	if !strings.Contains(report, "[CRITICAL] MG-CMD-001") {
		t.Fatalf("critical warning missing:\n%s", report)
	}
	if !strings.Contains(report, "remote_code.py:2") {
		t.Fatalf("file/line missing:\n%s", report)
	}
	if !strings.Contains(errBuf.String(), "WARNING: findings at or above fail-on") {
		t.Fatalf("stderr warning missing: %s", errBuf.String())
	}
}

func TestCheckSpyFixtureIsNeverExecuted(t *testing.T) {
	spyPath := filepath.Join(testdata, "spy", "remote_code_spy.py")
	marker := filepath.Join(testdata, "spy", "SPY_EXECUTED.marker")
	if err := os.Remove(marker); err != nil && !os.IsNotExist(err) {
		t.Fatalf("pre-clean: %v", err)
	}
	spy, err := os.ReadFile(spyPath)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := testserver.New(testserver.Config{
		ID:      "fixture/spy",
		Current: fixtureRev,
		Revisions: map[string][]testserver.File{fixtureRev: {
			{Path: "config.json", Content: []byte(`{"auto_map": {"AutoModel": "remote_code_spy.FixtureRemote"}}`)},
			{Path: "remote_code_spy.py", Content: spy},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	app, _, _ := newTestApp(t)
	run(t, app, "check", "fixture/spy", "--api-url", srv.URL())

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("SPY FIXTURE EXECUTED: ModelGate must never run model code")
	} else if !os.IsNotExist(err) {
		t.Fatalf("marker check: %v", err)
	}
}

// TestCheckUnknownTreeTypeStillAnalyzes is the regression for a hostile
// server labelling a Python file with an unknown tree type ("blob"): every
// entry that is not explicitly a directory must be treated as a file, or the
// content rules never run and a critical finding degrades to a clean exit.
func TestCheckUnknownTreeTypeStillAnalyzes(t *testing.T) {
	srv, err := testserver.New(testserver.Config{
		ID:      "fixture/oddtype",
		Current: fixtureRev,
		Revisions: map[string][]testserver.File{fixtureRev: {
			{Path: "config.json", Content: []byte(`{"auto_map": {"AutoModel": "remote_code.FixtureRemote"}}`)},
			{Path: "remote_code.py", Content: []byte("import os\nos.system('id')\n"), Type: "blob"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)

	app, out, errBuf := newTestApp(t)
	code := run(t, app, "check", "fixture/oddtype", "--api-url", srv.URL())
	if code != ExitFindings {
		t.Fatalf("unknown tree type must still be analyzed: exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "MG-CMD-001") {
		t.Fatalf("content rules never ran on the mislabelled file:\n%s", out.String())
	}
}

func TestCheckFormats(t *testing.T) {
	srv := fixture(t, "malicious", "model", "fixture/malicious")
	for _, format := range []string{"json", "sigma", "sarif"} {
		t.Run(format, func(t *testing.T) {
			app, out, _ := newTestApp(t)
			code := run(t, app, "check", "fixture/malicious", "--api-url", srv.URL(), "--format", format)
			if code != ExitFindings {
				t.Fatalf("exit = %d", code)
			}
			data := out.String()
			switch format {
			case "json":
				var decoded map[string]any
				if err := json.Unmarshal([]byte(data), &decoded); err != nil {
					t.Fatalf("invalid json: %v", err)
				}
				if decoded["schema_version"] != "1.0" {
					t.Fatalf("schema = %v", decoded["schema_version"])
				}
			case "sigma":
				if !strings.Contains(data, "condition: 1 of sel_*") {
					t.Fatalf("sigma output wrong:\n%s", data)
				}
			case "sarif":
				var log struct {
					Version string `json:"version"`
				}
				if err := json.Unmarshal([]byte(data), &log); err != nil || log.Version != "2.1.0" {
					t.Fatalf("sarif invalid: %v %+v", err, log)
				}
			}
		})
	}
}

func TestCheckOutAndSbomWriteFilesOnlyOnRequest(t *testing.T) {
	srv := fixture(t, "benign", "model", "fixture/benign")
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	sbomPath := filepath.Join(dir, "sbom.json")

	app, out, _ := newTestApp(t)
	code := run(t, app, "check", "fixture/benign", "--api-url", srv.URL(),
		"--format", "json", "--out", reportPath, "--sbom", sbomPath)
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout must stay empty when --out is used: %q", out.String())
	}
	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("report not written: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		t.Fatalf("report invalid: %v", err)
	}
	sbomBytes, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Fatalf("sbom not written: %v", err)
	}
	var bom map[string]any
	if err := json.Unmarshal(sbomBytes, &bom); err != nil {
		t.Fatalf("sbom invalid: %v", err)
	}
	if bom["bomFormat"] != "CycloneDX" || bom["specVersion"] != "1.6" {
		t.Fatalf("sbom header = %v %v", bom["bomFormat"], bom["specVersion"])
	}
}

func TestCheckFailOnMedium(t *testing.T) {
	srv := fixture(t, "benign", "model", "fixture/benign")
	app, _, _ := newTestApp(t)
	if code := run(t, app, "check", "fixture/benign", "--api-url", srv.URL()); code != ExitOK {
		t.Fatalf("default gate exit = %d", code)
	}
	app2, _, _ := newTestApp(t)
	if code := run(t, app2, "check", "fixture/benign", "--api-url", srv.URL(), "--fail-on", "medium"); code != ExitFindings {
		t.Fatalf("strict gate exit = %d, want 1", code)
	}
}

func TestCheckPinFlag(t *testing.T) {
	srv := fixture(t, "benign", "model", "fixture/benign")
	app, out, _ := newTestApp(t)
	code := run(t, app, "check", "fixture/benign", "--api-url", srv.URL(), "--pin", fixtureRev)
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out.String(), "Pinned") {
		t.Fatalf("pin info missing:\n%s", out.String())
	}
}

func TestUsageErrors(t *testing.T) {
	srv := fixture(t, "benign", "model", "fixture/benign")
	cases := [][]string{
		{},
		{"check"},
		{"check", "a", "b"},
		{"check", "../evil", "--api-url", srv.URL()},
		{"check", "fixture/benign", "--api-url", srv.URL(), "--format", "xml"},
		{"check", "fixture/benign", "--api-url", srv.URL(), "--fail-on", "bogus"},
		{"check", "fixture/benign", "--api-url", "ftp://x"},
		{"unknown-command"},
	}
	for _, args := range cases {
		app, _, _ := newTestApp(t)
		if code := run(t, app, args...); code != ExitError {
			t.Errorf("args %v: exit = %d, want 2", args, code)
		}
	}
}

func TestHelpAndVersion(t *testing.T) {
	app, out, errBuf := newTestApp(t)
	if code := run(t, app, "version"); code != ExitOK {
		t.Fatalf("version exit = %d", code)
	}
	if !strings.Contains(out.String(), "modelgate 1.0.0-test") {
		t.Fatalf("version output = %q", out.String())
	}
	if code := run(t, app, "help"); code != ExitOK {
		t.Fatalf("help exit = %d", code)
	}
	if !strings.Contains(errBuf.String(), "modelgate check <repo-id>") {
		t.Fatalf("usage missing: %s", errBuf.String())
	}
	if code := run(t, app, "check", "-h"); code != ExitOK {
		t.Fatalf("check -h exit = %d", code)
	}
}

func TestRulesCommand(t *testing.T) {
	app, out, _ := newTestApp(t)
	if code := run(t, app, "rules"); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out.String(), "MG-CMD-001") {
		t.Fatalf("rules output = %q", out.String())
	}

	app2, out2, _ := newTestApp(t)
	if code := run(t, app2, "rules", "--format", "json"); code != ExitOK {
		t.Fatalf("json exit = %d", code)
	}
	var decoded []map[string]any
	if err := json.Unmarshal(out2.Bytes(), &decoded); err != nil {
		t.Fatalf("rules json invalid: %v", err)
	}
	if len(decoded) < 10 {
		t.Fatalf("rules = %d", len(decoded))
	}

	app3, _, _ := newTestApp(t)
	if code := run(t, app3, "rules", "--format", "yaml"); code != ExitError {
		t.Fatalf("bad format exit = %d", code)
	}
}

// newSplitFlagSet mirrors the flag shape of the check subcommand.
func newSplitFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})
	fs.String("format", "text", "")
	fs.String("api-url", "", "")
	fs.String("pin", "", "")
	fs.Bool("verbose", false, "")
	return fs
}

// TestSplitArgsReordersFlagsBeforePositionals is the regression test for
// "check <repo-id> --format json" silently ignoring every flag after the
// repo id (Go's flag package stops at the first positional argument).
func TestSplitArgsReordersFlagsBeforePositionals(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		args       []string
		wantFormat string
		wantArgs   []string
	}{
		{"flags already first", []string{"--format", "json", "repo"}, "json", []string{"repo"}},
		{"flag after repo id", []string{"repo", "--format", "json"}, "json", []string{"repo"}},
		{"attached value", []string{"repo", "--format=sigma"}, "sigma", []string{"repo"}},
		{"single dash", []string{"repo", "-format", "sarif"}, "sarif", []string{"repo"}},
		{"two positionals", []string{"a", "--format", "json", "b"}, "json", []string{"a", "b"}},
		{"value that looks like a flag", []string{"--pin", "-strange", "repo"}, "text", []string{"repo"}},
		{"terminator keeps weird positional", []string{"--format", "json", "--", "-x"}, "json", []string{"-x"}},
		{"terminator after repo id", []string{"repo", "--", "--weird"}, "text", []string{"repo", "--weird"}},
		{"no flags at all", []string{"repo"}, "text", []string{"repo"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newSplitFlagSet()
			if err := fs.Parse(splitArgs(fs, tc.args)); err != nil {
				t.Fatalf("parse(%v) via splitArgs: %v", tc.args, err)
			}
			if got := fs.Lookup("format").Value.String(); got != tc.wantFormat {
				t.Fatalf("format = %q, want %q", got, tc.wantFormat)
			}
			got := strings.Join(fs.Args(), "\x00")
			want := strings.Join(tc.wantArgs, "\x00")
			if got != want {
				t.Fatalf("positionals = %q, want %q (split = %v)", got, want, splitArgs(fs, tc.args))
			}
		})
	}
}

func TestSplitArgsBoolFlagDoesNotConsume(t *testing.T) {
	t.Parallel()
	fs := newSplitFlagSet()
	args := splitArgs(fs, []string{"repo", "--verbose", "extra"})
	if err := fs.Parse(args); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if fs.Lookup("verbose").Value.String() != "true" {
		t.Fatal("verbose must be set")
	}
	if got := strings.Join(fs.Args(), ","); got != "repo,extra" {
		t.Fatalf("positionals = %q, want repo,extra", got)
	}
}

// FuzzSplitArgs proves three invariants for arbitrary argv (encoded as a
// NUL-separated byte string): no token is created or destroyed, re-splitting
// an already reordered argv is a no-op, and parsing never panics.
func FuzzSplitArgs(f *testing.F) {
	for _, seed := range []string{
		"repo\x00--format\x00json",
		"--\x00-x",
		"",
		"-verbose\x00--pin=abc\x00repo",
		"a\x00--\x00--\x00b",
		"repo\x00--api-url\x00http://x\x00--format\x00xml",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		args := strings.Split(string(data), "\x00")
		once := splitArgs(newSplitFlagSet(), args)
		if len(once) != len(args) {
			t.Fatalf("token count changed: %v -> %v", args, once)
		}
		a := append([]string(nil), args...)
		b := append([]string(nil), once...)
		sort.Strings(a)
		sort.Strings(b)
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("token multiset changed: %v -> %v", args, once)
			}
		}
		twice := splitArgs(newSplitFlagSet(), once)
		if len(twice) != len(once) {
			t.Fatalf("re-split changed length: %v -> %v", once, twice)
		}
		for i := range once {
			if twice[i] != once[i] {
				t.Fatalf("split not idempotent: %v -> %v -> %v", args, once, twice)
			}
		}
		// Parsing must never panic; flag errors (unknown flags, missing
		// values, -h) are legitimate outcomes for arbitrary input.
		_ = newSplitFlagSet().Parse(once)
	})
}

func TestFetcherFactoryErrorExits2(t *testing.T) {
	app, _, errBuf := newTestApp(t)
	app.NewFetcher = func(string, time.Duration) (hf.Fetcher, error) {
		return nil, errBoom
	}
	if code := run(t, app, "check", "fixture/benign"); code != ExitError {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(errBuf.String(), "fixture") && !strings.Contains(errBuf.String(), "boom") {
		t.Fatalf("error not reported: %s", errBuf.String())
	}
}

// TestNoWriteWithoutExplicitFlags hashes the whole testdata tree before and
// after a full check run: the tool must not modify any file on disk.
func TestNoWriteWithoutExplicitFlags(t *testing.T) {
	before, err := hashTree(testdata)
	if err != nil {
		t.Fatal(err)
	}
	srv := fixture(t, "malicious", "model", "fixture/malicious")
	app, _, _ := newTestApp(t)
	if code := run(t, app, "check", "fixture/malicious", "--api-url", srv.URL()); code != ExitFindings {
		t.Fatalf("exit = %d", code)
	}
	after, err := hashTree(testdata)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("check modified files under testdata")
	}
	if _, err := os.Stat(filepath.Join(testdata, "spy", "SPY_EXECUTED.marker")); err == nil {
		t.Fatal("spy marker exists after check")
	}
}

func hashTree(root string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		h.Write([]byte(rel))
		h.Write([]byte{0})
		h.Write(content)
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// TestRequestsAreGetOnly proves the read-only client never mutates the remote.
func TestRequestsAreGetOnly(t *testing.T) {
	srv := fixture(t, "malicious", "model", "fixture/malicious")
	app, _, _ := newTestApp(t)
	run(t, app, "check", "fixture/malicious", "--api-url", srv.URL())
	if got := srv.NonGET(); len(got) != 0 {
		t.Fatalf("non-GET requests observed: %v", got)
	}
	if len(srv.Methods()) == 0 {
		t.Fatal("fixture received no requests")
	}
}

// TestNoExecImport is the read-only-by-construction guard: no production Go
// file may import os/exec or call exec.Command, so model code can never be
// handed to an interpreter.
func TestNoExecImport(t *testing.T) {
	roots := []string{
		filepath.Join("..", "..", "cmd"),
		filepath.Join("..", "..", "internal"),
	}
	forbidden := []string{`"os/exec"`, "exec.Command("}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, needle := range forbidden {
				if strings.Contains(string(content), needle) {
					t.Errorf("%s contains forbidden %q", path, needle)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestAcceptanceLiveHuggingFace is the optional live acceptance run against
// the real Hugging Face API. It is skipped unless MODELGATE_LIVE=1.
func TestAcceptanceLiveHuggingFace(t *testing.T) {
	if os.Getenv("MODELGATE_LIVE") != "1" {
		t.Skip("live acceptance disabled; set MODELGATE_LIVE=1 to run")
	}
	app, out, errBuf := newTestApp(t)
	code := run(t, app, "check", "sentence-transformers/all-MiniLM-L6-v2")
	if code != ExitOK {
		t.Fatalf("known-harmless model exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
}
