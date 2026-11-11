package scan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trungminhdo4-glitch/modelgate/internal/finding"
	"github.com/trungminhdo4-glitch/modelgate/internal/hf"
	"github.com/trungminhdo4-glitch/modelgate/internal/testserver"
)

const fixtureRev = "rev01abcdef01abcdef01abcdef01abcdef01"

func fixture(t *testing.T, dir, repoType, id string) *testserver.Server {
	t.Helper()
	cfg, err := testserver.FromDir(repoType, id, fixtureRev, filepath.Join("..", "..", "testdata", "hf", dir))
	if err != nil {
		t.Fatalf("loading fixture %s: %v", dir, err)
	}
	return synth(t, cfg)
}

func synth(t *testing.T, cfg testserver.Config) *testserver.Server {
	t.Helper()
	srv, err := testserver.New(cfg)
	if err != nil {
		t.Fatalf("starting fixture server: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func fetcher(t *testing.T, srv *testserver.Server) hf.Fetcher {
	t.Helper()
	c, err := hf.NewClient(srv.URL(), 5*time.Second)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return c
}

func countAtLeast(fs []finding.Finding, min finding.Severity) int {
	n := 0
	for _, f := range fs {
		if ok, err := f.Severity.AtLeast(min); err == nil && ok {
			n++
		}
	}
	return n
}

func TestAnalyzeBenignModel(t *testing.T) {
	srv := fixture(t, "benign", "model", "fixture/benign")
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/benign"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if res.Revision != fixtureRev {
		t.Fatalf("revision = %q", res.Revision)
	}
	if len(res.AnalyzedFiles) != 1 || res.AnalyzedFiles[0] != "modeling_clean.py" {
		t.Fatalf("analyzed = %v", res.AnalyzedFiles)
	}
	if res.Trust.ConfigFlag || res.Trust.AutoMapCount != 1 || res.Trust.CardMentions != 0 {
		t.Fatalf("trust = %+v", res.Trust)
	}
	if n := countAtLeast(res.Findings, finding.SeverityHigh); n != 0 {
		t.Fatalf("benign fixture must have no high/critical findings: %+v", res.Findings)
	}
	if !hasRule(res.Findings, RuleAutoMap) {
		t.Fatalf("expected auto_map finding: %+v", res.Findings)
	}
	if got := srv.NonGET(); len(got) != 0 {
		t.Fatalf("client used non-GET requests: %v", got)
	}
}

func TestAnalyzeMaliciousModel(t *testing.T) {
	srv := fixture(t, "malicious", "model", "fixture/malicious")
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/malicious"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(res.AnalyzedFiles) != 1 || res.AnalyzedFiles[0] != "remote_code.py" {
		t.Fatalf("analyzed = %v", res.AnalyzedFiles)
	}
	want := []string{"MG-CMD-001", "MG-CMD-002", "MG-EXEC-002", "MG-ENC-001", "MG-ENC-002", "MG-NET-001", "MG-NET-003"}
	for _, rule := range want {
		if !hasRule(res.Findings, rule) {
			t.Errorf("missing rule %s in %+v", rule, res.Findings)
		}
	}
	if !res.Trust.ConfigFlag || res.Trust.CardMentions == 0 {
		t.Fatalf("trust surface not detected: %+v", res.Trust)
	}
	if countAtLeast(res.Findings, finding.SeverityCritical) == 0 {
		t.Fatal("expected critical findings")
	}
}

func TestAnalyzeDataset(t *testing.T) {
	srv := fixture(t, "dataset", "dataset", "fixture/dataset")
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{
		RepoType: "dataset",
		RepoID:   "fixture/dataset",
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !hasRule(res.Findings, RuleDatasetScript) {
		t.Fatalf("expected dataset script finding: %+v", res.Findings)
	}
	if len(res.AnalyzedFiles) != 1 || res.AnalyzedFiles[0] != "load_script.py" {
		t.Fatalf("analyzed = %v", res.AnalyzedFiles)
	}
	if !res.Trust.DatasetScripts {
		t.Fatal("trust.DatasetScripts not set")
	}
}

func TestAnalyzeMissingAutoMapTarget(t *testing.T) {
	srv := synth(t, testserver.Config{
		ID:      "fixture/missing",
		Current: fixtureRev,
		Revisions: map[string][]testserver.File{fixtureRev: {
			{Path: "config.json", Content: []byte(`{"auto_map": {"AutoModel": "ghost.Fixture"}}`)},
		}},
	})
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/missing"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !hasRule(res.Findings, RuleAutoMapMiss) {
		t.Fatalf("expected missing-target finding: %+v", res.Findings)
	}
	if len(res.AnalyzedFiles) != 0 {
		t.Fatalf("nothing should be analyzed: %v", res.AnalyzedFiles)
	}
}

func TestAnalyzeRejectsUnsafeAutoMapTarget(t *testing.T) {
	srv := synth(t, testserver.Config{
		ID:      "fixture/unsafe",
		Current: fixtureRev,
		Revisions: map[string][]testserver.File{fixtureRev: {
			{Path: "config.json", Content: []byte(`{"auto_map": {"AutoModel": "../../evil.Fixture"}}`)},
		}},
	})
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/unsafe"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !hasRule(res.Findings, RuleAutoMapUnsafe) {
		t.Fatalf("expected unsafe-target finding: %+v", res.Findings)
	}
	for _, p := range srv.Paths() {
		if strings.Contains(p, "..") {
			t.Fatalf("traversal reached the server: %s", p)
		}
	}
}

func TestAnalyzeLFSStoredTarget(t *testing.T) {
	srv := synth(t, testserver.Config{
		ID:      "fixture/lfs",
		Current: fixtureRev,
		Revisions: map[string][]testserver.File{fixtureRev: {
			{Path: "config.json", Content: []byte(`{"auto_map": {"AutoModel": "lfsmod.Fixture"}}`)},
			{
				Path:    "lfsmod.py",
				Content: []byte("version https://git-lfs.github.com/spec/v1\noid sha256:fixture\nsize 42\n"),
				LFSOID:  "fixture",
			},
		}},
	})
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/lfs"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !hasRule(res.Findings, RuleLFS) {
		t.Fatalf("expected LFS finding: %+v", res.Findings)
	}
	if len(res.AnalyzedFiles) != 0 {
		t.Fatalf("LFS target must not be analyzed: %v", res.AnalyzedFiles)
	}
}

func TestAnalyzeSkipsOversizedTarget(t *testing.T) {
	srv := synth(t, testserver.Config{
		ID:      "fixture/big",
		Current: fixtureRev,
		Revisions: map[string][]testserver.File{fixtureRev: {
			{Path: "config.json", Content: []byte(`{"auto_map": {"AutoModel": "bigmod.Fixture"}}`)},
			{Path: "bigmod.py", Content: []byte("x = 1\n"), Size: 2 << 20},
		}},
	})
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/big"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !hasRule(res.Findings, RuleLimit) {
		t.Fatalf("expected size-limit finding: %+v", res.Findings)
	}
	if len(res.AnalyzedFiles) != 0 {
		t.Fatalf("oversized file must not be analyzed: %v", res.AnalyzedFiles)
	}
	for _, p := range srv.Paths() {
		if filepath.Base(p) == "bigmod.py" {
			t.Fatalf("oversized file must not be fetched: %s", p)
		}
	}
}

func TestAnalyzeInvalidConfigJSON(t *testing.T) {
	srv := synth(t, testserver.Config{
		ID:      "fixture/badcfg",
		Current: fixtureRev,
		Revisions: map[string][]testserver.File{fixtureRev: {
			{Path: "config.json", Content: []byte(`{`)},
		}},
	})
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/badcfg"})
	if err != nil {
		t.Fatalf("analyze must not fail on bad config: %v", err)
	}
	if !hasRule(res.Findings, RuleConfigInvalid) {
		t.Fatalf("expected invalid-config finding: %+v", res.Findings)
	}
}

func TestAnalyzeMaxFilesCap(t *testing.T) {
	srv := synth(t, testserver.Config{
		ID:       "fixture/many",
		RepoType: "dataset",
		Current:  fixtureRev,
		Revisions: map[string][]testserver.File{fixtureRev: {
			{Path: "a.py", Content: []byte("x = 1\n")},
			{Path: "b.py", Content: []byte("y = 2\n")},
			{Path: "c.py", Content: []byte("z = 3\n")},
		}},
	})
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{
		RepoType: "dataset",
		RepoID:   "fixture/many",
		MaxFiles: 2,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(res.AnalyzedFiles) != 2 || res.AnalyzedFiles[0] != "a.py" || res.AnalyzedFiles[1] != "b.py" {
		t.Fatalf("analyzed = %v", res.AnalyzedFiles)
	}
	if !hasRule(res.Findings, RuleLimit) {
		t.Fatalf("expected file-cap finding: %+v", res.Findings)
	}
}

func TestAnalyzePinMatch(t *testing.T) {
	srv := fixture(t, "benign", "model", "fixture/benign")
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{
		RepoID: "fixture/benign",
		Pin:    fixtureRev,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !hasRule(res.Findings, RulePinOK) {
		t.Fatalf("expected pin-verified finding: %+v", res.Findings)
	}
	if res.Delta != nil {
		t.Fatal("matching pin must not produce a delta")
	}
}

func TestAnalyzePinMismatchProducesDelta(t *testing.T) {
	oldRev := "aaa012345678901234567890123456789012345"
	newRev := "bbb012345678901234567890123456789012345"
	cfgJSON := []byte(`{"auto_map": {"AutoModel": "module.Fixture"}}`)
	srv := synth(t, testserver.Config{
		ID:      "fixture/pinned",
		Current: newRev,
		Revisions: map[string][]testserver.File{
			oldRev: {
				{Path: "config.json", Content: cfgJSON},
				{Path: "module.py", Content: []byte("value = eval('1')\n")},
			},
			newRev: {
				{Path: "config.json", Content: cfgJSON},
				{Path: "module.py", Content: []byte("import os\nos.system('id')\n")},
				{Path: "extra.py", Content: []byte("x = 1\n")},
			},
		},
	})
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{
		RepoID: "fixture/pinned",
		Pin:    oldRev,
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if res.Delta == nil {
		t.Fatal("expected delta")
	}
	if res.Delta.Pinned != oldRev || res.Delta.Current != newRev {
		t.Fatalf("delta revisions wrong: %+v", res.Delta)
	}
	if len(res.Delta.Changes) != 2 {
		t.Fatalf("changes = %+v", res.Delta.Changes)
	}
	if res.Delta.Changes[0].Path != "extra.py" || res.Delta.Changes[0].Change != "added" {
		t.Fatalf("first change = %+v", res.Delta.Changes[0])
	}
	if res.Delta.Changes[1].Path != "module.py" || res.Delta.Changes[1].Change != "modified" {
		t.Fatalf("second change = %+v", res.Delta.Changes[1])
	}
	if len(res.Delta.NewFindings) == 0 || !hasRule(res.Delta.NewFindings, "MG-CMD-001") {
		t.Fatalf("new findings = %+v", res.Delta.NewFindings)
	}
	if !hasRule(res.Delta.ResolvedFindings, "MG-EXEC-001") {
		t.Fatalf("resolved findings = %+v", res.Delta.ResolvedFindings)
	}
	if !hasRule(res.Findings, RulePinMismatch) {
		t.Fatalf("expected pin-mismatch finding: %+v", res.Findings)
	}
}

func TestAnalyzePinRevisionGone(t *testing.T) {
	srv := fixture(t, "benign", "model", "fixture/benign")
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{
		RepoID: "fixture/benign",
		Pin:    "dead00000000000000000000000000000000000",
	})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if !hasRule(res.Findings, RulePinMissing) {
		t.Fatalf("expected pin-missing finding: %+v", res.Findings)
	}
	if res.Delta != nil {
		t.Fatal("no delta when the pinned revision is gone")
	}
}

func TestAnalyzeCanceledContext(t *testing.T) {
	srv := fixture(t, "benign", "model", "fixture/benign")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Analyze(ctx, fetcher(t, srv), Options{RepoID: "fixture/benign"}); err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestAnalyzeInvalidOptions(t *testing.T) {
	c, err := hf.NewClient("https://huggingface.co", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cases := []Options{
		{RepoID: "../evil"},
		{RepoID: "fixture/benign", RepoType: "kernel"},
		{RepoID: "fixture/benign", Revision: "a/../b"},
		{RepoID: "fixture/benign", Pin: ".."},
	}
	for _, opts := range cases {
		if _, err := Analyze(ctx, c, opts); err == nil {
			t.Fatalf("expected error for options %+v", opts)
		}
	}
	if _, err := Analyze(ctx, nil, Options{RepoID: "fixture/benign"}); err == nil {
		t.Fatal("expected error for nil fetcher")
	}
}

func TestAnalyzeUnknownRevision(t *testing.T) {
	srv := fixture(t, "benign", "model", "fixture/benign")
	_, err := Analyze(context.Background(), fetcher(t, srv), Options{
		RepoID:   "fixture/benign",
		Revision: "doesnotexist00000000000000000000000000",
	})
	if err == nil {
		t.Fatal("expected error for unknown revision")
	}
}
