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

// transformers' trust_remote_code loader also downloads and imports every
// relative import of an auto_map module, recursively. A payload hidden one or
// two hops away must be analyzed like the auto_map target itself.
func TestAnalyzeFollowsRelativeImports(t *testing.T) {
	rev := "ccc012345678901234567890123456789012345"
	srv := synth(t, testserver.Config{
		ID:      "fixture/relimports",
		Current: rev,
		Revisions: map[string][]testserver.File{
			rev: {
				{Path: "config.json", Content: []byte(`{"auto_map": {"AutoModel": "modeling.Fixture"}}`)},
				{Path: "modeling.py", Content: []byte("from .helpers import setup\r\nfrom ..outside import nope\nfrom .absent import gone\nclass Fixture: pass\n")},
				{Path: "helpers.py", Content: []byte("import .deep\n\ndef setup():\n    return 1\n")},
				{Path: "deep.py", Content: []byte("from .modeling import Fixture\nimport os\nos.system('id')\n")},
				{Path: "unrelated.py", Content: []byte("import os\nos.system('never imported')\n")},
			},
		},
	})
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/relimports"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	want := []string{"modeling.py", "helpers.py", "deep.py"}
	if strings.Join(res.AnalyzedFiles, ",") != strings.Join(want, ",") {
		t.Fatalf("analyzed files = %v, want %v", res.AnalyzedFiles, want)
	}
	var hit bool
	for _, f := range res.Findings {
		if f.Rule == "MG-CMD-001" && f.File == "deep.py" {
			hit = true
		}
		if f.File == "unrelated.py" || f.Rule == RuleAutoMapMiss {
			t.Fatalf("unexpected finding %+v", f)
		}
	}
	if !hit {
		t.Fatalf("payload two imports away was not reported: %+v", res.Findings)
	}
	if strings.Join(res.AutoMapTargets, ",") != "modeling.py" {
		t.Fatalf("auto_map targets = %v", res.AutoMapTargets)
	}
}

// AutoTokenizer/AutoProcessor read auto_map from their own config files, as
// [slow, fast] lists, and "repo--module.Class" pulls code from another repo.
func TestAnalyzeAutoMapListsAuxConfigsAndRemoteRefs(t *testing.T) {
	rev := "eee012345678901234567890123456789012345"
	srv := synth(t, testserver.Config{
		ID:      "fixture/automap",
		Current: rev,
		Revisions: map[string][]testserver.File{
			rev: {
				{Path: "config.json", Content: []byte(`{"auto_map": {"AutoModel": "other/shared--modeling.Model", "AutoConfig": "configuration.Cfg"}}`)},
				{Path: "configuration.py", Content: []byte("class Cfg: pass\n")},
				{Path: "tokenizer_config.json", Content: []byte(`{"auto_map": {"AutoTokenizer": ["tokenization.Slow", null]}}`)},
				{Path: "tokenization.py", Content: []byte("import os\nos.system('id')\n")},
				{Path: "preprocessor_config.json", Content: []byte(`{"auto_map": {"AutoImageProcessor": "processing.Proc"}}`)},
				{Path: "processing.py", Content: []byte("x = eval('1')\n")},
			},
		},
	})
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/automap"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	want := "configuration.py,processing.py,tokenization.py"
	if got := strings.Join(res.AnalyzedFiles, ","); got != want {
		t.Fatalf("analyzed files = %q, want %q", got, want)
	}
	var cmd, eval, remote bool
	for _, f := range res.Findings {
		switch {
		case f.Rule == "MG-CMD-001" && f.File == "tokenization.py":
			cmd = true
		case f.Rule == "MG-EXEC-001" && f.File == "processing.py":
			eval = true
		case f.Rule == RuleAutoMapRemote:
			remote = f.File == "config.json" && strings.Contains(f.Message, "other/shared")
		case f.Rule == RuleAutoMapMiss || f.Rule == RuleAutoMapBadVal:
			t.Fatalf("unexpected finding %+v", f)
		}
	}
	if !cmd || !eval || !remote {
		t.Fatalf("cmd=%v eval=%v remote=%v findings=%+v", cmd, eval, remote, res.Findings)
	}
	if res.Trust.AutoMapCount != 4 {
		t.Fatalf("auto_map count = %d, want 4", res.Trust.AutoMapCount)
	}
}

func TestAnalyzeCustomPipelines(t *testing.T) {
	rev := "fff012345678901234567890123456789012345"
	srv := synth(t, testserver.Config{
		ID:      "fixture/pipelines",
		Current: rev,
		Revisions: map[string][]testserver.File{
			rev: {
				{Path: "config.json", Content: []byte(`{"custom_pipelines": {"my-task": {"impl": "pipeline.MyPipeline", "pt": ["AutoModel"]}, "other": {"impl": "org/elsewhere--pipe.P"}, "broken": {"pt": []}}}`)},
				{Path: "pipeline.py", Content: []byte("import os\nos.system('id')\n")},
			},
		},
	})
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/pipelines"})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if got := strings.Join(res.AnalyzedFiles, ","); got != "pipeline.py" {
		t.Fatalf("analyzed files = %q", got)
	}
	var cmd, remote, bad bool
	for _, f := range res.Findings {
		switch {
		case f.Rule == "MG-CMD-001" && f.File == "pipeline.py":
			cmd = true
		case f.Rule == RuleAutoMapRemote:
			remote = strings.Contains(f.Message, "org/elsewhere") && strings.Contains(f.Message, "custom_pipelines.other")
		case f.Rule == RuleAutoMapBadVal:
			bad = strings.Contains(f.Message, "custom_pipelines.broken")
		}
	}
	if !cmd || !remote || !bad {
		t.Fatalf("cmd=%v remote=%v bad=%v findings=%+v", cmd, remote, bad, res.Findings)
	}
	if res.Trust.AutoMapCount != 3 {
		t.Fatalf("entry point count = %d, want 3", res.Trust.AutoMapCount)
	}
}

func TestAnalyzeRelativeImportsRespectFileLimit(t *testing.T) {
	rev := "ddd012345678901234567890123456789012345"
	srv := synth(t, testserver.Config{
		ID:      "fixture/relimit",
		Current: rev,
		Revisions: map[string][]testserver.File{
			rev: {
				{Path: "config.json", Content: []byte(`{"auto_map": {"AutoModel": "a.Fixture"}}`)},
				{Path: "a.py", Content: []byte("from .b import x\n")},
				{Path: "b.py", Content: []byte("from .c import x\n")},
				{Path: "c.py", Content: []byte("import os\nos.system('id')\n")},
			},
		},
	})
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/relimit", MaxFiles: 2})
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	if len(res.AnalyzedFiles) != 2 || !hasRule(res.Findings, RuleLimit) {
		t.Fatalf("limit not enforced: files=%v findings=%+v", res.AnalyzedFiles, res.Findings)
	}
}

func TestRelativeImports(t *testing.T) {
	t.Parallel()
	src := []byte("from .a import x\n  from .pkg.mod import y\nimport .b\n# from .commented import z\nfrom ..up import w\nfrom . import v\nx = 'from .str import u'\n")
	got := strings.Join(relativeImports("sub/m.py", src), ",")
	want := "sub/a.py,sub/b.py,sub/pkg.mod.py,sub/pkg/mod.py"
	if got != want {
		t.Fatalf("relativeImports = %q, want %q", got, want)
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
