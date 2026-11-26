package scan

import (
	"context"
	"strings"
	"testing"

	"github.com/trungminhdo4-glitch/modelgate/internal/finding"
	"github.com/trungminhdo4-glitch/modelgate/internal/testserver"
)

func TestAnalyzeCheckpointFormatsWithoutReadingWeights(t *testing.T) {
	for _, repoType := range []string{"model", "dataset"} {
		t.Run(repoType, func(t *testing.T) {
			paths := []string{"weights.pkl", "data.pickle", "nested/weights.PT", "model.pth", "model.ckpt", "pytorch_model.bin", "weights/pytorch_model-00001-of-00002.bin"}
			files := []testserver.File{{Path: "config.json", Content: []byte(`{}`)}}
			for _, path := range paths {
				files = append(files, testserver.File{Path: path, Content: []byte("inert fixture"), Size: 1 << 40})
			}
			srv := synth(t, testserver.Config{
				ID: "fixture/artifacts", RepoType: repoType, Current: fixtureRev,
				Revisions: map[string][]testserver.File{fixtureRev: files},
			})
			res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/artifacts", RepoType: repoType})
			if err != nil {
				t.Fatal(err)
			}
			var got []finding.Finding
			for _, f := range res.Findings {
				if f.Rule == "MG-ARTIFACT-001" {
					got = append(got, f)
					if f.Severity != finding.SeverityLow || f.File == "" || f.Remediation == "" || len(f.References) == 0 {
						t.Fatalf("incomplete format-review finding: %+v", f)
					}
					if !strings.Contains(f.Message, "not inspected") {
						t.Fatalf("finding must explain heuristic scope: %+v", f)
					}
				}
			}
			if len(got) != len(paths) {
				t.Fatalf("want %d artifact findings, got %+v", len(paths), got)
			}
			for _, request := range srv.Paths() {
				if strings.Contains(request, "/resolve/") && !strings.HasSuffix(request, "/config.json") {
					t.Fatalf("unexpected artifact content download: %s", request)
				}
			}
			if len(res.AnalyzedFiles) != 0 {
				t.Fatalf("metadata-only findings must not mark artifacts analyzed: %v", res.AnalyzedFiles)
			}
		})
	}
}

func TestAnalyzeCheckpointFormatNearMisses(t *testing.T) {
	files := []testserver.File{{Path: "config.json", Content: []byte(`{}`)}}
	for _, path := range []string{"model.safetensors", "model.safetensors.index.json", "model.onnx", "model.gguf", "tokenizer.bin", "notes/pickle.txt", "weights.pt.txt", "pytorch_model.bin.index.json", "pytorch_model-backup.bin"} {
		files = append(files, testserver.File{Path: path, Content: []byte("inert fixture")})
	}
	files = append(files, testserver.File{Path: "directory.pt", Type: "directory"})
	srv := synth(t, testserver.Config{ID: "fixture/near-miss", Current: fixtureRev, Revisions: map[string][]testserver.File{fixtureRev: files}})
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/near-miss"})
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(res.Findings, "MG-ARTIFACT-001") {
		t.Fatalf("unrecognized names must not trigger artifact rule: %+v", res.Findings)
	}
}

func TestAnalyzeCheckpointFormatPinDelta(t *testing.T) {
	const oldRev = "aaa012345678901234567890123456789012345"
	srv := synth(t, testserver.Config{
		ID: "fixture/artifact-pin", Current: fixtureRev,
		Revisions: map[string][]testserver.File{
			oldRev: {{Path: "old.pkl", Content: []byte("inert old fixture")}},
			fixtureRev: {{Path: "model.safetensors", Content: []byte("inert tensor fixture")},
				{Path: "new.pt", Content: []byte("inert new fixture")}},
		},
	})
	res, err := Analyze(context.Background(), fetcher(t, srv), Options{RepoID: "fixture/artifact-pin", Pin: oldRev})
	if err != nil {
		t.Fatal(err)
	}
	if res.Delta == nil || len(res.Delta.NewFindings) != 1 || len(res.Delta.ResolvedFindings) != 1 {
		t.Fatalf("artifact delta missing: %+v", res.Delta)
	}
	if res.Delta.NewFindings[0].File != "new.pt" || res.Delta.ResolvedFindings[0].File != "old.pkl" {
		t.Fatalf("wrong artifact delta paths: %+v", res.Delta)
	}
}
