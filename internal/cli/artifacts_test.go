package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/trungminhdo4-glitch/modelgate/internal/testserver"
)

func TestCheckpointReviewReportsAndSeverityGate(t *testing.T) {
	srv, err := testserver.New(testserver.Config{
		ID: "fixture/checkpoint", Current: fixtureRev,
		Revisions: map[string][]testserver.File{fixtureRev: {{Path: "pytorch_model.bin", Content: []byte("inert fixture")}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	for _, format := range []string{"text", "json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			app, out, errBuf := newTestApp(t)
			code := run(t, app, "check", "fixture/checkpoint", "--api-url", srv.URL(), "--format", format)
			if code != ExitOK || !strings.Contains(out.String(), "MG-ARTIFACT-001") || !strings.Contains(out.String(), "pytorch_model.bin") {
				t.Fatalf("exit=%d stdout=%s stderr=%s", code, out, errBuf)
			}
			if (format == "json" || format == "sarif") && !json.Valid(out.Bytes()) {
				t.Fatalf("invalid machine report: %s", out)
			}
		})
	}
	app, _, errBuf := newTestApp(t)
	if code := run(t, app, "check", "fixture/checkpoint", "--api-url", srv.URL(), "--fail-on", "low"); code != ExitFindings {
		t.Fatalf("low-severity policy should fail: exit=%d stderr=%s", code, errBuf)
	}
}
