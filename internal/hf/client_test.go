package hf

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trungminhdo4-glitch/modelgate/internal/testserver"
)

func TestValidateRepoID(t *testing.T) {
	t.Parallel()
	valid := []string{"gpt2", "org/name", "org-1/name_2", "a.b/c-d"}
	for _, in := range valid {
		if err := ValidateRepoID(in); err != nil {
			t.Fatalf("ValidateRepoID(%q): %v", in, err)
		}
	}
	invalid := []string{"", "..", "../x", "org/../etc", "a b", "http://evil", "org/", "/org", "org//name", strings.Repeat("a", 300)}
	for _, in := range invalid {
		if err := ValidateRepoID(in); err == nil {
			t.Fatalf("ValidateRepoID(%q): expected error", in)
		} else if !errors.Is(err, ErrInvalidRepoID) {
			t.Fatalf("ValidateRepoID(%q): wrong error: %v", in, err)
		}
	}
}

func TestValidateRevision(t *testing.T) {
	t.Parallel()
	valid := []string{"main", "v1.0", "abc123", "refs/pr/1", "feature/x"}
	for _, in := range valid {
		if err := ValidateRevision(in); err != nil {
			t.Fatalf("ValidateRevision(%q): %v", in, err)
		}
	}
	invalid := []string{"", "..", "a/../b", "a//b", "-x", "/x", "a b"}
	for _, in := range invalid {
		if err := ValidateRevision(in); err == nil {
			t.Fatalf("ValidateRevision(%q): expected error", in)
		}
	}
}

func TestValidateRepoType(t *testing.T) {
	t.Parallel()
	if err := ValidateRepoType(RepoModel); err != nil {
		t.Fatalf("model: %v", err)
	}
	if err := ValidateRepoType(RepoDataset); err != nil {
		t.Fatalf("dataset: %v", err)
	}
	if err := ValidateRepoType("widget"); err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestValidateBaseURL(t *testing.T) {
	t.Parallel()
	if _, err := ValidateBaseURL("https://huggingface.co"); err != nil {
		t.Fatalf("valid url rejected: %v", err)
	}
	if _, err := ValidateBaseURL("https://huggingface.co/"); err != nil {
		t.Fatalf("trailing slash must be normalized: %v", err)
	}
	if _, err := ValidateBaseURL("http://127.0.0.1:8080"); err != nil {
		t.Fatalf("localhost url rejected: %v", err)
	}
	for _, bad := range []string{"ftp://x", "file:///etc/passwd", "https://user:pass@example.com", "not-a-url", ""} {
		if u, err := ValidateBaseURL(bad); err == nil {
			t.Fatalf("ValidateBaseURL(%q) accepted: %q", bad, u)
		}
	}
}

func TestNewClientDefaults(t *testing.T) {
	t.Parallel()
	c, err := NewClient("", 0)
	if err != nil {
		t.Fatalf("default client: %v", err)
	}
	if c.base.String() != defaultBaseURL {
		t.Fatalf("base = %q", c.base.String())
	}
	if c.hc.Timeout <= 0 {
		t.Fatal("timeout must default to a positive value")
	}
	if _, err := NewClient("ftp://x", time.Second); err == nil {
		t.Fatal("expected error for non-http base URL")
	}
}

const testRev = "rev01abcdef01abcdef01abcdef01abcdef01"

func startFixture(t *testing.T, repoType, id string) *testserver.Server {
	t.Helper()
	cfg := testserver.Config{
		ID:       id,
		RepoType: repoType,
		Current:  testRev,
		Revisions: map[string][]testserver.File{testRev: {
			{Path: "config.json", Content: []byte(`{"auto_map": {}}`)},
			{Path: "sub dir/file.py", Content: []byte("x = 1\n")},
		}},
	}
	srv, err := testserver.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func TestClientEndpointsAndMethods(t *testing.T) {
	srv := startFixture(t, "model", "fixture/benign")
	c, err := NewClient(srv.URL(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	meta, err := c.Meta(ctx, RepoModel, "fixture/benign", "")
	if err != nil {
		t.Fatalf("meta: %v", err)
	}
	if meta.Sha != testRev || len(meta.Siblings) != 2 {
		t.Fatalf("meta = %+v", meta)
	}

	if _, err := c.Meta(ctx, RepoModel, "fixture/benign", testRev); err != nil {
		t.Fatalf("meta@rev: %v", err)
	}
	tree, err := c.Tree(ctx, RepoModel, "fixture/benign", testRev)
	if err != nil {
		t.Fatalf("tree: %v", err)
	}
	if len(tree) != 2 {
		t.Fatalf("tree = %+v", tree)
	}
	data, err := c.Raw(ctx, RepoModel, "fixture/benign", testRev, "config.json")
	if err != nil {
		t.Fatalf("raw: %v", err)
	}
	if !strings.Contains(string(data), "auto_map") {
		t.Fatalf("raw = %q", data)
	}
	// Path with a space must be escaped and still resolve.
	if _, err := c.Raw(ctx, RepoModel, "fixture/benign", testRev, "sub dir/file.py"); err != nil {
		t.Fatalf("raw with space: %v", err)
	}
	// Traversal is rejected before any request leaves the process.
	if _, err := c.Raw(ctx, RepoModel, "fixture/benign", testRev, "../secrets"); err == nil {
		t.Fatal("traversal path must be rejected")
	}

	paths := srv.Paths()
	wantPrefixes := []string{
		"/api/models/fixture/benign",
		"/api/models/fixture/benign/revision/" + testRev,
		"/api/models/fixture/benign/tree/" + testRev,
		"/fixture/benign/raw/" + testRev + "/config.json",
		"/fixture/benign/raw/" + testRev + "/sub dir/file.py",
	}
	if len(paths) < len(wantPrefixes) {
		t.Fatalf("paths = %v", paths)
	}
	for i, want := range wantPrefixes {
		if paths[i] != want {
			t.Errorf("path[%d] = %q, want %q", i, paths[i], want)
		}
	}
	if got := srv.NonGET(); len(got) != 0 {
		t.Fatalf("non-GET requests: %v", got)
	}
	for _, m := range srv.Methods() {
		if m != http.MethodGet {
			t.Fatalf("method used: %s", m)
		}
	}
}

func TestClientDatasetEndpoints(t *testing.T) {
	srv := startFixture(t, "dataset", "fixture/ds")
	c, err := NewClient(srv.URL(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	meta, err := c.Meta(ctx, RepoDataset, "fixture/ds", "")
	if err != nil {
		t.Fatalf("dataset meta: %v", err)
	}
	if meta.ID != "fixture/ds" {
		t.Fatalf("meta = %+v", meta)
	}
	if _, err := c.Raw(ctx, RepoDataset, "fixture/ds", testRev, "config.json"); err != nil {
		t.Fatalf("dataset raw: %v", err)
	}
	paths := srv.Paths()
	if paths[0] != "/api/datasets/fixture/ds" {
		t.Errorf("dataset api path = %q", paths[0])
	}
	if paths[1] != "/datasets/fixture/ds/raw/"+testRev+"/config.json" {
		t.Errorf("dataset raw path = %q", paths[1])
	}
}

func TestClientNotFound(t *testing.T) {
	srv := startFixture(t, "model", "fixture/benign")
	c, _ := NewClient(srv.URL(), 5*time.Second)
	_, err := c.Raw(context.Background(), RepoModel, "fixture/benign", testRev, "nope.py")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if !IsNotFound(err) {
		t.Fatal("IsNotFound must be true for 404")
	}
	_, err = c.Meta(context.Background(), RepoModel, "fixture/benign", "unknownrev00000000000000000000000000000")
	if !IsNotFound(err) {
		t.Fatalf("meta 404 not detected: %v", err)
	}
}

func TestClientHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c, _ := NewClient(srv.URL, time.Second)
	_, err := c.Meta(context.Background(), RepoModel, "org/name", "")
	var he *HTTPError
	if !errors.As(err, &he) || he.StatusCode != http.StatusInternalServerError {
		t.Fatalf("err = %v, want HTTPError 500", err)
	}
}

func TestClientRejectsInvalidInputWithoutRequest(t *testing.T) {
	srv := startFixture(t, "model", "fixture/benign")
	c, _ := NewClient(srv.URL(), time.Second)
	ctx := context.Background()
	if _, err := c.Meta(ctx, RepoModel, "../etc", ""); err == nil {
		t.Fatal("invalid id must be rejected")
	}
	if _, err := c.Meta(ctx, "widget", "org/name", ""); err == nil {
		t.Fatal("invalid type must be rejected")
	}
	if _, err := c.Tree(ctx, RepoModel, "org/name", "a/../b"); err == nil {
		t.Fatal("invalid revision must be rejected")
	}
	if len(srv.Paths()) != 0 {
		t.Fatalf("no request may leave for invalid input: %v", srv.Paths())
	}
}

func TestClientTooLarge(t *testing.T) {
	big := strings.Repeat("A", maxRawBody+1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(big))
	}))
	t.Cleanup(srv.Close)
	c, _ := NewClient(srv.URL, 5*time.Second)
	_, err := c.Raw(context.Background(), RepoModel, "org/name", testRev, "big.txt")
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestHTTPErrorMessageNamesMethod(t *testing.T) {
	e := &HTTPError{StatusCode: 403, URL: "https://example.invalid/x"}
	if !strings.Contains(e.Error(), "GET") || !strings.Contains(e.Error(), "403") {
		t.Fatalf("message = %q", e.Error())
	}
}

func TestParseMetaInvalidJSON(t *testing.T) {
	t.Parallel()
	if _, err := ParseMeta([]byte("{")); err == nil {
		t.Fatal("expected error")
	}
}

func FuzzParseMeta(f *testing.F) {
	f.Add([]byte(`{"id": "org/name", "sha": "abc"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte("[]"))
	f.Add([]byte{0x00})
	f.Fuzz(func(t *testing.T, body []byte) {
		if _, err := ParseMeta(body); err != nil {
			return
		}
	})
}

func FuzzParseTree(f *testing.F) {
	f.Add([]byte(`[{"type":"file","path":"a.py","oid":"abc","size":1}]`))
	f.Add([]byte(`[]`))
	f.Add([]byte("not json"))
	f.Fuzz(func(t *testing.T, body []byte) {
		entries, err := ParseTree(body)
		if err != nil {
			return
		}
		for _, e := range entries {
			// Type is untrusted data and may be any string: the scanner
			// treats every entry that is not explicitly a directory as a
			// file, so an odd type must never hide content.
			if err := validateFilePath(e.Path); err != nil {
				t.Fatalf("unsafe tree path %q accepted: %v", e.Path, err)
			}
		}
	})
}
