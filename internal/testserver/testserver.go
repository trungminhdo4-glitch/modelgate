// Package testserver provides an in-process, Hugging Face compatible API
// fixture. The server answers GET requests only, records every method and
// path it receives, and serves repository snapshots from memory or disk.
//
// It exists so that the full `modelgate check` pipeline can be exercised
// without any network access — CI runs entirely offline against it.
package testserver

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// File is one repository file served by the fixture.
type File struct {
	Path    string
	Content []byte
	OID     string // git-object-style hash; derived from Content when empty
	Size    int64  // reported size; derived from Content when 0
	LFSOID  string // set to simulate Git-LFS stored content
	Type    string // tree entry type; defaults to "file" (lets tests simulate hostile servers)
}

// Config describes one fixture repository.
type Config struct {
	ID        string            // e.g. "fixture/benign"
	RepoType  string            // "model" or "dataset"
	Current   string            // revision served without a revision suffix
	Revisions map[string][]File // revision -> files
}

// Server is a running fixture endpoint.
type Server struct {
	cfg     Config
	srv     *httptest.Server
	mu      sync.Mutex
	methods []string
	paths   []string
}

// New starts a fixture server. The caller must call Close.
func New(cfg Config) (*Server, error) {
	if cfg.ID == "" || cfg.Current == "" {
		return nil, errors.New("testserver: ID and Current are required")
	}
	if len(cfg.Revisions) == 0 {
		return nil, errors.New("testserver: at least one revision is required")
	}
	if _, ok := cfg.Revisions[cfg.Current]; !ok {
		return nil, fmt.Errorf("testserver: current revision %q not in Revisions", cfg.Current)
	}
	if cfg.RepoType == "" {
		cfg.RepoType = "model"
	}
	for rev, files := range cfg.Revisions {
		for i := range files {
			if files[i].OID == "" {
				sum := sha1.Sum(files[i].Content)
				files[i].OID = hex.EncodeToString(sum[:])
			}
			if files[i].Size == 0 {
				files[i].Size = int64(len(files[i].Content))
			}
		}
		cfg.Revisions[rev] = files
	}
	s := &Server{cfg: cfg}
	s.srv = httptest.NewServer(s)
	return s, nil
}

// FromDir loads a repository snapshot from a directory tree. File paths are
// relative to dir and use forward slashes.
func FromDir(repoType, id, rev, dir string) (Config, error) {
	var files []File
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files = append(files, File{
			Path:    filepath.ToSlash(rel),
			Content: content,
		})
		return nil
	})
	if err != nil {
		return Config{}, err
	}
	return Config{
		ID:        id,
		RepoType:  repoType,
		Current:   rev,
		Revisions: map[string][]File{rev: files},
	}, nil
}

// URL returns the base URL of the running fixture.
func (s *Server) URL() string { return s.srv.URL }

// Close shuts the fixture down.
func (s *Server) Close() { s.srv.Close() }

// Methods returns a copy of every HTTP method received, in order.
func (s *Server) Methods() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.methods...)
}

// Paths returns a copy of every request path received, in order.
func (s *Server) Paths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.paths...)
}

// NonGET returns every request that was not a plain GET.
func (s *Server) NonGET() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for i, m := range s.methods {
		if m != http.MethodGet {
			out = append(out, fmt.Sprintf("%s %s", m, s.paths[i]))
		}
	}
	return out
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.methods = append(s.methods, r.Method)
	s.paths = append(s.paths, r.URL.Path)
	s.mu.Unlock()

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/models/") || strings.HasPrefix(r.URL.Path, "/api/datasets/"):
		s.serveAPI(w, r.URL.Path)
	default:
		s.serveRaw(w, r.URL.Path)
	}
}

// serveAPI handles /api/{models|datasets}/... routes.
func (s *Server) serveAPI(w http.ResponseWriter, path string) {
	rest := path
	for _, prefix := range []string{"/api/models/", "/api/datasets/"} {
		if strings.HasPrefix(rest, prefix) {
			rest = strings.TrimPrefix(rest, prefix)
			break
		}
	}
	var rev string
	isTree := false
	switch {
	case rest == s.cfg.ID:
		rev = s.cfg.Current
	case strings.HasPrefix(rest, s.cfg.ID+"/revision/"):
		rev = strings.TrimPrefix(rest, s.cfg.ID+"/revision/")
	case strings.HasPrefix(rest, s.cfg.ID+"/tree/"):
		rev = strings.TrimPrefix(rest, s.cfg.ID+"/tree/")
		isTree = true
	default:
		http.NotFound(w, nil)
		return
	}
	files, ok := s.cfg.Revisions[rev]
	if !ok {
		http.NotFound(w, nil)
		return
	}
	if isTree {
		s.writeTree(w, files)
		return
	}
	s.writeMeta(w, rev, files)
}

type metaSibling struct {
	RFilename string `json:"rfilename"`
}

type metaResponse struct {
	ID       string        `json:"id"`
	Sha      string        `json:"sha"`
	Siblings []metaSibling `json:"siblings"`
	Private  bool          `json:"private"`
}

func (s *Server) writeMeta(w http.ResponseWriter, rev string, files []File) {
	resp := metaResponse{ID: s.cfg.ID, Sha: rev, Siblings: make([]metaSibling, 0, len(files))}
	for _, f := range files {
		resp.Siblings = append(resp.Siblings, metaSibling{RFilename: f.Path})
	}
	writeJSON(w, resp)
}

func (s *Server) writeTree(w http.ResponseWriter, files []File) {
	entries := make([]map[string]any, 0, len(files))
	for _, f := range files {
		typ := f.Type
		if typ == "" {
			typ = "file"
		}
		e := map[string]any{
			"type": typ,
			"path": f.Path,
			"oid":  f.OID,
			"size": f.Size,
		}
		if f.LFSOID != "" {
			e["lfs"] = map[string]any{"oid": f.LFSOID, "size": f.Size}
		}
		entries = append(entries, e)
	}
	writeJSON(w, entries)
}

// serveRaw handles /{id}/raw/{rev}/{path} and /datasets/{id}/raw/{rev}/{path}.
func (s *Server) serveRaw(w http.ResponseWriter, path string) {
	var rest string
	switch {
	case strings.HasPrefix(path, "/datasets/"+s.cfg.ID+"/raw/"):
		rest = strings.TrimPrefix(path, "/datasets/"+s.cfg.ID+"/raw/")
	case strings.HasPrefix(path, "/"+s.cfg.ID+"/raw/"):
		rest = strings.TrimPrefix(path, "/"+s.cfg.ID+"/raw/")
	default:
		http.NotFound(w, nil)
		return
	}
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		http.NotFound(w, nil)
		return
	}
	rev, file := rest[:slash], rest[slash+1:]
	files, ok := s.cfg.Revisions[rev]
	if !ok {
		http.NotFound(w, nil)
		return
	}
	for _, f := range files {
		if f.Path == file {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Write(f.Content)
			return
		}
	}
	http.NotFound(w, nil)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
