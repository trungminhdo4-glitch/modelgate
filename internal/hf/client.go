// Package hf implements a read-only Hugging Face Hub API client.
//
// Read-only by construction: the client exposes GET requests only, validates
// repository identifiers and API base URLs before use, and caps response
// sizes. There is no code path that uploads, mutates, or deletes anything.
package hf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Repository types known to the client.
const (
	RepoModel   = "model"
	RepoDataset = "dataset"
)

// Sentinel errors.
var (
	// ErrNotFound is returned for HTTP 404 responses.
	ErrNotFound = errors.New("hf: resource not found")
	// ErrTooLarge is returned when a response exceeds the size cap.
	ErrTooLarge = errors.New("hf: response exceeds size limit")
	// ErrInvalidRepoID marks a rejected repository identifier.
	ErrInvalidRepoID = errors.New("invalid repository id")
	// ErrInvalidRepoType marks a rejected repository type.
	ErrInvalidRepoType = errors.New("invalid repository type")
	// ErrInvalidBaseURL marks a rejected API base URL.
	ErrInvalidBaseURL = errors.New("invalid api base url")
)

// Response size caps (bytes). They bound memory use on hostile input.
const (
	maxMetaBody  = 16 << 20 // 16 MiB for API metadata
	maxRawBody   = 2 << 20  // 2 MiB for raw files (analysis cap is lower)
	maxTreePages = 64
)

var (
	repoID         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)
	revSeg         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	defaultBaseURL = "https://huggingface.co"
	linkEntry      = regexp.MustCompile(`<([^>]*)>([^<]*)`)
	linkRelation   = regexp.MustCompile(`(?i);\s*rel\s*=\s*(?:"([^"]*)"|([^;,\s]+))`)
)

// ValidateRepoID rejects anything that is not a plain "owner/name" style id.
// This also blocks path traversal ("../") and scheme smuggling.
func ValidateRepoID(id string) error {
	if id == "" || len(id) > 256 || !repoID.MatchString(id) {
		return fmt.Errorf("%w: %q", ErrInvalidRepoID, id)
	}
	return nil
}

// ValidateRepoType accepts "model" or "dataset".
func ValidateRepoType(t string) error {
	switch t {
	case RepoModel, RepoDataset:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidRepoType, t)
	}
}

// ValidateRevision accepts branch names, tags and commit SHAs. Every slash
// separated segment must be plain (no "." or ".."), which keeps the revision
// from escaping the URL path it is embedded in.
func ValidateRevision(rev string) error {
	if rev == "" || len(rev) > 128 {
		return fmt.Errorf("invalid revision: %q", rev)
	}
	for _, seg := range strings.Split(rev, "/") {
		if seg == "." || seg == ".." || !revSeg.MatchString(seg) {
			return fmt.Errorf("invalid revision: %q", rev)
		}
	}
	return nil
}

// ValidateBaseURL validates the API base URL. Only http(s) without userinfo
// is allowed; this keeps --api-url from becoming an open redirect or a
// credential-smuggling vector.
func ValidateBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBaseURL, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("%w: scheme %q not allowed", ErrInvalidBaseURL, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: missing host", ErrInvalidBaseURL)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: userinfo not allowed", ErrInvalidBaseURL)
	}
	u.RawQuery, u.Fragment = "", ""
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}

// Sibling is one file entry of a repository as reported by the Hub API.
type Sibling struct {
	RFilename string `json:"rfilename"`
}

// Meta is the subset of the Hub repository metadata ModelGate needs.
type Meta struct {
	ID       string    `json:"id"`
	Sha      string    `json:"sha"`
	Siblings []Sibling `json:"siblings"`
	Private  bool      `json:"private"`
}

// LFS describes a Git-LFS stored blob.
type LFS struct {
	OID  string `json:"oid"`
	Size int64  `json:"size"`
}

// TreeEntry is one entry of the repository tree at a revision.
type TreeEntry struct {
	Type string `json:"type"` // "file" | "directory"
	Path string `json:"path"`
	OID  string `json:"oid"`
	Size int64  `json:"size"`
	LFS  *LFS   `json:"lfs,omitempty"`
}

// Fetcher is the read-only interface used by the analysis stage.
type Fetcher interface {
	Meta(ctx context.Context, repoType, id, rev string) (*Meta, error)
	Tree(ctx context.Context, repoType, id, rev string) ([]TreeEntry, error)
	Raw(ctx context.Context, repoType, id, rev, path string) ([]byte, error)
}

// Client talks to a Hugging Face-compatible API over GET only.
type Client struct {
	base      *url.URL
	hc        *http.Client
	userAgent string
}

// NewClient builds a client for baseURL. An empty baseURL selects the public
// Hugging Face endpoint; tests and mirrors pass their own URL.
func NewClient(baseURL string, timeout time.Duration) (*Client, error) {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	base, err := ValidateBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		base:      base,
		hc:        &http.Client{Timeout: timeout},
		userAgent: "modelgate/readonly (+https://github.com/trungminhdo4-glitch/modelgate)",
	}, nil
}

// HTTPError reports a non-2xx response.
type HTTPError struct {
	StatusCode int
	URL        string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("hf: GET %s: unexpected status %d", e.URL, e.StatusCode)
}

// IsNotFound reports whether err came from an HTTP 404.
func IsNotFound(err error) bool {
	if errors.Is(err, ErrNotFound) {
		return true
	}
	var he *HTTPError
	return errors.As(err, &he) && he.StatusCode == http.StatusNotFound
}

// get performs a bounded GET request and returns the body and response headers.
func (c *Client) get(ctx context.Context, u string, limit int64) ([]byte, *http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("hf: GET %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, fmt.Errorf("%w: GET %s", ErrNotFound, u)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, &HTTPError{StatusCode: resp.StatusCode, URL: u}
	}
	limited := io.LimitReader(resp.Body, limit+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, nil, fmt.Errorf("hf: reading %s: %w", u, err)
	}
	if int64(len(body)) > limit {
		return nil, nil, fmt.Errorf("%w: %s", ErrTooLarge, u)
	}
	return body, resp, nil
}

// apiPrefix maps the repository type to the API path segment.
func apiPrefix(repoType string) (string, error) {
	switch repoType {
	case RepoModel:
		return "/api/models", nil
	case RepoDataset:
		return "/api/datasets", nil
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidRepoType, repoType)
	}
}

// repoRoot maps the repository type to the raw-content path segment.
func repoRoot(repoType string) (string, error) {
	switch repoType {
	case RepoModel:
		return "", nil
	case RepoDataset:
		return "/datasets", nil
	default:
		return "", fmt.Errorf("%w: %q", ErrInvalidRepoType, repoType)
	}
}

// escapeRev escapes each slash-separated segment of a revision name.
func escapeRev(rev string) string {
	parts := strings.Split(rev, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// escapeID escapes each segment of an "owner/name" identifier.
func escapeID(id string) string {
	parts := strings.Split(id, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

// escapePath escapes each segment of a repository-relative file path.
func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

// validateFilePath rejects traversal and absolute paths in file references.
func validateFilePath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "..") || strings.ContainsRune(p, 0) {
		return fmt.Errorf("invalid file path: %q", p)
	}
	return nil
}

// Meta fetches repository metadata, optionally at a specific revision.
// An empty rev selects the default branch.
func (c *Client) Meta(ctx context.Context, repoType, id, rev string) (*Meta, error) {
	if err := ValidateRepoType(repoType); err != nil {
		return nil, err
	}
	if err := ValidateRepoID(id); err != nil {
		return nil, err
	}
	prefix, err := apiPrefix(repoType)
	if err != nil {
		return nil, err
	}
	u := c.base.String() + prefix + "/" + escapeID(id)
	if rev != "" {
		if err := ValidateRevision(rev); err != nil {
			return nil, err
		}
		u += "/revision/" + escapeRev(rev)
	}
	body, _, err := c.get(ctx, u, maxMetaBody)
	if err != nil {
		return nil, err
	}
	return ParseMeta(body)
}

// ParseMeta decodes repository metadata JSON.
func ParseMeta(body []byte) (*Meta, error) {
	m := &Meta{}
	if err := json.Unmarshal(body, m); err != nil {
		return nil, fmt.Errorf("hf: decoding metadata: %w", err)
	}
	return m, nil
}

// Tree fetches the recursive file tree at a revision.
func (c *Client) Tree(ctx context.Context, repoType, id, rev string) ([]TreeEntry, error) {
	if err := ValidateRepoType(repoType); err != nil {
		return nil, err
	}
	if err := ValidateRepoID(id); err != nil {
		return nil, err
	}
	if err := ValidateRevision(rev); err != nil {
		return nil, err
	}
	prefix, err := apiPrefix(repoType)
	if err != nil {
		return nil, err
	}
	root, err := url.Parse(c.base.String() + prefix + "/" + escapeID(id) + "/tree/" + escapeRev(rev) + "?recursive=true")
	if err != nil {
		return nil, err
	}
	// A pagination link or redirect may change the query, but it must stay on
	// the same repository tree endpoint and origin.
	validate := func(next *url.URL) error {
		if next.Scheme != root.Scheme || !strings.EqualFold(next.Host, root.Host) ||
			next.EscapedPath() != root.EscapedPath() || next.User != nil || next.Fragment != "" {
			return errors.New("hf: tree pagination points outside the repository tree endpoint")
		}
		return nil
	}
	hc := *c.hc
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("hf: too many tree redirects")
		}
		return validate(req.URL)
	}
	paged := *c
	paged.hc = &hc

	var tree []TreeEntry
	seen := make(map[string]bool)
	remaining := int64(maxMetaBody)
	for next := root; next != nil; {
		if len(seen) >= maxTreePages {
			return nil, fmt.Errorf("%w: tree exceeds %d pages", ErrTooLarge, maxTreePages)
		}
		key := next.String()
		if seen[key] {
			return nil, errors.New("hf: tree pagination cycle")
		}
		seen[key] = true
		body, resp, err := paged.get(ctx, key, remaining)
		if err != nil {
			if len(seen) > 1 && IsNotFound(err) {
				return nil, fmt.Errorf("hf: tree page %d was not found", len(seen))
			}
			return nil, err
		}
		remaining -= int64(len(body))
		entries, err := ParseTree(body)
		if err != nil {
			return nil, err
		}
		tree = append(tree, entries...)
		next, err = nextTreePage(resp.Request.URL, resp.Header.Values("Link"))
		if err != nil {
			return nil, err
		}
		if next != nil {
			if err := validate(next); err != nil {
				return nil, err
			}
		}
	}
	return tree, nil
}

func nextTreePage(current *url.URL, headers []string) (*url.URL, error) {
	var next *url.URL
	for _, header := range headers {
		for _, entry := range linkEntry.FindAllStringSubmatch(header, -1) {
			rel := linkRelation.FindStringSubmatch(entry[2])
			if rel == nil || !slices.Contains(strings.Fields(rel[1]+rel[2]), "next") {
				continue
			}
			if next != nil || entry[1] == "" {
				return nil, errors.New("hf: ambiguous or empty next tree page")
			}
			var err error
			next, err = current.Parse(entry[1])
			if err != nil {
				return nil, errors.New("hf: invalid next tree page URL")
			}
		}
	}
	return next, nil
}

// ParseTree decodes a repository tree JSON document. Every entry path is
// validated: traversal, absolute paths and NUL bytes make the whole tree
// unusable, so a hostile server can never steer a fetch outside the
// repository (defense in depth next to Client.Raw).
func ParseTree(body []byte) ([]TreeEntry, error) {
	var entries []TreeEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("hf: decoding tree: %w", err)
	}
	for _, e := range entries {
		if err := validateFilePath(e.Path); err != nil {
			return nil, fmt.Errorf("hf: tree: %w", err)
		}
	}
	return entries, nil
}

// Raw fetches one repository file at a revision as bytes.
func (c *Client) Raw(ctx context.Context, repoType, id, rev, path string) ([]byte, error) {
	if err := ValidateRepoType(repoType); err != nil {
		return nil, err
	}
	if err := ValidateRepoID(id); err != nil {
		return nil, err
	}
	if err := ValidateRevision(rev); err != nil {
		return nil, err
	}
	if err := validateFilePath(path); err != nil {
		return nil, err
	}
	root, err := repoRoot(repoType)
	if err != nil {
		return nil, err
	}
	u := c.base.String() + root + "/" + escapeID(id) + "/raw/" + escapeRev(rev) + "/" + escapePath(path)
	body, _, err := c.get(ctx, u, maxRawBody)
	return body, err
}
