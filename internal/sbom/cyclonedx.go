// Package sbom produces a CycloneDX 1.6 SBOM for a checked repository.
// The SBOM lists every repository file with its content hash plus all
// findings as vulnerabilities, so reviewers can diff attestations over time.
package sbom

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/trungminhdo4-glitch/modelgate/internal/scan"
)

// SpecVersion of the CycloneDX specification used here.
const SpecVersion = "1.6"

// Options controls tool stamping and the SBOM timestamp (clock injection
// keeps SBOMs byte-reproducible in tests).
type Options struct {
	ToolName    string
	ToolVersion string
	Homepage    string
	Timestamp   time.Time
}

// BOM is the CycloneDX document.
type BOM struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	SerialNumber    string          `json:"serialNumber"`
	Version         int             `json:"version"`
	Metadata        Metadata        `json:"metadata"`
	Components      []Component     `json:"components"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// Metadata describes the SBOM creation context.
type Metadata struct {
	Timestamp  string     `json:"timestamp"`
	Tools      []Tool     `json:"tools"`
	Component  Component  `json:"component"`
	Properties []Property `json:"properties,omitempty"`
}

// Tool identifies the SBOM producer.
type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Component is a CycloneDX component entry.
type Component struct {
	BOMRef     string     `json:"bom-ref,omitempty"`
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	Hashes     []Hash     `json:"hashes,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

// Hash is one content hash of a component.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// Property is a name/value annotation.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Vulnerability carries one ModelGate finding in CycloneDX shape. The ID is
// the stable ModelGate rule ID; no CVE is claimed.
type Vulnerability struct {
	ID          string   `json:"id"`
	Source      Source   `json:"source"`
	Description string   `json:"description"`
	Ratings     []Rating `json:"ratings,omitempty"`
	Affects     []Affect `json:"affects,omitempty"`
}

// Source names who reported the vulnerability entry.
type Source struct {
	Name string `json:"name"`
}

// Rating carries the severity as ModelGate assessed it.
type Rating struct {
	Severity string `json:"severity"`
	Method   string `json:"method"`
}

// Affect links a finding to a component reference.
type Affect struct {
	Ref string `json:"ref"`
}

// Build renders the SBOM for one analysis result.
func Build(res *scan.Result, opts Options) *BOM {
	if opts.ToolName == "" {
		opts.ToolName = "modelgate"
	}
	if opts.ToolVersion == "" {
		opts.ToolVersion = "dev"
	}
	modelRef := "model/" + res.RepoID + "@" + res.Revision
	componentType := "machine-learning-model"
	if res.RepoType == "dataset" {
		componentType = "file"
	}

	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  SpecVersion,
		SerialNumber: "urn:uuid:" + stableUUID(fmt.Sprintf("modelgate:sbom:%s@%s", res.RepoID, res.Revision)),
		Version:      1,
		Metadata: Metadata{
			Timestamp: opts.Timestamp.UTC().Format(time.RFC3339),
			Tools: []Tool{{
				Vendor:  "trung-dev",
				Name:    opts.ToolName,
				Version: opts.ToolVersion,
			}},
			Component: Component{
				BOMRef:  modelRef,
				Type:    componentType,
				Name:    res.RepoID,
				Version: res.Revision,
				Properties: []Property{
					{Name: "modelgate:repository_url", Value: repositoryURL(res)},
					{Name: "modelgate:repo_type", Value: res.RepoType},
					{Name: "modelgate:mode", Value: "static-read-only"},
				},
			},
			Properties: []Property{
				{Name: "modelgate:homepage", Value: opts.Homepage},
				{Name: "modelgate:trust_remote_code.auto_map", Value: fmt.Sprintf("%d", res.Trust.AutoMapCount)},
				{Name: "modelgate:trust_remote_code.card_mentions", Value: fmt.Sprintf("%d", res.Trust.CardMentions)},
			},
		},
	}

	entries := make([]scanFile, 0, len(res.Tree))
	for _, e := range res.Tree {
		if e.Type == "file" {
			sf := scanFile{path: e.Path, oid: e.OID, size: e.Size}
			if e.LFS != nil {
				sf.lfsOID = e.LFS.OID
			}
			entries = append(entries, sf)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	analyzed := map[string]bool{}
	for _, f := range res.AnalyzedFiles {
		analyzed[f] = true
	}

	bom.Components = make([]Component, 0, len(entries))
	for _, e := range entries {
		c := Component{
			BOMRef:  "file/" + e.path + "@" + res.Revision,
			Type:    "file",
			Name:    e.path,
			Version: res.Revision,
			Properties: []Property{
				{Name: "modelgate:size_bytes", Value: fmt.Sprintf("%d", e.size)},
				{Name: "modelgate:role", Value: fileRole(e.path)},
				{Name: "modelgate:analyzed", Value: fmt.Sprintf("%t", analyzed[e.path])},
			},
		}
		if e.lfsOID != "" {
			c.Hashes = []Hash{{Alg: "SHA-256", Content: e.lfsOID}}
		} else if e.oid != "" {
			c.Hashes = []Hash{{Alg: "SHA-1", Content: e.oid}}
		}
		bom.Components = append(bom.Components, c)
	}

	for _, f := range res.Findings {
		v := Vulnerability{
			ID:          f.Rule,
			Source:      Source{Name: "ModelGate static analysis"},
			Description: fmt.Sprintf("%s — %s%s", f.Title, f.Message, fileSuffix(f.File)),
			Ratings:     []Rating{{Severity: string(f.Severity), Method: "other"}},
			Affects:     []Affect{{Ref: modelRef}},
		}
		if f.File != "" {
			ref := "file/" + f.File + "@" + res.Revision
			if componentExists(bom.Components, ref) {
				v.Affects = []Affect{{Ref: ref}}
			}
		}
		bom.Vulnerabilities = append(bom.Vulnerabilities, v)
	}
	return bom
}

type scanFile struct {
	path   string
	oid    string
	size   int64
	lfsOID string
}

func componentExists(components []Component, ref string) bool {
	for _, c := range components {
		if c.BOMRef == ref {
			return true
		}
	}
	return false
}

func fileSuffix(path string) string {
	if path == "" {
		return ""
	}
	return " (file: " + path + ")"
}

// fileRole classifies a repository file for SBOM consumers.
func fileRole(path string) string {
	switch {
	case path == "config.json":
		return "model-config"
	case len(path) > 3 && path[len(path)-3:] == ".py":
		return "python-source"
	case path == "README.md" || path == "readme.md":
		return "documentation"
	case len(path) > 5 && path[len(path)-5:] == ".json":
		return "metadata"
	default:
		return "other"
	}
}

// repositoryURL returns the canonical Hub URL of the checked repository.
func repositoryURL(res *scan.Result) string {
	if res.RepoType == "dataset" {
		return "https://huggingface.co/datasets/" + res.RepoID
	}
	return "https://huggingface.co/" + res.RepoID
}

// stableUUID derives a deterministic RFC 4122 version-5 style UUID so the
// same repository at the same revision yields the same serial number.
func stableUUID(seed string) string {
	sum := sha1.Sum([]byte(seed))
	b := sum[:]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// JSON renders the SBOM as indented JSON with a trailing newline.
func (b *BOM) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sbom: encoding: %w", err)
	}
	return append(data, '\n'), nil
}
