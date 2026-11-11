// Package pin implements commit-SHA pinning helpers: comparing two repository
// revisions and diffing the resulting findings for a delta report.
package pin

import (
	"sort"

	"github.com/trungminhdo4-glitch/modelgate/internal/finding"
	"github.com/trungminhdo4-glitch/modelgate/internal/hf"
)

// Change types for repository files.
const (
	ChangeAdded    = "added"
	ChangeRemoved  = "removed"
	ChangeModified = "modified"
)

// FileChange describes one difference between the pinned and current revision.
type FileChange struct {
	Path   string `json:"path"`
	Change string `json:"change"`
}

// Delta is the report section produced when a pinned revision differs from
// what upstream currently serves.
type Delta struct {
	Pinned           string            `json:"pinned_revision"`
	Current          string            `json:"current_revision"`
	Changes          []FileChange      `json:"changes,omitempty"`
	NewFindings      []finding.Finding `json:"new_findings,omitempty"`
	ResolvedFindings []finding.Finding `json:"resolved_findings,omitempty"`
}

// DiffTrees compares file entries of two revisions. Directories are ignored;
// results are sorted by path so reports stay reproducible.
func DiffTrees(pinned, current []hf.TreeEntry) []FileChange {
	oldFiles := map[string]string{}
	newFiles := map[string]string{}
	for _, e := range pinned {
		if e.Type == "file" {
			oldFiles[e.Path] = e.OID
		}
	}
	for _, e := range current {
		if e.Type == "file" {
			newFiles[e.Path] = e.OID
		}
	}
	var out []FileChange
	for path, oldOID := range oldFiles {
		newOID, ok := newFiles[path]
		switch {
		case !ok:
			out = append(out, FileChange{Path: path, Change: ChangeRemoved})
		case oldOID != newOID:
			out = append(out, FileChange{Path: path, Change: ChangeModified})
		}
	}
	for path := range newFiles {
		if _, ok := oldFiles[path]; !ok {
			out = append(out, FileChange{Path: path, Change: ChangeAdded})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Change < out[j].Change
	})
	return out
}

// DiffFindings returns findings present in the current revision but not in
// the pinned one (added), and findings that disappeared (resolved).
func DiffFindings(pinned, current []finding.Finding) (added, resolved []finding.Finding) {
	oldSet := map[string]bool{}
	for _, f := range pinned {
		oldSet[f.Key()] = true
	}
	newSet := map[string]bool{}
	for _, f := range current {
		newSet[f.Key()] = true
	}
	for _, f := range current {
		if !oldSet[f.Key()] {
			added = append(added, f)
		}
	}
	for _, f := range pinned {
		if !newSet[f.Key()] {
			resolved = append(resolved, f)
		}
	}
	finding.SortFindings(added)
	finding.SortFindings(resolved)
	return added, resolved
}
