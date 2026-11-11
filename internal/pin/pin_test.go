package pin

import (
	"testing"

	"github.com/trung-dev/modelgate/internal/finding"
	"github.com/trung-dev/modelgate/internal/hf"
)

func TestDiffTrees(t *testing.T) {
	t.Parallel()
	pinned := []hf.TreeEntry{
		{Type: "file", Path: "a.py", OID: "111"},
		{Type: "file", Path: "b.py", OID: "222"},
		{Type: "file", Path: "gone.py", OID: "333"},
		{Type: "directory", Path: "dir", OID: "444"},
	}
	current := []hf.TreeEntry{
		{Type: "file", Path: "a.py", OID: "111"},
		{Type: "file", Path: "b.py", OID: "999"},
		{Type: "file", Path: "new.py", OID: "555"},
		{Type: "directory", Path: "dir", OID: "444"},
	}
	got := DiffTrees(pinned, current)
	want := []FileChange{
		{Path: "b.py", Change: ChangeModified},
		{Path: "gone.py", Change: ChangeRemoved},
		{Path: "new.py", Change: ChangeAdded},
	}
	if len(got) != len(want) {
		t.Fatalf("changes = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("change[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestDiffTreesIdentical(t *testing.T) {
	t.Parallel()
	files := []hf.TreeEntry{{Type: "file", Path: "a.py", OID: "1"}}
	if got := DiffTrees(files, files); got != nil {
		t.Fatalf("identical trees must yield no changes: %+v", got)
	}
}

func TestDiffFindings(t *testing.T) {
	t.Parallel()
	oldF := []finding.Finding{
		{Rule: "R1", File: "a.py", Evidence: "x"},
		{Rule: "R2", File: "b.py", Evidence: "y"},
	}
	newF := []finding.Finding{
		{Rule: "R1", File: "a.py", Evidence: "x"},
		{Rule: "R3", File: "c.py", Evidence: "z"},
	}
	added, resolved := DiffFindings(oldF, newF)
	if len(added) != 1 || added[0].Rule != "R3" {
		t.Fatalf("added = %+v", added)
	}
	if len(resolved) != 1 || resolved[0].Rule != "R2" {
		t.Fatalf("resolved = %+v", resolved)
	}
}

func TestDiffFindingsEmpty(t *testing.T) {
	t.Parallel()
	added, resolved := DiffFindings(nil, nil)
	if added != nil || resolved != nil {
		t.Fatalf("added=%v resolved=%v", added, resolved)
	}
}
