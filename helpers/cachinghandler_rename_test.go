package helpers

// Regression for workspace issues #100/#129: after RENAME, cached handles
// under the old path must resolve to the NEW path (content keeps flowing
// to the same inode), and handles at the replaced target must be
// invalidated rather than silently serving the replaced file.

import (
	"os"
	"testing"

	billy "github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
)

func newTestHandler() (billy.Filesystem, *CachingHandler) {
	fs := memfs.New()
	_ = fs.MkdirAll("/d", 0o755)
	h := NewCachingHandler(NewNullAuthHandler(fs), 1024).(*CachingHandler)
	return fs, h
}

func TestRenameHandles_MigratesOldToNew(t *testing.T) {
	fs, h := newTestHandler()

	old := []string{"d", "a.txt"}
	fh := h.ToHandle(fs, old)

	h.RenameHandles(fs, "/d/a.txt", "/d/b.txt")

	gotFs, gotPath, err := h.FromHandle(fh)
	if err != nil {
		t.Fatalf("pre-rename handle after rename: %v", err)
	}
	if gotFs != billy.Filesystem(fs) && len(gotPath) != 2 || gotPath[0] != "d" || gotPath[1] != "b.txt" {
		t.Fatalf("migrated handle resolves to %v, want [d b.txt]", gotPath)
	}
}

func TestRenameHandles_MigratesSubtree(t *testing.T) {
	fs, h := newTestHandler()

	child := []string{"dirA", "child.txt"}
	fh := h.ToHandle(fs, child)

	h.RenameHandles(fs, "/dirA", "/dirB")

	_, gotPath, err := h.FromHandle(fh)
	if err != nil {
		t.Fatalf("child handle after dir rename: %v", err)
	}
	if gotPath[0] != "dirB" || gotPath[1] != "child.txt" {
		t.Fatalf("subtree-migrated handle resolves to %v, want [dirB child.txt]", gotPath)
	}
}

func TestRenameHandles_InvalidatesReplacedTarget(t *testing.T) {
	fs, h := newTestHandler()

	target := []string{"d", "b.txt"}
	targetFH := h.ToHandle(fs, target)

	h.RenameHandles(fs, "/d/a.txt", "/d/b.txt")

	if _, _, err := h.FromHandle(targetFH); err == nil {
		t.Fatal("replaced target handle still resolves; must be invalidated")
	}
}

func TestRenameHandles_UnrelatedPathsUntouched(t *testing.T) {
	fs, h := newTestHandler()

	other := []string{"d", "other.txt"}
	fh := h.ToHandle(fs, other)

	h.RenameHandles(fs, "/d/a.txt", "/d/b.txt")

	_, gotPath, err := h.FromHandle(fh)
	if err != nil || gotPath[0] != "d" || gotPath[1] != "other.txt" {
		t.Fatalf("unrelated handle disturbed: %v %v", gotPath, err)
	}
}

var _ = os.FileMode(0)
