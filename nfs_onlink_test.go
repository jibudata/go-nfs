package nfs

// Regression for the LINK wire layout: LINK3args is (file nfs_fh3,
// link diropargs3) and LINK3res is (post_op_attr, wcc_data) —
// RFC 1813 §3.3.15. The previous implementation parsed SYMLINK's
// layout (diropargs3 + sattr + nfspath3), so a real LINK request died
// with NFS3ERR_GARBAGE_ARGS before reaching the filesystem (found by
// cthon04 basic/test7 over the agent-data-workspace compliance mount).

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	billy "github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
)

type onLinkStubHandler struct {
	Handler
	fs billy.Filesystem
}

func (h *onLinkStubHandler) ToHandle(_ billy.Filesystem, path []string) []byte {
	return []byte(strings.Join(path, "/"))
}

func (h *onLinkStubHandler) FromHandle(fh []byte) (billy.Filesystem, []string, error) {
	if len(fh) == 0 {
		return h.fs, []string{}, nil
	}
	return h.fs, strings.Split(string(fh), "/"), nil
}

func (h *onLinkStubHandler) Change(fs billy.Filesystem) billy.Change {
	return onLinkOsChanger{root: fs.Root()}
}

// onLinkOsChanger implements UnixChange against the real OS, rooted at
// the billy filesystem root, mirroring what shadowFS-style backends do.
type onLinkOsChanger struct {
	root string
}

func (c onLinkOsChanger) abs(name string) string { return filepath.Join(c.root, name) }
func (c onLinkOsChanger) Link(path, link string) error {
	return os.Link(c.abs(path), c.abs(link))
}
func (c onLinkOsChanger) Chmod(name string, mode os.FileMode) error {
	return os.Chmod(c.abs(name), mode)
}
func (c onLinkOsChanger) Lchown(name string, uid, gid int) error {
	return os.Lchown(c.abs(name), uid, gid)
}
func (c onLinkOsChanger) Chown(name string, uid, gid int) error {
	return os.Chown(c.abs(name), uid, gid)
}
func (c onLinkOsChanger) Chtimes(name string, atime, mtime time.Time) error {
	return os.Chtimes(c.abs(name), atime, mtime)
}
func (c onLinkOsChanger) Mknod(string, uint32, uint32, uint32) error { return syscall.ENOSYS }
func (c onLinkOsChanger) Mkfifo(string, uint32) error                { return syscall.ENOSYS }
func (c onLinkOsChanger) Socket(string) error                        { return syscall.ENOSYS }

func TestOnLink_CreatesHardlinkFromRealArgs(t *testing.T) {
	dir := t.TempDir()
	fs := osfs.New(dir)
	handler := &onLinkStubHandler{fs: fs}

	f, err := fs.Create("src.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	// LINK3args (RFC 1813 §3.3.15), encoded by hand as the kernel
	// client would: nfs_fh3 = opaque("src.txt"), then diropargs3 =
	// (opaque("" dir handle), string("link.txt")). The bytes are
	// written directly because go-xdr2 encodes an empty []byte without
	// its length prefix, which no real client ever puts on the wire.
	var body bytes.Buffer
	body.Write([]byte{0, 0, 0, 7, 's', 'r', 'c', '.', 't', 'x', 't', 0})   // fh: len 7 + pad
	body.Write([]byte{0, 0, 0, 0})                                         // link.dir: opaque len 0
	body.Write([]byte{0, 0, 0, 8, 'l', 'i', 'n', 'k', '.', 't', 'x', 't'}) // link.name

	w := &response{
		writer:    bytes.NewBuffer(nil),
		req:       &request{xid: 1, Body: bytes.NewReader(body.Bytes())},
		responded: true, // skip the RPC header; assert the NFS body alone
		errorFmt:  wccDataErrorFormatter,
	}
	if err := onLink(context.Background(), w, handler); err != nil {
		t.Fatalf("onLink with RFC 1813 arg layout: %v", err)
	}

	fi1, err := os.Stat(filepath.Join(dir, "src.txt"))
	if err != nil {
		t.Fatal(err)
	}
	fi2, err := os.Stat(filepath.Join(dir, "link.txt"))
	if err != nil {
		t.Fatalf("link target missing after onLink: %v", err)
	}
	if !os.SameFile(fi1, fi2) {
		t.Fatal("link.txt is not a hard link to src.txt")
	}

	// Reply shape: status then the resok body must be non-empty (source
	// post_op_attr + linkdir wcc), and status must be NFS3_OK (0).
	reply := w.writer.Bytes()
	status := uint32(0xffffffff)
	for _, b := range reply[0:4] {
		status = (status << 8) | uint32(b)
	}
	if status != 0 {
		t.Fatalf("reply status = %d, want 0", status)
	}
	if len(reply) <= 4 {
		t.Fatal("reply carries no resok body (post_op_attr + wcc_data)")
	}
}

func TestOnLink_TargetExists(t *testing.T) {
	dir := t.TempDir()
	fs := osfs.New(dir)
	handler := &onLinkStubHandler{fs: fs}

	for _, name := range []string{"src.txt", "link.txt"} {
		f, err := fs.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	var body bytes.Buffer
	body.Write([]byte{0, 0, 0, 7, 's', 'r', 'c', '.', 't', 'x', 't', 0})   // fh: len 7 + pad
	body.Write([]byte{0, 0, 0, 0})                                         // link.dir: opaque len 0
	body.Write([]byte{0, 0, 0, 8, 'l', 'i', 'n', 'k', '.', 't', 'x', 't'}) // link.name

	w := &response{
		writer:   bytes.NewBuffer(nil),
		req:      &request{xid: 1, Body: bytes.NewReader(body.Bytes())},
		errorFmt: wccDataErrorFormatter,
	}
	err := onLink(context.Background(), w, handler)
	var st *NFSStatusError
	if !errors.As(err, &st) || st.NFSStatus != NFSStatusExist {
		t.Fatalf("onLink over existing target: got %v, want NFSStatusExist", err)
	}
}

func TestOnLink_SourceMissing(t *testing.T) {
	dir := t.TempDir()
	fs := osfs.New(dir)
	handler := &onLinkStubHandler{fs: fs}

	var body bytes.Buffer
	body.Write([]byte{0, 0, 0, 8, 'n', 'o', 'p', 'e', '.', 't', 'x', 't'}) // fh: len 8
	body.Write([]byte{0, 0, 0, 0})                                         // link.dir: opaque len 0
	body.Write([]byte{0, 0, 0, 8, 'l', 'i', 'n', 'k', '.', 't', 'x', 't'}) // link.name

	w := &response{
		writer:   bytes.NewBuffer(nil),
		req:      &request{xid: 1, Body: bytes.NewReader(body.Bytes())},
		errorFmt: wccDataErrorFormatter,
	}
	err := onLink(context.Background(), w, handler)
	var st *NFSStatusError
	if !errors.As(err, &st) || st.NFSStatus != NFSStatusNoEnt {
		t.Fatalf("onLink with missing source: got %v, want NFSStatusNoEnt", err)
	}
}
