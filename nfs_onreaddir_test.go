package nfs

// Regression for READDIR resumption from the '..' cookie: contents
// cookies start at 2 (0 and 1 are '.' and '..'), so the previous
// resume test `cookie == obj.Cookie` never fired for cookie 1 and a
// READDIR resuming from it returned an empty, EOF-true directory
// (cthon04 special/telldir over the agent-data-workspace compliance
// mount). RFC 1813: READDIR returns the entries FOLLOWING the cookie
// position.

import (
	"bytes"
	"context"
	"testing"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/willscott/go-nfs-client/nfs/xdr"
)

func readDirReply(t *testing.T, handler Handler, cookie uint64) []byte {
	t.Helper()
	// READDIR3args: nfs_fh3 handle, cookie u64, cookieverif u64, count u32.
	var body bytes.Buffer
	if err := xdr.Write(&body, []byte("")); err != nil {
		t.Fatal(err)
	}
	if err := xdr.Write(&body, cookie); err != nil {
		t.Fatal(err)
	}
	if err := xdr.Write(&body, uint64(0)); err != nil {
		t.Fatal(err)
	}
	if err := xdr.Write(&body, uint32(8192)); err != nil {
		t.Fatal(err)
	}
	w := &response{
		writer:    bytes.NewBuffer(nil),
		req:       &request{xid: 1, Body: bytes.NewReader(body.Bytes())},
		responded: true, // skip the RPC header; assert the NFS body alone
		errorFmt:  opAttrErrorFormatter,
	}
	if err := onReadDir(context.Background(), w, handler); err != nil {
		t.Fatalf("onReadDir(cookie=%d): %v", cookie, err)
	}
	return w.writer.Bytes()
}

func TestOnReadDir_ResumeFromDotdotCookie(t *testing.T) {
	dir := t.TempDir()
	fs := osfs.New(dir)
	handler := &onLinkStubHandler{fs: fs}

	for _, name := range []string{"alpha.txt", "beta.txt", "gamma.txt"} {
		f, err := fs.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	// Resuming from cookie 1 (after '..') must return the whole
	// contents listing, not an empty directory.
	reply := readDirReply(t, handler, 1)
	for _, name := range []string{"alpha.txt", "beta.txt", "gamma.txt"} {
		if !bytes.Contains(reply, []byte(name)) {
			t.Fatalf("resume from cookie 1: %q missing from the reply", name)
		}
	}
}

func TestOnReadDir_ResumeFromEntryCookie(t *testing.T) {
	dir := t.TempDir()
	fs := osfs.New(dir)
	handler := &onLinkStubHandler{fs: fs}

	for _, name := range []string{"alpha.txt", "beta.txt", "gamma.txt"} {
		f, err := fs.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	// Sorted contents: alpha(2), beta(3), gamma(4). Resuming from
	// cookie 3 returns the entries following beta.
	reply := readDirReply(t, handler, 3)
	if !bytes.Contains(reply, []byte("gamma.txt")) {
		t.Fatal("resume from cookie 3: gamma.txt missing from the reply")
	}
	if bytes.Contains(reply, []byte("alpha.txt")) || bytes.Contains(reply, []byte("beta.txt")) {
		t.Fatal("resume from cookie 3: entries at or before the cookie leaked into the reply")
	}
}

func TestOnReadDir_FullListing(t *testing.T) {
	dir := t.TempDir()
	fs := osfs.New(dir)
	handler := &onLinkStubHandler{fs: fs}

	for _, name := range []string{"alpha.txt", "beta.txt"} {
		f, err := fs.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	reply := readDirReply(t, handler, 0)
	for _, name := range []string{"alpha.txt", "beta.txt"} {
		if !bytes.Contains(reply, []byte(name)) {
			t.Fatalf("full listing: %q missing from the reply", name)
		}
	}
}
