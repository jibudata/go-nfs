package nfs_test

// Acceptance tests for the handle-keyed write fd cache (issue #235 of
// agent-data-workspace): hit avoids re-open, rename decouples identity
// from the name, LRU eviction closes, capacity 0 disables, idle TTL
// sweeps, and same-handle writes serialize.

import (
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	billy "github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-billy/v5/util"
	nfs "github.com/jibudata/go-nfs"
	"github.com/jibudata/go-nfs/helpers"
	"github.com/willscott/go-nfs-client/nfs/rpc"
	nfsc "github.com/willscott/go-nfs-client/nfs"
)

// countingFS records every OpenFile (name) and every Close so tests can
// prove hit counts and eviction closes.
type countingFS struct {
	billy.Filesystem
	mu      sync.Mutex
	opens   map[string]int
	closed  []string
	slowDur time.Duration
}

func newCountingFS() *countingFS {
	return &countingFS{Filesystem: memfs.New(), opens: map[string]int{}}
}

// norm collapses the leading slash: memfs-direct fixture writes arrive
// as "/f.txt" while the server opens via fs.Join(path...) = "f.txt" —
// same file, one key.
func norm(name string) string { return strings.TrimPrefix(name, "/") }

func (c *countingFS) openCount(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.opens[norm(name)]
}

func (c *countingFS) closeCount(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, cl := range c.closed {
		if cl == norm(name) {
			n++
		}
	}
	return n
}

func (c *countingFS) Create(filename string) (billy.File, error) {
	return c.OpenFile(filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o666)
}

func (c *countingFS) Open(filename string) (billy.File, error) {
	return c.OpenFile(filename, os.O_RDONLY, 0)
}

func (c *countingFS) OpenFile(filename string, flag int, perm os.FileMode) (billy.File, error) {
	f, err := c.Filesystem.OpenFile(filename, flag, perm)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.opens[norm(filename)]++
	c.mu.Unlock()
	return &countingFile{File: f, c: c, name: filename}, nil
}

type countingFile struct {
	billy.File
	c    *countingFS
	name string
}

func (f *countingFile) Close() error {
	f.c.mu.Lock()
	f.c.closed = append(f.c.closed, norm(f.name))
	f.c.mu.Unlock()
	return f.File.Close()
}

func (f *countingFile) Write(p []byte) (int, error) {
	if d := f.c.slowDur; d > 0 {
		time.Sleep(d)
	}
	return f.File.Write(p)
}

// startCachedServer mounts fs over a loopback NFS server with the
// write handle cache configured per the arguments and returns a
// mounted client target.
func startCachedServer(t *testing.T, fs billy.Filesystem, capacity int, idleTTL time.Duration) *nfsc.Target {
	t.Helper()
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	handler := helpers.NewCachingHandler(helpers.NewNullAuthHandler(fs), 1024)
	srv := &nfs.Server{Handler: handler}
	nfs.WithWriteHandleCache(srv, capacity, idleTTL)
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = listener.Close() })

	c, err := rpc.DialTCP(listener.Addr().Network(), listener.Addr().(*net.TCPAddr).String(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	var mounter nfsc.Mount
	mounter.Client = c
	target, err := mounter.Mount("/", rpc.AuthNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mounter.Unmount() })
	return target
}

// Hit: the second WRITE on the same handle goes through the cached fd —
// OpenFile runs exactly once for the file.
func TestWriteHandleCache_HitAvoidsReopen(t *testing.T) {
	mem := newCountingFS()
	if err := util.WriteFile(mem, "/f.txt", []byte("seed"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := startCachedServer(t, mem, 8, time.Minute)

	f, err := target.OpenFile("/f.txt", 0666)
	if err != nil {
		t.Fatal(err)
	}
	base := mem.openCount("/f.txt") // fixture-direct opens
	if _, err := f.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if got := mem.openCount("/f.txt"); got != base+1 {
		t.Fatalf("server opens after first WRITE = %d, want %d", got, base+1)
	}
	if _, err := f.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if got := mem.openCount("/f.txt"); got != base+1 {
		t.Fatalf("second WRITE re-opened the file (%d opens); cache miss", got)
	}
	_ = f.Close()

	got, err := util.ReadFile(mem, "/f.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), "onetwo") {
		t.Fatalf("content = %q, want onetwo…", got)
	}
}

// Identity follows the handle, not the name: after the underlying path
// moves (renamed directly on the billy fs, bypassing NFS), writes
// through the cached fd still land in the file — now at its new name.
func TestWriteHandleCache_RenameDecouplesIdentity(t *testing.T) {
	mem := newCountingFS()
	if err := util.WriteFile(mem, "/f.txt", []byte("seed"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := startCachedServer(t, mem, 8, time.Minute)

	f, err := target.OpenFile("/f.txt", 0666)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	// Rename the underlying path directly (no NFS RENAME): the cached
	// handle still maps to the old name, the cached fd to the same file.
	if err := mem.Rename("/f.txt", "/g.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("-after")); err != nil {
		t.Fatalf("write through cached fd after underlying rename: %v", err)
	}
	_ = f.Close()
	got, err := util.ReadFile(mem, "/g.txt")
	if err != nil {
		t.Fatalf("renamed file missing: %v", err)
	}
	// The client writes at its own offset 0 (overwriting the seed) —
	// the point is that the bytes landed in the file at its NEW name.
	if string(got) != "before-after" {
		t.Fatalf("content at new path = %q, want before-after", got)
	}
}

// LRU: exceeding capacity evicts the least recently used entry and the
// eviction CLOSES its fd.
func TestWriteHandleCache_LRUEvictionCloses(t *testing.T) {
	mem := newCountingFS()
	for _, n := range []string{"/a.txt", "/b.txt"} {
		if err := util.WriteFile(mem, n, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	target := startCachedServer(t, mem, 1, time.Minute)
	baseCloseA, baseCloseB := mem.closeCount("/a.txt"), mem.closeCount("/b.txt")

	fa, err := target.OpenFile("/a.txt", 0666)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fa.Write([]byte("A")); err != nil {
		t.Fatal(err)
	}
	fb, err := target.OpenFile("/b.txt", 0666)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fb.Write([]byte("B")); err != nil {
		t.Fatal(err)
	}
	// /a.txt was evicted by /b.txt's registration: its fd is closed.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if mem.closeCount("/a.txt") > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if mem.closeCount("/a.txt") <= baseCloseA {
		t.Fatal("LRU eviction did not close /a.txt's fd")
	}
	if mem.closeCount("/b.txt") != baseCloseB {
		t.Fatal("live entry /b.txt was closed")
	}
	_ = fa.Close()
	_ = fb.Close()
}

// Capacity 0 = the mechanism is off: every WRITE opens by path and
// closes after the write (legacy behavior, zero diff).
func TestWriteHandleCache_ZeroDisables(t *testing.T) {
	mem := newCountingFS()
	if err := util.WriteFile(mem, "/f.txt", []byte("seed"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := startCachedServer(t, mem, 0, time.Minute)

	f, err := target.OpenFile("/f.txt", 0666)
	if err != nil {
		t.Fatal(err)
	}
	baseOpens, baseCloses := mem.openCount("/f.txt"), mem.closeCount("/f.txt")
	for i := 0; i < 2; i++ {
		if _, werr := f.Write([]byte("x")); werr != nil {
			t.Fatal(werr)
		}
	}
	_ = f.Close()
	if got := mem.openCount("/f.txt"); got != baseOpens+2 {
		t.Fatalf("disabled cache: server opens = %d, want %d (open per WRITE)", got, baseOpens+2)
	}
	if got := mem.closeCount("/f.txt"); got < baseCloses+2 {
		t.Fatalf("disabled cache: closes = %d, want >=%d (close per WRITE)", got, baseCloses+2)
	}
}

// Same-handle concurrent WRITEs queue on the per-entry mutex: both
// writes complete at their offsets (no lost update), and the server
// still opened the file exactly once.
func TestWriteHandleCache_PerEntrySerialization(t *testing.T) {
	mem := newCountingFS()
	mem.slowDur = 20 * time.Millisecond
	if err := util.WriteFile(mem, "/f.txt", []byte(strings.Repeat(".", 64)), 0o644); err != nil {
		t.Fatal(err)
	}
	target := startCachedServer(t, mem, 8, time.Minute)

	// Two client fds on the same path share one server-side handle.
	baseOpens := mem.openCount("/f.txt")
	f1, err := target.OpenFile("/f.txt", 0666)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := target.OpenFile("/f.txt", 0666)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); _, e := f1.Write([]byte("AAAA")); errs <- e }()
	go func() { defer wg.Done(); _, e := f2.Write([]byte("BBBB")); errs <- e }()
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatalf("concurrent write failed: %v", e)
		}
	}
	_ = f1.Close()
	_ = f2.Close()

	// One server-side open for both handles (fixture baseline + 1);
	// the closing ReadFile opens separately and is asserted around.
	if got := mem.openCount("/f.txt"); got != baseOpens+1 {
		t.Fatalf("opens = %d, want %d (both handles share the cached fd)", got, baseOpens+1)
	}
	got, err := util.ReadFile(mem, "/f.txt")
	if err != nil {
		t.Fatal(err)
	}
	// Both client fds start at offset 0, so the serialized winner takes
	// the head — but the loser's bytes must be COMPLETELY absent (no
	// byte-level interleave = the per-entry mutex held across the write).
	dots := strings.Repeat(".", 64)
	if string(got) != "AAAA"+dots[4:] && string(got) != "BBBB"+dots[4:] {
		t.Fatalf("content = %q, want a clean AAAA/BBBB winner (interleave = serialization broken)", got)
	}
}

// Idle TTL: an entry untouched past the TTL is closed and dropped by
// the next cache interaction.
func TestWriteHandleCache_IdleTTLSweep(t *testing.T) {
	mem := newCountingFS()
	if err := util.WriteFile(mem, "/f.txt", []byte("seed"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := startCachedServer(t, mem, 8, 120*time.Millisecond)
	baseOpens := mem.openCount("/f.txt")

	f, err := target.OpenFile("/f.txt", 0666)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	baseCloses := mem.closeCount("/f.txt")

	// Sleep past the TTL; the next write's cache interaction sweeps the
	// idle entry (close + drop) and re-opens by path.
	// Sleep past the TTL; the next write's cache interaction sweeps the
	// idle entry (close + drop) and re-opens by path.
	time.Sleep(250 * time.Millisecond)
	f2, err := target.OpenFile("/f.txt", 0666)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f2.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	_ = f2.Close()
	if mem.closeCount("/f.txt") <= baseCloses {
		t.Fatal("idle sweep did not close the stale entry")
	}
	if mem.openCount("/f.txt") != baseOpens+2 {
		t.Fatalf("opens = %d, want %d (sweep must re-open on the next write)", mem.openCount("/f.txt"), baseOpens+2)
	}
}
