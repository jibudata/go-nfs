package helpers_test

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/go-git/go-billy/v5/osfs"
	nfshelper "github.com/willscott/go-nfs/helpers"
)

// TestCachingHandler_ConcurrentChurn hammers ToHandle/FromHandle with
// concurrent unique-path creation (forcing LRU eviction) while other
// goroutines keep re-resolving a pinned working set. Regression for the
// eviction bookkeeping race: GetOldest-then-Add let concurrent Gets
// re-order the LRU between the read and the Add, purging the reverse
// mapping of a still-live handle while a dead one lingered elsewhere —
// surfacing as spurious ESTALE for clients under concurrent CREATE.
// Run with -race.
func TestCachingHandler_ConcurrentChurn(t *testing.T) {
	dir := t.TempDir()
	fs := osfs.New(dir)
	handler := nfshelper.NewCachingHandler(nfshelper.NewNullAuthHandler(fs), 256)

	// Pinned working set: hot handles other goroutines keep resolving.
	pinned := make([][]byte, 8)
	for i := 0; i < 8; i++ {
		p := fmt.Sprintf("pinned_%d", i)
		if err := os.WriteFile(fs.Join(dir, p), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		pinned[i] = handler.ToHandle(fs, []string{p})
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var staleErrs int64

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, fh := range pinned {
					if _, _, err := handler.FromHandle(fh); err != nil {
						fmt.Fprintln(os.Stderr, "pinned handle went stale:", err)
						staleErrs++
						return
					}
				}
			}
		}()
	}

	const churn = 20000
	for i := 0; i < churn; i++ {
		p := fmt.Sprintf("churn_%06d", i)
		if err := os.WriteFile(fs.Join(dir, p), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		fh := handler.ToHandle(fs, []string{p})
		// The just-created handle must resolve immediately (a miss here
		// is the client-visible ESTALE right after CREATE).
		if _, _, err := handler.FromHandle(fh); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("fresh handle #%d failed to resolve: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
	if staleErrs > 0 {
		t.Fatalf("%d pinned-handle resolutions went stale during churn", staleErrs)
	}
}
