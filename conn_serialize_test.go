package nfs

// Regression for the serializer deadlock: when a client stops reading
// responses, the serializeWrites goroutine used to exit silently — the
// serve loop then blocked forever on the full writeSerializer channel,
// the client's requests went unanswered, and a hard mount hung until
// rebooted (agent-data-workspace #512). The serializer must tear the
// connection down (close + cancel) so the client can reconnect.

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestSerializeWrites_StuckClientAbortsConnection drives a connection
// over net.Pipe where the peer reads the first response then stops. The
// second response cannot be flushed: the serializer must give up at the
// write deadline, close the pipe, and cancel the serve context instead
// of deadlocking.
func TestSerializeWrites_StuckClientAbortsConnection(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	c := &conn{
		Server:          &Server{Handler: nil},
		writeSerializer: make(chan []byte, 1),
		Conn:            server,
		writeTimeout:    300 * time.Millisecond,
	}
	connCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.cancel = cancel
	done := make(chan struct{})
	go func() {
		c.serializeWrites(connCtx)
		close(done)
	}()

	// Peer: read exactly the first response (one flush = one chunk on
	// the synchronous pipe), then stop having any pending read — that
	// is what makes the second response's flush block forever.
	go func() {
		buf := make([]byte, 64)
		_, _ = client.Read(buf) // response 1 (fragment header + body)
		// deliberate: no further reads — the wedged kernel client
	}()

	c.writeSerializer <- []byte("response-one")
	// Response 2 cannot be flushed: the peer stopped reading and the
	// pipe has no buffer. The deadline must fire, and abort must close
	// the pipe and cancel the context.
	c.writeSerializer <- []byte("response-two-cannot-flush")

	select {
	case <-connCtx.Done():
		// aborted: context released. ✓
	case <-time.After(5 * time.Second):
		t.Fatal("serializeWrites did not abort after the stuck-client write deadline; the pipeline would deadlock")
	}
	select {
	case <-done:
		// serializer exited instead of wedging. ✓
	case <-time.After(5 * time.Second):
		t.Fatal("serializeWrites goroutine did not exit after abort")
	}
}

// TestSerializeWrites_HappyPathUnchanged guards the fix against
// regressing the normal case: a reading peer must still receive every
// response, in order.
func TestSerializeWrites_HappyPathUnchanged(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	c := &conn{
		Server:          &Server{Handler: nil},
		writeSerializer: make(chan []byte, 1),
		Conn:            server,
		writeTimeout:    5 * time.Second,
	}
	connCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.cancel = cancel
	go c.serializeWrites(connCtx)

	replies := make(chan string, 2)
	go func() {
		buf := make([]byte, 128)
		// header (4) + payload, per response
		if _, err := client.Read(buf); err != nil {
			replies <- "ERR"
			return
		}
		replies <- "one"
		if _, err := client.Read(buf); err != nil {
			replies <- "ERR"
			return
		}
		replies <- "two"
	}()

	c.writeSerializer <- []byte("first")
	c.writeSerializer <- []byte("second")

	for _, want := range []string{"one", "two"} {
		select {
		case got := <-replies:
			if got != want {
				t.Fatalf("reply %q, want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for reply %q", want)
		}
	}
}
