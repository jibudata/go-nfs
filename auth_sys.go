package nfs

// AUTH_SYS (AUTH_UNIX, flavor 1) caller credential parsing (issue
// jibudata/agent-data-workspace#80). The credential body is the ONC RPC
// XDR structure: stamp, machinename, uid, gid, supplementary-gids vector.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
)

// authSysFlavor is the ONC RPC auth flavor for AUTH_SYS (RFC 5531 §8.2).
const authSysFlavor = 1

// maxAuthSysGIDs bounds the supplementary-group vector so a hostile
// credential body cannot balloon memory.
const maxAuthSysGIDs = 64

// CallerCredentials is the identity an NFS client asserted for one RPC
// under AUTH_SYS. The server does not verify the assertion; consumers
// decide how much to trust it (see OwnershipEnforcer).
type CallerCredentials struct {
	UID  uint32
	GID  uint32
	GIDs []uint32
}

type callerCredentialsKey struct{}

// WithCallerCredentials returns ctx carrying cc for handler consumption.
func WithCallerCredentials(ctx context.Context, cc *CallerCredentials) context.Context {
	return context.WithValue(ctx, callerCredentialsKey{}, cc)
}

// CallerCredentialsFromContext reports the AUTH_SYS identity asserted on
// the request, or nil for AUTH_NONE / unparseable credentials.
func CallerCredentialsFromContext(ctx context.Context) *CallerCredentials {
	cc, _ := ctx.Value(callerCredentialsKey{}).(*CallerCredentials)
	return cc
}

// readXdrOpaque reads an XDR counted byte string and consumes its
// zero-padding. (go-nfs-client's ReadOpaque skips the pad, which would
// desync every later field of the credential.)
func readXdrOpaque(r io.Reader) ([]byte, error) {
	var l uint32
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, err
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	if pad := (4 - int(l)%4) % 4; pad > 0 {
		if _, err := io.CopyN(io.Discard, r, int64(pad)); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// parseAuthSys decodes an AUTH_SYS credential body: stamp (ignored),
// machinename (ignored), uid, gid, and the supplementary-gids vector.
func parseAuthSys(body []byte) (*CallerCredentials, error) {
	r := bytes.NewReader(body)
	dec := func() (uint32, error) {
		var v uint32
		if err := binary.Read(r, binary.BigEndian, &v); err != nil {
			return 0, err
		}
		return v, nil
	}

	if _, err := dec(); err != nil { // stamp
		return nil, fmt.Errorf("auth_sys stamp: %w", err)
	}
	if _, err := readXdrOpaque(r); err != nil { // machinename
		return nil, fmt.Errorf("auth_sys machinename: %w", err)
	}
	uid, err := dec()
	if err != nil {
		return nil, fmt.Errorf("auth_sys uid: %w", err)
	}
	gid, err := dec()
	if err != nil {
		return nil, fmt.Errorf("auth_sys gid: %w", err)
	}
	ngids, err := dec()
	if err != nil {
		return nil, fmt.Errorf("auth_sys gid count: %w", err)
	}
	if ngids > maxAuthSysGIDs {
		return nil, fmt.Errorf("auth_sys gid count %d exceeds %d", ngids, maxAuthSysGIDs)
	}
	gids := make([]uint32, 0, ngids)
	for i := uint32(0); i < ngids; i++ {
		g, err := dec()
		if err != nil {
			return nil, fmt.Errorf("auth_sys gids[%d]: %w", i, err)
		}
		gids = append(gids, g)
	}
	return &CallerCredentials{UID: uid, GID: gid, GIDs: gids}, nil
}
