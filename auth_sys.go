package nfs

// AUTH_SYS (AUTH_UNIX, flavor 1) caller credential parsing (issue
// jibudata/agent-data-workspace#80). The credential body is the ONC RPC
// XDR structure: stamp, machinename, uid, gid, gids-vector.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/willscott/go-nfs-client/nfs/xdr"
)

// authSysFlavor is the ONC RPC auth flavor for AUTH_SYS (RFC 5531 §8.2).
const authSysFlavor = 1

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

// parseAuthSys decodes an AUTH_SYS credential body: stamp (ignored),
// machinename (ignored), uid, gid, and the supplementary-gids vector.
func parseAuthSys(body []byte) (*CallerCredentials, error) {
	dec := xdr.NewReader(bytes.NewReader(body))
	stamp, err := dec.ReadUInt()
	if err != nil {
		return nil, fmt.Errorf("auth_sys stamp: %w", err)
	}
	_ = stamp
	machine, err := dec.ReadString()
	if err != nil {
		return nil, fmt.Errorf("auth_sys machinename: %w", err)
	}
	_ = machine
	uid, err := dec.ReadUInt()
	if err != nil {
		return nil, fmt.Errorf("auth_sys uid: %w", err)
	}
	gid, err := dec.ReadUInt()
	if err != nil {
		return nil, fmt.Errorf("auth_sys gid: %w", err)
	}
	ngids, err := dec.ReadUInt()
	if err != nil {
		return nil, fmt.Errorf("auth_sys gid len: %w", err)
	}
	// Bound the vector so a hostile credential body cannot balloon memory.
	if ngids > 64 {
		return nil, fmt.Errorf("auth_sys gid count %d exceeds 64", ngids)
	}
	cc := &CallerCredentials{UID: uid, GID: gid}
	if ngids > 0 {
		cc.GIDs = make([]uint32, 0, ngids)
		for i := uint32(0); i < ngids; i++ {
			g, err := dec.ReadUInt()
			if err != nil {
				return nil, fmt.Errorf("auth_sys gid[%d]: %w", i, err)
			}
			cc.GIDs = append(cc.GIDs, g)
		}
	}
	return cc, nil
}

// parseAuthSysLen is a sanity companion used by tests: total XDR bytes a
// well-formed credential of this shape occupies.
func parseAuthSysLen(machinename string, ngids uint32) int {
	n := 4 + 4 // stamp + machinename length
	n += (len(machinename) + 3) &^ 3
	n += 4 * 3 // uid, gid, gidlen
	n += 4 * ngids
	return n
}

// errShortAuthSys is returned when a credential body ends mid-field.
var errShortAuthSys = errors.New("truncated auth_sys credential")

// ensureLittleEndianHelpersUsed keeps binary imported for potential
// platform-specific credential probes without an unused-import failure.
var _ = binary.LittleEndian
