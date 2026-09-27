package nfs

import (
	"fmt"
	"syscall"
	"testing"
)

// Deep or overlong component paths must surface as NFS3ERR_NAMETOOLONG,
// not flatten into EACCES/IO: the overlay's path-budget guard
// (agent-data-workspace issue #351) returns ENAMETOOLONG explicitly so
// a client can tell "name too long" from "permission denied".
func TestRefineFsErrnoStatus_NameTooLong(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want NFSStatus
		ok   bool
	}{
		{"enametoolong bare", syscall.ENAMETOOLONG, NFSStatusNameTooLong, true},
		{"enametoolong wrapped", fmt.Errorf("checkPathBudget: %w", syscall.ENAMETOOLONG), NFSStatusNameTooLong, true},
		{"access passthrough", syscall.EACCES, 0, false},
		{"nil", nil, 0, false},
	}
	for _, tc := range cases {
		got, ok := refineFsErrnoStatus(tc.err)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("%s: refineFsErrnoStatus(%v) = %d,%v; want %d,%v", tc.name, tc.err, got, ok, tc.want, tc.ok)
		}
	}
}
