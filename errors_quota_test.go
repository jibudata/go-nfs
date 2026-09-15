package nfs

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
)

// Quota/space errors from billy filesystems must surface with their
// POSIX semantics on the wire: EDQUOT → NFS3ERR_DQUOT, ENOSPC →
// NFS3ERR_NOSPC, EFBIG → NFS3ERR_FBIG — including through fmt.Errorf
// wrapping layers (issue #178).
func TestRefineQuotaStatus(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want NFSStatus
		ok   bool
	}{
		{"edquot bare", syscall.EDQUOT, NFSStatusDQuot, true},
		{"edquot wrapped", fmt.Errorf("openFile: %w", syscall.EDQUOT), NFSStatusDQuot, true},
		{"enospc bare", syscall.ENOSPC, NFSStatusNoSPC, true},
		{"enospc wrapped", fmt.Errorf("publish: %w", fmt.Errorf("stage: %w", syscall.ENOSPC)), NFSStatusNoSPC, true},
		{"efbig", syscall.EFBIG, NFSStatusFBig, true},
		{"plain errno passthrough", syscall.EACCES, 0, false},
		{"non-errno", errors.New("boom"), 0, false},
		{"nil", nil, 0, false},
	}
	for _, tc := range cases {
		got, ok := refineQuotaStatus(tc.err)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("%s: refineQuotaStatus(%v) = %d,%v; want %d,%v", tc.name, tc.err, got, ok, tc.want, tc.ok)
		}
	}
}
