package nfs

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// jibudata/agent-data-workspace#351: backing-filesystem errors must map
// to the most specific NFSv3 status — ENAMETOOLONG used to fall through
// the NFSStatusIO catch-all, so deep-path clients saw an EIO cascade
// (chmod/stat/unlink/rename on a too-long path) instead of
// NFS3ERR_NAMETOOLONG, and could not distinguish name-length rejections
// from genuine I/O failure.
func TestStatusFromOSError(t *testing.T) {
	cases := []struct {
		err  error
		want NFSStatus
	}{
		{nil, NFSStatusOk},
		{os.ErrNotExist, NFSStatusNoEnt},
		{syscall.ENOENT, NFSStatusNoEnt},
		{os.ErrExist, NFSStatusExist},
		{syscall.EEXIST, NFSStatusExist},
		{syscall.ENAMETOOLONG, NFSStatusNameTooLong},
		{&os.PathError{Op: "mkdir", Path: "x", Err: syscall.ENAMETOOLONG}, NFSStatusNameTooLong},
		{os.ErrPermission, NFSStatusAccess},
		{syscall.EACCES, NFSStatusAccess},
		{syscall.ENOTDIR, NFSStatusNotDir},
		{syscall.EISDIR, NFSStatusIsDir},
		{syscall.ENOTEMPTY, NFSStatusNotEmpty},
		{syscall.ENOSPC, NFSStatusNoSPC},
		{syscall.EDQUOT, NFSStatusDQuot},
		{syscall.EFBIG, NFSStatusFBig},
		{errors.New("something odd"), NFSStatusIO},
	}
	for _, c := range cases {
		if got := statusFromOSError(c.err); got != c.want {
			t.Errorf("statusFromOSError(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}
