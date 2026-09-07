package nfs

// OwnershipEnforcer is an optional interface the exported billy.Filesystem
// may implement to enforce POSIX-style ownership/permission semantics that
// a userspace COW filesystem maintains itself (issue
// jibudata/agent-data-workspace#80). When the filesystem does not implement
// it, behaviour is unchanged and every operation is permitted, matching
// go-nfs' historical always-root model.

import (
	"context"
	"os"

	"github.com/go-git/go-billy/v5"
)

// OwnershipEnforcer is consulted by the NFS write-path handlers before a
// mutation touches the filesystem. callerUID is the AUTH_SYS uid the client
// asserted for the request; implementations decide the trust model (a
// common one: allow uid 0, allow the file owner, check directory write
// bits, else EPERM).
type OwnershipEnforcer interface {
	// EnforceSetAttr is consulted before chmod/chown/truncate/utimes on path.
	// info is the Lstat of the target. Return an error (e.g. EPERM) to deny.
	EnforceSetAttr(path string, callerUID uint32, info os.FileInfo) error
	// EnforceDirWrite is consulted before create/mkdir/symlink/mknod/link
	// inside dirPath, before unlink/rmdir of an entry of dirPath, and before
	// either rename endpoint. info is the Lstat of the directory. Return an
	// error (e.g. EACCES) to deny.
	EnforceDirWrite(dirPath string, callerUID uint32, info os.FileInfo) error
	// NoteCreated records the owner a freshly created entry (file, dir,
	// symlink, mknod) should carry. Best-effort: an error is logged, not
	// returned to the client.
	NoteCreated(path string, callerUID uint32)
}

// callerUIDFromContext reports the AUTH_SYS uid asserted on the request,
// defaulting to 0 (root) for AUTH_NONE — the historical always-root model.
func callerUIDFromContext(ctx context.Context) uint32 {
	if cc := CallerCredentialsFromContext(ctx); cc != nil {
		return cc.UID
	}
	return 0
}

// enforceDirWrite consults fs's OwnershipEnforcer, if any, about a mutation
// inside dir; deny maps to NFSERR_ACCES. dirPath is joined from path parts.
func enforceDirWrite(ctx context.Context, fs billy.Filesystem, parts []string) *NFSStatusError {
	en, ok := fs.(OwnershipEnforcer)
	if !ok {
		return nil
	}
	dirPath := fs.Join(parts...)
	info, err := fs.Lstat(dirPath)
	if err != nil {
		return nil // stat problems surface on the actual operation
	}
	if err := en.EnforceDirWrite(dirPath, callerUIDFromContext(ctx), info); err != nil {
		return &NFSStatusError{NFSStatusAccess, err}
	}
	return nil
}
