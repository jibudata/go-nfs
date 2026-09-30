package nfs

import (
	"bytes"
	"context"
	"os"

	"github.com/go-git/go-billy/v5"
	"github.com/willscott/go-nfs-client/nfs/xdr"
)

// LINK (RFC 1813 §3.3.15): LINK3args is the source file's handle plus a
// diropargs3 naming the new link; LINK3res carries the source file's
// post-op attributes and the link directory's wcc — no file handle is
// returned, clients LOOKUP the new name. The previous implementation
// parsed SYMLINK's wire layout (diropargs3 + sattr + nfspath3) and
// replied with a symlink-shaped body, so every real LINK request failed
// with NFS3ERR_GARBAGE_ARGS before reaching the filesystem (found by
// cthon04 basic/test7 over the agent-data-workspace compliance mount).
func onLink(ctx context.Context, w *response, userHandle Handler) error {
	w.errorFmt = wccDataErrorFormatter

	// The source handle is mid-message: decode it through the struct
	// decoder, which consumes the opaque field's padding. The
	// hand-rolled xdr.ReadOpaque leaves pad bytes in the stream and
	// would desync the diropargs3 that follows.
	var srcHandle []byte
	if err := xdr.Read(w.req.Body, &srcHandle); err != nil {
		return &NFSStatusError{NFSStatusInval, err}
	}
	link := DirOpArg{}
	if err := xdr.Read(w.req.Body, &link); err != nil {
		return &NFSStatusError{NFSStatusInval, err}
	}

	fs, srcPath, err := userHandle.FromHandle(srcHandle)
	if err != nil {
		return &NFSStatusError{NFSStatusStale, err}
	}
	if !billy.CapabilityCheck(fs, billy.WriteCapability) {
		return &NFSStatusError{NFSStatusROFS, os.ErrPermission}
	}
	if len(link.Filename) > PathNameMax {
		return &NFSStatusError{NFSStatusNameTooLong, os.ErrInvalid}
	}

	srcInfo, err := fs.Stat(fs.Join(srcPath...))
	if err != nil {
		if os.IsNotExist(err) {
			return &NFSStatusError{NFSStatusNoEnt, err}
		}
		return &NFSStatusError{NFSStatusIO, err}
	}
	if srcInfo.IsDir() {
		// POSIX link(2) refuses directories; the kernel client expects
		// the same on the wire.
		return &NFSStatusError{NFSStatusPerm, os.ErrPermission}
	}

	_, linkDirPath, err := userHandle.FromHandle(link.Handle)
	if err != nil {
		return &NFSStatusError{NFSStatusStale, err}
	}
	newFilePath := fs.Join(append(linkDirPath, string(link.Filename))...)
	if _, err := fs.Stat(newFilePath); err == nil {
		return &NFSStatusError{NFSStatusExist, os.ErrExist}
	}
	if s, err := fs.Stat(fs.Join(linkDirPath...)); err != nil {
		return &NFSStatusError{NFSStatusAccess, err}
	} else if !s.IsDir() {
		return &NFSStatusError{NFSStatusNotDir, nil}
	}

	changer := userHandle.Change(fs)
	if changer == nil {
		return &NFSStatusError{NFSStatusAccess, os.ErrPermission}
	}
	cos, ok := changer.(UnixChange)
	if !ok {
		return &NFSStatusError{NFSStatusAccess, os.ErrPermission}
	}

	if err := cos.Link(fs.Join(srcPath...), newFilePath); err != nil {
		if st, ok := refineFsErrnoStatus(err); ok {
			return &NFSStatusError{st, err}
		}
		if os.IsExist(err) {
			return &NFSStatusError{NFSStatusExist, err}
		}
		return &NFSStatusError{NFSStatusAccess, err}
	}

	writer := bytes.NewBuffer([]byte{})
	if err := xdr.Write(writer, uint32(NFSStatusOk)); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}
	// LINK3resok: post_op_attr of the source file, then the link
	// directory's wcc.
	if err := WritePostOpAttrs(writer, tryStat(fs, srcPath)); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}
	if err := WriteWcc(writer, nil, tryStat(fs, linkDirPath)); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}

	if err := w.Write(writer.Bytes()); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}
	return nil
}
