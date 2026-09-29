package nfs

import (
	"bytes"
	"context"
	"io"
	"math"
	"os"
	"sync"

	"github.com/go-git/go-billy/v5"
	"github.com/willscott/go-nfs-client/nfs/xdr"
)

// writeStability is the level of durability requested with the write
type writeStability uint32

const (
	unstable writeStability = 0
	dataSync writeStability = 1
	fileSync writeStability = 2
)

type writeArgs struct {
	Handle []byte
	Offset uint64
	Count  uint32
	How    uint32
	Data   []byte
}

func onWrite(ctx context.Context, w *response, userHandle Handler) error {
	w.errorFmt = wccDataErrorFormatter
	var req writeArgs
	if err := xdr.Read(w.req.Body, &req); err != nil {
		return &NFSStatusError{NFSStatusInval, err}
	}

	fs, path, err := userHandle.FromHandle(req.Handle)
	if err != nil {
		return &NFSStatusError{NFSStatusStale, err}
	}
	if !billy.CapabilityCheck(fs, billy.WriteCapability) {
		return &NFSStatusError{NFSStatusROFS, os.ErrPermission}
	}
	if len(req.Data) > math.MaxInt32 || req.Count > math.MaxInt32 {
		return &NFSStatusError{NFSStatusFBig, os.ErrInvalid}
	}
	if req.How != uint32(unstable) && req.How != uint32(dataSync) && req.How != uint32(fileSync) {
		return &NFSStatusError{NFSStatusInval, os.ErrInvalid}
	}
	fullPath := fs.Join(path...)

	// With the handle-keyed write fd cache enabled (issue #235), a hit
	// writes through the cached fd and stats THE OPEN FILE — identity
	// follows the handle, not the name: the underlying path may have
	// been renamed or removed without invalidating the cache, and the
	// write still lands in the file the handle has been pinned to since
	// the first WRITE. A miss (or a disabled cache) stats and opens by
	// path exactly as the legacy behavior does, then registers the fd.
	var file billy.File
	var entry *writeHandleEntry
	var info os.FileInfo
	var resolveMu *sync.Mutex
	if w.Server.writeCache != nil {
		// Serialize the miss→open→put window per handle: a racing WRITE
		// on a cold handle must not open a second fd for the same file.
		resolveMu = w.Server.writeCache.resolveMu(req.Handle)
		entry = w.Server.writeCache.get(req.Handle)
	}
	if entry != nil {
		file = entry.file
		// Identity follows the handle: stat the OPEN FILE when it can
		// (memfs/osfs files all expose Stat beyond the billy.File
		// interface). When neither the fd nor the (possibly moved or
		// removed) path yields a stat, the pre-op wcc ships absent —
		// legal wcc_data — and the write still proceeds.
		if st, ok := file.(interface{ Stat() (os.FileInfo, error) }); ok {
			info, err = st.Stat()
			if err != nil {
				info = nil
			}
		}
		if info == nil {
			info, err = fs.Stat(fullPath)
			if err != nil {
				info = nil
			}
		}
	} else {
		info, err = fs.Stat(fullPath)
		if err != nil {
			if resolveMu != nil {
				resolveMu.Unlock()
			}
			if os.IsNotExist(err) {
				return &NFSStatusError{NFSStatusNoEnt, err}
			}
			return &NFSStatusError{NFSStatusAccess, err}
		}
		if !info.Mode().IsRegular() {
			if resolveMu != nil {
				resolveMu.Unlock()
			}
			return &NFSStatusError{NFSStatusInval, os.ErrInvalid}
		}
		file, err = fs.OpenFile(fullPath, os.O_RDWR, info.Mode().Perm())
		if err != nil {
			if resolveMu != nil {
				resolveMu.Unlock()
			}
			return &NFSStatusError{NFSStatusAccess, err}
		}
		entry = w.Server.writeCache.put(req.Handle, file)
	}
	if resolveMu != nil {
		// The entry's own mutex now guards the write span.
		resolveMu.Unlock()
	}
	if info != nil && !info.Mode().IsRegular() {
		w.Server.writeCache.release(entry)
		return &NFSStatusError{NFSStatusInval, os.ErrInvalid}
	}
	var preOpCache *FileCacheAttribute
	if info != nil {
		preOpCache = ToFileAttribute(info, fullPath).AsCache()
	}
	if _, err := file.Seek(int64(req.Offset), io.SeekStart); err != nil {
		w.Server.writeCache.release(entry)
		return &NFSStatusError{NFSStatusIO, err}
	}
	end := req.Count
	if len(req.Data) < int(end) {
		end = uint32(len(req.Data))
	}
	writtenCount, err := file.Write(req.Data[:end])
	if err != nil {
		Log.Errorf("Error writing: %v", err)
		w.Server.writeCache.release(entry)
		return &NFSStatusError{statusFromWriteError(err), err}
	}
	if entry != nil {
		// Cached fd stays open for the next WRITE on this handle.
		w.Server.writeCache.release(entry)
	} else if err := file.Close(); err != nil {
		Log.Errorf("error closing: %v", err)
		return &NFSStatusError{statusFromWriteError(err), err}
	}

	writer := bytes.NewBuffer([]byte{})
	if err := xdr.Write(writer, uint32(NFSStatusOk)); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}

	if err := WriteWcc(writer, preOpCache, tryStat(fs, path)); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}
	if err := xdr.Write(writer, uint32(writtenCount)); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}
	if err := xdr.Write(writer, fileSync); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}
	if err := xdr.Write(writer, w.Server.ID); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}

	if err := w.Write(writer.Bytes()); err != nil {
		return &NFSStatusError{NFSStatusServerFault, err}
	}
	return nil
}
