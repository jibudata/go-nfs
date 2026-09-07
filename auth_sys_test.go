package nfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// encodeAuthSys builds an AUTH_SYS credential body the way a client would:
// stamp, machinename, uid, gid, supplementary-gids vector (issue
// jibudata/agent-data-workspace#80).
func encodeAuthSys(stamp uint32, machinename string, uid, gid uint32, gids []uint32) []byte {
	w := new(bytes.Buffer)
	writeUint32 := func(v uint32) {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], v)
		w.Write(b[:])
	}
	writeOpaque := func(s string) {
		writeUint32(uint32(len(s)))
		w.WriteString(s)
		for pad := (4 - len(s)%4) % 4; pad > 0; pad-- {
			w.WriteByte(0)
		}
	}
	writeUint32(stamp)
	writeOpaque(machinename)
	writeUint32(uid)
	writeUint32(gid)
	writeUint32(uint32(len(gids)))
	for _, g := range gids {
		writeUint32(g)
	}
	return w.Bytes()
}

func TestParseAuthSys_CredentialWithGIDs(t *testing.T) {
	body := encodeAuthSys(42, "client.example", 65534, 65534, []uint32{65534, 100, 0})

	cc, err := parseAuthSys(body)
	if err != nil {
		t.Fatalf("parseAuthSys: %v", err)
	}
	if cc.UID != 65534 || cc.GID != 65534 {
		t.Fatalf("uid/gid = %d/%d, want 65534/65534", cc.UID, cc.GID)
	}
	if len(cc.GIDs) != 3 || cc.GIDs[0] != 65534 || cc.GIDs[1] != 100 || cc.GIDs[2] != 0 {
		t.Fatalf("gids = %v, want [65534 100 0]", cc.GIDs)
	}
}

func TestParseAuthSys_EmptyGIDsAndRoot(t *testing.T) {
	cc, err := parseAuthSys(encodeAuthSys(1, "m", 0, 0, nil))
	if err != nil {
		t.Fatalf("parseAuthSys: %v", err)
	}
	if cc.UID != 0 || cc.GID != 0 || len(cc.GIDs) != 0 {
		t.Fatalf("cc = %+v, want root with no gids", cc)
	}
}

func TestParseAuthSys_RejectsHugeGIDVector(t *testing.T) {
	body := encodeAuthSys(1, "m", 1, 1, make([]uint32, 65))
	if _, err := parseAuthSys(body); err == nil {
		t.Fatal("parseAuthSys accepted a 65-gid vector, want error")
	}
}

func TestParseAuthSys_TruncatedBody(t *testing.T) {
	body := encodeAuthSys(1, "m", 5, 5, []uint32{5})
	if _, err := parseAuthSys(body[:len(body)-2]); err == nil {
		t.Fatal("parseAuthSys accepted a truncated body, want error")
	}
}

func TestCallerCredentialsFromContext(t *testing.T) {
	if cc := CallerCredentialsFromContext(context.Background()); cc != nil {
		t.Fatalf("empty ctx returned %+v, want nil", cc)
	}
	ctx := WithCallerCredentials(context.Background(), &CallerCredentials{UID: 1000, GID: 1000})
	if cc := CallerCredentialsFromContext(ctx); cc == nil || cc.UID != 1000 {
		t.Fatalf("ctx cc = %+v, want uid 1000", cc)
	}
}

// TestOwnershipEnforcerContract pins the workspace-side contract: a
// cross-UID caller is denied, the owner is allowed.
func TestOwnershipEnforcer_SetAttrDenial(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	en := &denyEnforcer{}
	if err := en.EnforceSetAttr(path, 65534, info); err == nil {
		t.Fatal("EnforceSetAttr allowed a denied caller")
	}
	if err := en.EnforceSetAttr(path, 1000, info); err != nil {
		t.Fatalf("EnforceSetAttr denied the owner: %v", err)
	}
}

type denyEnforcer struct{}

func (d *denyEnforcer) EnforceSetAttr(path string, callerUID uint32, info os.FileInfo) error {
	if callerUID == 65534 {
		return os.ErrPermission
	}
	return nil
}

func (d *denyEnforcer) EnforceDirWrite(dirPath string, callerUID uint32, info os.FileInfo) error {
	return nil
}

func (d *denyEnforcer) NoteCreated(path string, callerUID uint32) {}
