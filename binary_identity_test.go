//go:build darwin

package keychain

import (
	"runtime"
	"testing"
)

func TestGetSelfCDHashes(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		// would also be supported in signed bins, but test bins wouldn't be
		// signed so.
		t.Skip("GetSelfCDHashes is only supported on arm64")
		return
	}
	hash, err := getSelfCDHashes()
	if err != nil {
		t.Fatalf("GetSelfCDHash failed: %v", err)
	}
	t.Logf("CDHashes: %#v", hash)
}

func TestBinaryIdentity(t *testing.T) {
	hash, err := BinaryIdentity()
	if err != nil {
		t.Fatalf("BinaryIdentity failed: %v", err)
	}
	t.Logf("BinaryIdentity: %s", hash)
}

func TestHashExecutableFile(t *testing.T) {
	hash, err := hashExecutableFile()
	if err != nil {
		t.Fatalf("hashExecutableFile failed: %v", err)
	}
	t.Logf("hashExecutableFile: %s", hash)
}
