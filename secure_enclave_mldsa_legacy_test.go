//go:build darwin && !go1.27

package keychain

import (
	"errors"
	"testing"
)

func TestSecureEnclaveMLDSAFallbackWithoutStdlib(t *testing.T) {
	requireSecureEnclave(t)
	options := SecureEnclaveKeyOptions{Algorithm: SecureEnclaveMLDSA65, AccessControl: &AccessControl{Protection: AccessibleAfterFirstUnlockThisDeviceOnly}}
	if _, err := CreateSecureEnclaveKey(options); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("strict unsupported algorithm: %v", err)
	}
	options.AllowFallback = true
	key, err := CreateSecureEnclaveKey(options)
	if err != nil {
		t.Fatal(err)
	}
	if key.Algorithm() != SecureEnclaveP256 {
		t.Fatalf("fallback algorithm: %v", key.Algorithm())
	}
	verifySecureEnclaveSignatures(t, key)
}
