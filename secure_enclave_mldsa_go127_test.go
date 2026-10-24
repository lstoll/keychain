//go:build darwin && go1.27

package keychain

import (
	"crypto"
	"crypto/mldsa"
	"errors"
	"runtime"
	"strings"
	"testing"
)

func TestSecureEnclaveMLDSASigningOptions(t *testing.T) {
	for _, opts := range []crypto.SignerOpts{nil, crypto.Hash(0), &mldsa.Options{}, (*mldsa.Options)(nil)} {
		if context, err := mldsaSigningContext(opts); err != nil || context != "" {
			t.Fatalf("empty context: %q %v", context, err)
		}
	}
	context := strings.Repeat("x", 255)
	if got, err := mldsaSigningContext(&mldsa.Options{Context: context}); err != nil || got != context {
		t.Fatalf("context: %q %v", got, err)
	}
	for _, opts := range []crypto.SignerOpts{crypto.SHA256, crypto.SHA512, crypto.MLDSAMu, &mldsa.Options{Context: strings.Repeat("x", 256)}} {
		if _, err := mldsaSigningContext(opts); err == nil {
			t.Fatalf("accepted opts %+v", opts)
		}
	}
}

func TestSecureEnclaveMLDSAStdlib(t *testing.T) {
	requireSecureEnclave(t)
	for _, algorithm := range []SecureEnclaveAlgorithm{SecureEnclaveMLDSA65, SecureEnclaveMLDSA87} {
		t.Run(map[SecureEnclaveAlgorithm]string{SecureEnclaveMLDSA65: "65", SecureEnclaveMLDSA87: "87"}[algorithm], func(t *testing.T) {
			key, err := CreateSecureEnclaveKey(SecureEnclaveKeyOptions{Algorithm: algorithm, AccessControl: &AccessControl{Protection: AccessibleAfterFirstUnlockThisDeviceOnly}})
			if errors.Is(err, ErrUnsupportedAlgorithm) {
				t.Skipf("ML-DSA unavailable: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			if key.Algorithm() != algorithm {
				t.Fatalf("algorithm: %v", key.Algorithm())
			}
			verifyEnclaveMLDSA(t, key)
			loaded, err := LoadSecureEnclaveKey(key.DataRepresentation(), SecureEnclaveLoadOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if loaded.Algorithm() != algorithm || !key.Public().(*mldsa.PublicKey).Equal(loaded.Public()) {
				t.Fatal("key changed on reload")
			}
			copied := *loaded
			loaded = nil
			runtime.GC()
			verifyEnclaveMLDSA(t, &copied)
		})
	}
}

func verifyEnclaveMLDSA(t *testing.T, key *SecureEnclaveKey) {
	t.Helper()
	message := []byte("Secure Enclave ML-DSA Go stdlib interoperability")
	contexts := []string{""}
	if key.sec.SupportsMLDSAContext() {
		contexts = append(contexts, "keychain-test context\x00unicode ☕")
	} else {
		if _, err := key.Sign(nil, message, &mldsa.Options{Context: "required context"}); err == nil {
			t.Fatal("silently discarded unsupported context")
		}
	}
	for _, context := range contexts {
		opts := &mldsa.Options{Context: context}
		sig, err := key.Sign(nil, message, opts)
		if err != nil {
			t.Fatal(err)
		}
		pub := key.Public().(*mldsa.PublicKey)
		if err := mldsa.Verify(pub, message, sig, opts); err != nil {
			t.Fatalf("Go verification (context %q): %v", context, err)
		}
		if err := mldsa.Verify(pub, []byte("wrong message"), sig, opts); err == nil {
			t.Fatal("accepted wrong message")
		}
		sig[0] ^= 1
		if err := mldsa.Verify(pub, message, sig, opts); err == nil {
			t.Fatal("accepted corrupt signature")
		}
	}
	if _, err := key.Sign(nil, message, crypto.MLDSAMu); err == nil {
		t.Fatal("accepted external mu")
	}
}
