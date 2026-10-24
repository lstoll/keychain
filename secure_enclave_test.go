//go:build darwin

package keychain

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"lds.li/keychain/internal/corefoundation"
	"lds.li/keychain/internal/security"
)

func TestSecureEnclaveSignValidation(t *testing.T) {
	sec, err := security.Get()
	if err != nil {
		t.Fatal(err)
	}
	key := &SecureEnclaveKey{pub: &ecdsa.PublicKey{}, sec: sec}
	for _, tc := range []struct {
		name   string
		opts   crypto.SignerOpts
		digest []byte
	}{
		{"nil options", nil, nil},
		{"unhashed", crypto.Hash(0), make([]byte, 32)},
		{"SHA1", crypto.SHA1, make([]byte, 20)},
		{"short SHA256", crypto.SHA256, make([]byte, 31)},
		{"long SHA384", crypto.SHA384, make([]byte, 49)},
		{"short SHA512", crypto.SHA512, make([]byte, 63)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := key.Sign(nil, tc.digest, tc.opts); err == nil {
				t.Fatal("expected rejection before native API call")
			}
		})
	}

	if _, err := key.Sign(nil, make([]byte, 32), crypto.SHA256); err == nil {
		t.Fatal("accepted unsupported native algorithm")
	}
	if _, err := new(SecureEnclaveKey).Sign(nil, make([]byte, 32), crypto.SHA256); err == nil {
		t.Fatal("accepted zero key")
	}
	if _, err := LoadSecureEnclaveKey(nil, SecureEnclaveLoadOptions{}); err == nil {
		t.Fatal("accepted empty representation")
	}
}

func TestSecureEnclaveE2E(t *testing.T) {
	requireSecureEnclave(t)
	if filename := os.Getenv("SECURE_ENCLAVE_TEST_BLOB"); filename != "" {
		data, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		key, err := LoadSecureEnclaveKey(data, SecureEnclaveLoadOptions{})
		if err != nil {
			t.Fatal(err)
		}
		verifySecureEnclaveSignatures(t, key)
		return
	}
	key, err := CreateSecureEnclaveKey(SecureEnclaveKeyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	background, err := CreateSecureEnclaveKey(SecureEnclaveKeyOptions{AccessControl: &AccessControl{Protection: AccessibleAfterFirstUnlockThisDeviceOnly}})
	if err != nil {
		t.Fatal(err)
	}
	verifySecureEnclaveSignatures(t, background)
	// Provision and reload a presence-protected key without prompting for a signature.
	presence, err := CreateSecureEnclaveKey(SecureEnclaveKeyOptions{AccessControl: &AccessControl{Protection: AccessibleWhenUnlockedThisDeviceOnly, Flags: AccessControlUserPresence}})
	if err != nil {
		t.Fatal(err)
	}
	presenceLoaded, err := LoadSecureEnclaveKey(presence.DataRepresentation(), SecureEnclaveLoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !presence.Public().(*ecdsa.PublicKey).Equal(presenceLoaded.Public()) {
		t.Fatal("presence key changed after load")
	}
	verifySecureEnclaveSignatures(t, key)
	blob := key.DataRepresentation()
	loaded, err := LoadSecureEnclaveKey(blob, SecureEnclaveLoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !key.Public().(*ecdsa.PublicKey).Equal(loaded.Public()) {
		t.Fatal("public key changed after load")
	}
	verifySecureEnclaveSignatures(t, loaded)
	copied := *loaded
	loaded = nil
	runtime.GC()
	verifySecureEnclaveSignatures(t, &copied)
	// The public key and persisted blob must not expose mutable internal state.
	if p1, p2 := key.Public(), key.Public(); p1.(*ecdsa.PublicKey) == p2.(*ecdsa.PublicKey) {
		t.Fatal("Public returns the key's own value")
	}
	blob[0] ^= 0xff
	if bytes.Equal(blob, key.DataRepresentation()) {
		t.Fatal("representation aliases internal data")
	}
	verifySecureEnclaveSignatures(t, key)
	if _, err := LoadSecureEnclaveKey([]byte("invalid object ID"), SecureEnclaveLoadOptions{}); err == nil {
		t.Fatal("accepted invalid blob")
	}
	// Reload in a new process, with a blob stored as an ordinary protected file.
	filename := filepath.Join(t.TempDir(), "key.blob")
	if err := os.WriteFile(filename, key.DataRepresentation(), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSecureEnclaveE2E$")
	cmd.Env = append(os.Environ(), "SECURE_ENCLAVE_TEST_BLOB="+filename)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child reload: %v\n%s", err, output)
	}
}

func verifySecureEnclaveSignatures(t *testing.T, key *SecureEnclaveKey) {
	t.Helper()
	message := []byte("Secure Enclave Go signing test")
	d256 := sha256.Sum256(message)
	d384 := sha512.Sum384(message)
	d512 := sha512.Sum512(message)
	for _, tc := range []struct {
		hash   crypto.Hash
		digest []byte
	}{
		{crypto.SHA256, d256[:]}, {crypto.SHA384, d384[:]}, {crypto.SHA512, d512[:]},
	} {
		signature, err := key.Sign(nil, tc.digest, tc.hash)
		if err != nil {
			t.Fatalf("%v: %v", tc.hash, err)
		}
		if !ecdsa.VerifyASN1(key.Public().(*ecdsa.PublicKey), tc.digest, signature) {
			t.Fatalf("invalid %v signature", tc.hash)
		}
		signature[0] ^= 1
		if ecdsa.VerifyASN1(key.Public().(*ecdsa.PublicKey), tc.digest, signature) {
			t.Fatal("accepted corrupted signature")
		}
	}
}

func TestSecureEnclaveAccessRules(t *testing.T) {
	cf, err := corefoundation.Get()
	if err != nil {
		t.Fatal(err)
	}
	sec, err := security.Get()
	if err != nil {
		t.Fatal(err)
	}
	for _, protection := range []Accessible{AccessibleWhenUnlockedThisDeviceOnly, AccessibleAfterFirstUnlockThisDeviceOnly, AccessibleWhenPasscodeSetThisDeviceOnly} {
		ac, err := createAccessControl(sec, AccessControl{Protection: protection, Flags: AccessControlBiometryAny | AccessControlDevicePasscode | AccessControlOr | 1<<30})
		if err != nil {
			t.Fatal(err)
		}
		cf.Release(corefoundation.TypeRef(ac))
	}
	for _, requested := range []*AccessControl{nil, {}, {Flags: AccessControlUserPresence}} {
		ac := secureEnclaveAccessControl(requested)
		if ac.Protection != AccessibleWhenUnlockedThisDeviceOnly || ac.Flags&(1<<30) == 0 {
			t.Fatalf("defaults not applied for %+v: %+v", requested, ac)
		}
	}
	if ac := secureEnclaveAccessControl(&AccessControl{Protection: AccessibleAfterFirstUnlockThisDeviceOnly}); ac.Protection != AccessibleAfterFirstUnlockThisDeviceOnly {
		t.Fatalf("protection overridden: %+v", ac)
	}
	if _, err := LoadSecureEnclaveKey([]byte("blob"), SecureEnclaveLoadOptions{AuthContext: &AuthContext{}}); err == nil {
		t.Fatal("accepted zero auth context")
	}
}

func TestSecureEnclaveFallback(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options SecureEnclaveKeyOptions
		failure error
		want    []SecureEnclaveAlgorithm
	}{
		{"unavailable", SecureEnclaveKeyOptions{Algorithm: SecureEnclaveMLDSA65, AllowFallback: true}, ErrUnsupportedAlgorithm, []SecureEnclaveAlgorithm{SecureEnclaveMLDSA65, SecureEnclaveP256}},
		{"strict", SecureEnclaveKeyOptions{Algorithm: SecureEnclaveMLDSA65}, ErrUnsupportedAlgorithm, []SecureEnclaveAlgorithm{SecureEnclaveMLDSA65}},
		{"authentication failure", SecureEnclaveKeyOptions{Algorithm: SecureEnclaveMLDSA65, AllowFallback: true}, &Error{code: ErrorCodeAuthFailed}, []SecureEnclaveAlgorithm{SecureEnclaveMLDSA65}},
		{"invalid parameters", SecureEnclaveKeyOptions{Algorithm: SecureEnclaveMLDSA65, AllowFallback: true}, &Error{code: ErrorCodeParam}, []SecureEnclaveAlgorithm{SecureEnclaveMLDSA65}},
		{"missing entitlement", SecureEnclaveKeyOptions{Algorithm: SecureEnclaveMLDSA65, AllowFallback: true}, &Error{code: ErrorCodeMissingEntitlement}, []SecureEnclaveAlgorithm{SecureEnclaveMLDSA65}},
		{"locked session", SecureEnclaveKeyOptions{Algorithm: SecureEnclaveMLDSA65, AllowFallback: true}, &Error{code: ErrorCodeInteractionNotAllowed}, []SecureEnclaveAlgorithm{SecureEnclaveMLDSA65}},
		{"cancellation", SecureEnclaveKeyOptions{Algorithm: SecureEnclaveMLDSA65, AllowFallback: true}, &Error{code: ErrorCodeUserCanceled}, []SecureEnclaveAlgorithm{SecureEnclaveMLDSA65}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []SecureEnclaveAlgorithm
			key, err := createSecureEnclaveWithFallback(tc.options, func(algorithm SecureEnclaveAlgorithm) (*SecureEnclaveKey, error) {
				calls = append(calls, algorithm)
				if algorithm != SecureEnclaveP256 {
					return nil, tc.failure
				}
				return &SecureEnclaveKey{algorithm: algorithm}, nil
			})
			if !slices.Equal(calls, tc.want) {
				t.Fatalf("calls = %v, want %v", calls, tc.want)
			}
			if len(tc.want) == 2 {
				if err != nil || key.Algorithm() != SecureEnclaveP256 {
					t.Fatalf("fallback: %v %v", key, err)
				}
			} else if !errors.Is(err, tc.failure) {
				t.Fatalf("lost original failure: %v", err)
			}
		})
	}
	if _, err := CreateSecureEnclaveKey(SecureEnclaveKeyOptions{Algorithm: SecureEnclaveAlgorithm(999), AllowFallback: true}); err == nil {
		t.Fatal("accepted unknown algorithm")
	}
}

// Always exercise the required P-256 path independently of optional ML-DSA.
func TestSecureEnclaveP256Stdlib(t *testing.T) {
	requireSecureEnclave(t)
	key, err := CreateSecureEnclaveKey(SecureEnclaveKeyOptions{AccessControl: &AccessControl{Protection: AccessibleAfterFirstUnlockThisDeviceOnly}})
	if err != nil {
		t.Fatal(err)
	}
	if key.Algorithm() != SecureEnclaveP256 {
		t.Fatal("default changed from P-256")
	}
	verifySecureEnclaveSignatures(t, key)
	loaded, err := LoadSecureEnclaveKey(key.DataRepresentation(), SecureEnclaveLoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	verifySecureEnclaveSignatures(t, loaded)
}

func TestSecureEnclaveAlgorithmString(t *testing.T) {
	for algorithm, want := range map[SecureEnclaveAlgorithm]string{
		SecureEnclaveP256:          "P-256",
		SecureEnclaveMLDSA65:       "ML-DSA-65",
		SecureEnclaveMLDSA87:       "ML-DSA-87",
		SecureEnclaveAlgorithm(42): "SecureEnclaveAlgorithm(42)",
		SecureEnclaveAlgorithm(-1): "SecureEnclaveAlgorithm(-1)",
	} {
		if got := algorithm.String(); got != want {
			t.Errorf("%d: got %q, want %q", int(algorithm), got, want)
		}
	}
	if (*SecureEnclaveKey)(nil).Algorithm() != SecureEnclaveP256 {
		t.Error("nil key algorithm")
	}
}

// Canary for the private kSecAttrTokenOID ("toid") persistence attribute.
func TestSecureEnclaveTokenOIDPersistence(t *testing.T) {
	requireSecureEnclave(t)
	const hint = "the private kSecAttrTokenOID (\"toid\") persistence attribute may have changed in this macOS release"
	key, err := CreateSecureEnclaveKey(SecureEnclaveKeyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	blob := key.DataRepresentation()
	if len(blob) == 0 {
		t.Fatalf("empty DataRepresentation: %s", hint)
	}
	loaded, err := LoadSecureEnclaveKey(blob, SecureEnclaveLoadOptions{})
	if err != nil {
		t.Fatalf("reloading key: %v: %s", err, hint)
	}
	if !key.Public().(*ecdsa.PublicKey).Equal(loaded.Public()) {
		t.Fatalf("public key changed after reload: %s", hint)
	}
}
