//go:build darwin

package keychain

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
	"lds.li/keychain/internal/corefoundation"
	"lds.li/keychain/internal/security"
)

func TestListIdentities(t *testing.T) {
	requireIntegration(t)
	identities, err := ListIdentities(IdentityQuery{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("found %d identities", len(identities))
	for _, id := range identities {
		t.Logf("  %s (%s)", id.Label(), id.Type())

		cert, err := id.Certificate()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("  certificate: %s", cert.Subject)

		chain, err := id.CertificateChain(nil)
		if err != nil {
			t.Logf("  CertificateChain: %v", err)
			continue
		}
		t.Logf("  chain: %d certificates", len(chain))
		for _, cert := range chain {
			t.Logf("    %s", cert.Subject)
		}
	}
}

// TestSecIdentityLifecycle imports a software key and self-signed certificate
// into the default keychain, which forms a SecIdentity, and exercises it.
func TestSecIdentityLifecycle(t *testing.T) {
	requireIntegration(t)
	cf, err := corefoundation.Get()
	if err != nil {
		t.Fatal(err)
	}
	sec, err := security.Get()
	if err != nil {
		t.Fatal(err)
	}

	label := fmt.Sprintf("lds.li/keychain test %d", time.Now().UnixNano())
	goKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: label},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &goKey.PublicKey, goKey)
	if err != nil {
		t.Fatal(err)
	}
	goCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	labelRef, err := cf.CreateString(label)
	if err != nil {
		t.Fatal(err)
	}

	// Register cleanup before adding anything, so partial failures are cleaned.
	// Cleanup runs after defers, so it owns labelRef.
	t.Cleanup(func() {
		defer cf.Release(corefoundation.TypeRef(labelRef))
		for _, class := range []corefoundation.StringRef{sec.ClassCertificate, sec.ClassKey} {
			q, err := cf.MapToCFDictionary(map[corefoundation.TypeRef]corefoundation.TypeRef{
				corefoundation.TypeRef(sec.Class):     corefoundation.TypeRef(class),
				corefoundation.TypeRef(sec.AttrLabel): corefoundation.TypeRef(labelRef),
			})
			if err != nil {
				t.Errorf("cleanup query: %v", err)
				continue
			}
			err = newError(sec, sec.ItemDelete(q))
			cf.Release(corefoundation.TypeRef(q))
			if err != nil && !errors.Is(err, ErrItemNotFound) {
				t.Errorf("cleanup delete: %v", err)
			}
		}
	})

	// Private key: SecItemAdd of a software SecKey only reaches the data
	// protection keychain, so import SEC1 through the file-keychain importer.
	sec1, err := x509.MarshalECPrivateKey(goKey)
	if err != nil {
		t.Fatal(err)
	}
	importFileKeychainKey(t, cf, sec, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))

	// Certificate.
	certData := cf.BytesToCFData(der)
	if certData == 0 {
		t.Fatal("creating certificate CFData returned null")
	}
	defer cf.Release(corefoundation.TypeRef(certData))
	certRef := sec.CertificateCreateWithData(corefoundation.AllocatorDefault, certData)
	if certRef == 0 {
		t.Fatal("SecCertificateCreateWithData returned null")
	}
	defer cf.Release(corefoundation.TypeRef(certRef))
	addItem(t, cf, sec, corefoundation.TypeRef(certRef), labelRef, "certificate")

	id, err := GetIdentity(IdentityQuery{Label: label})
	if err != nil {
		t.Fatalf("GetIdentity: %v", err)
	}
	if id.Type() != IdentityTypeSecIdentity {
		t.Fatalf("Type = %v, want %v", id.Type(), IdentityTypeSecIdentity)
	}
	cert, err := id.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cert.Raw, goCert.Raw) {
		t.Fatal("identity certificate does not match generated certificate")
	}
	if hash, err := id.PublicKeyHash(); err != nil || len(hash) == 0 {
		t.Fatalf("PublicKeyHash = %x, %v", hash, err)
	}
	if bits, err := id.KeySizeInBits(); err != nil || bits != 256 {
		t.Fatalf("KeySizeInBits = %d, %v", bits, err)
	}
	signer, err := id.Signer()
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&goKey.PublicKey) {
		t.Fatalf("Signer().Public() = %#v, want generated public key", signer.Public())
	}
	digest := sha256.Sum256([]byte("software identity lifecycle"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(&goKey.PublicKey, digest[:], sig) {
		t.Fatal("signature did not verify")
	}

	chain, err := id.CertificateChain(nil)
	switch {
	case err != nil:
		t.Logf("CertificateChain (self-signed, untrusted) returned error: %v", err)
	case len(chain) == 0 || !bytes.Equal(chain[0].Raw, goCert.Raw):
		t.Fatalf("CertificateChain first element is not the leaf (%d certs)", len(chain))
	default:
		t.Logf("CertificateChain returned %d certificates", len(chain))
	}

	ctk, err := ListIdentities(IdentityQuery{Label: label, Type: IdentityQueryTypeCTK})
	if err != nil {
		t.Fatalf("ListIdentities CTK: %v", err)
	}
	if len(ctk) != 0 {
		t.Fatalf("CTK query returned %d identities for a software identity", len(ctk))
	}

	if err := id.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := GetIdentity(IdentityQuery{Label: label}); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("GetIdentity after delete = %v, want ErrItemNotFound", err)
	}
}

func addItem(t *testing.T, cf *corefoundation.Framework, sec *security.Framework, value corefoundation.TypeRef, label corefoundation.StringRef, what string) {
	t.Helper()
	attrs, err := cf.MapToCFDictionary(map[corefoundation.TypeRef]corefoundation.TypeRef{
		corefoundation.TypeRef(sec.ValueRef):                  value,
		corefoundation.TypeRef(sec.AttrLabel):                 corefoundation.TypeRef(label),
		corefoundation.TypeRef(sec.UseDataProtectionKeychain): corefoundation.TypeRef(cf.BooleanFalse),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer cf.Release(corefoundation.TypeRef(attrs))
	if err := newError(sec, sec.ItemAdd(attrs, nil)); err != nil {
		t.Fatalf("SecItemAdd %s: %v", what, err)
	}
}

// importFileKeychainKey imports a PEM private key into the default file
// keychain with SecItemImport and deletes it during cleanup.
func importFileKeychainKey(t *testing.T, cf *corefoundation.Framework, sec *security.Framework, pemData []byte) {
	t.Helper()
	h, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		t.Fatal(err)
	}
	var copyDefault func(keychain *uintptr) security.OSStatus
	var itemImport func(data corefoundation.DataRef, name corefoundation.StringRef, format, itemType *uint32, flags uint32, keyParams unsafe.Pointer, keychain uintptr, out *corefoundation.ArrayRef) security.OSStatus
	purego.RegisterLibFunc(&copyDefault, h, "SecKeychainCopyDefault")
	purego.RegisterLibFunc(&itemImport, h, "SecItemImport")

	var keychain uintptr
	if err := newError(sec, copyDefault(&keychain)); err != nil {
		t.Fatalf("SecKeychainCopyDefault: %v", err)
	}
	defer cf.Release(corefoundation.TypeRef(keychain))
	data := cf.BytesToCFData(pemData)
	defer cf.Release(corefoundation.TypeRef(data))
	name := cf.StringToCFString("key.pem")
	defer cf.Release(corefoundation.TypeRef(name))
	format, itemType := uint32(1), uint32(1) // kSecFormatOpenSSL, kSecItemTypePrivateKey
	var out corefoundation.ArrayRef
	if err := newError(sec, itemImport(data, name, &format, &itemType, 0, nil, keychain, &out)); err != nil {
		t.Fatalf("SecItemImport: %v", err)
	}
	t.Cleanup(func() {
		defer cf.Release(corefoundation.TypeRef(out))
		for _, ref := range cf.GoSliceFromCFArray(out) {
			q, err := cf.MapToCFDictionary(map[corefoundation.TypeRef]corefoundation.TypeRef{
				corefoundation.TypeRef(sec.Class):    corefoundation.TypeRef(sec.ClassKey),
				corefoundation.TypeRef(sec.ValueRef): ref,
			})
			if err != nil {
				t.Errorf("cleanup query: %v", err)
				continue
			}
			err = newError(sec, sec.ItemDelete(q))
			cf.Release(corefoundation.TypeRef(q))
			if err != nil && !errors.Is(err, ErrItemNotFound) {
				t.Errorf("cleanup delete imported key: %v", err)
			}
		}
	})
}
