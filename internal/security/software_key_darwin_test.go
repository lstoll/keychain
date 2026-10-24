//go:build darwin

package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	cf "lds.li/keychain/internal/corefoundation"
)

func TestSoftwareP256KeyRoundTrip(t *testing.T) {
	core, err := cf.Get()
	if err != nil {
		t.Fatal(err)
	}
	sec, err := Get()
	if err != nil {
		t.Fatal(err)
	}

	sizeValue := int32(256)
	size := core.NumberCreate(cf.AllocatorDefault, core.NumberIntType, unsafe.Pointer(&sizeValue))
	if size == 0 {
		t.Fatal("creating key-size CFNumber returned null")
	}
	defer core.Release(cf.TypeRef(size))
	params, err := core.MapToCFDictionary(map[cf.TypeRef]cf.TypeRef{
		cf.TypeRef(sec.AttrKeyType):       cf.TypeRef(sec.AttrKeyTypeECSECPrimeRandom),
		cf.TypeRef(sec.AttrKeySizeInBits): cf.TypeRef(size),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Release(cf.TypeRef(params))
	if got, ok := core.GetDictionaryInt(params, sec.AttrKeySizeInBits); !ok || got != 256 {
		t.Fatalf("key-size attribute = %d, %v, want 256", got, ok)
	}
	if got, ok := core.GetDictionaryString(params, sec.AttrKeyType); !ok || got != core.CFStringToString(sec.AttrKeyTypeECSECPrimeRandom) {
		t.Fatalf("key-type attribute = %q, %v; expected constant %q", got, ok, core.CFStringToString(sec.AttrKeyTypeECSECPrimeRandom))
	}

	key, err := sec.CreateRandomKey(params)
	if err != nil {
		var nativeErr *NativeError
		if errors.As(err, &nativeErr) && nativeErr.Code == int64(ErrSecParam) && strings.Contains(nativeErr.Description, "failed to generate CDSA key") {
			t.Skipf("host Security.framework cannot generate a software CDSA key: %v", err)
		}
		t.Fatalf("creating ephemeral software P-256 key: %v", err)
	}
	exerciseSoftwareP256Key(t, &key, sec, core)
}

func TestSoftwareP256ImportedKeyRoundTrip(t *testing.T) {
	core, err := cf.Get()
	if err != nil {
		t.Fatal(err)
	}
	sec, err := Get()
	if err != nil {
		t.Fatal(err)
	}
	goKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// SecKeyCreateWithData takes the X9.63 public point followed by the scalar.
	privateBytes, err := goKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	dValue, err := goKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	privateBytes = append(privateBytes, dValue...)
	data := core.BytesToCFData(privateBytes)
	if data == 0 {
		t.Fatal("creating private CFData returned null")
	}
	defer core.Release(cf.TypeRef(data))
	params, err := core.MapToCFDictionary(map[cf.TypeRef]cf.TypeRef{
		cf.TypeRef(sec.AttrKeyType):  cf.TypeRef(sec.AttrKeyTypeECSECPrimeRandom),
		cf.TypeRef(sec.AttrKeyClass): cf.TypeRef(sec.AttrKeyClassPrivate),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Release(cf.TypeRef(params))
	key, err := sec.CreateKeyWithData(data, params)
	if err != nil {
		t.Fatalf("importing P-256 private key: %v", err)
	}
	exerciseSoftwareP256Key(t, &key, sec, core)
}

func exerciseSoftwareP256Key(t *testing.T, key *Key, sec *Framework, core *cf.Framework) {
	t.Helper()
	if !key.IsAlgorithmSupported(sec.KeyAlgorithmECDSASignatureDigestX962SHA256) {
		t.Fatal("key does not support ECDSA SHA-256")
	}
	publicKey, err := key.CopyPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := publicKey.ExternalRepresentation()
	if err != nil {
		t.Fatal(err)
	}
	pub := parseP256PublicKey(t, publicBytes)

	digest := sha256.Sum256([]byte("native software key round trip"))
	signature, err := key.CreateSignature(digest[:], sec.KeyAlgorithmECDSASignatureDigestX962SHA256)
	if err != nil {
		t.Fatalf("signing with native key: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], signature) {
		t.Fatal("Go could not verify native ECDSA signature")
	}

	privateBytes, err := key.ExternalRepresentation()
	if err != nil {
		t.Fatalf("exporting software private key: %v", err)
	}
	privateData := core.BytesToCFData(privateBytes)
	if privateData == 0 {
		t.Fatal("creating private-key CFData returned null")
	}
	defer core.Release(cf.TypeRef(privateData))
	privateParams, err := core.MapToCFDictionary(map[cf.TypeRef]cf.TypeRef{
		cf.TypeRef(sec.AttrKeyType):  cf.TypeRef(sec.AttrKeyTypeECSECPrimeRandom),
		cf.TypeRef(sec.AttrKeyClass): cf.TypeRef(sec.AttrKeyClassPrivate),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer core.Release(cf.TypeRef(privateParams))
	reloaded, err := sec.CreateKeyWithData(privateData, privateParams)
	if err != nil {
		t.Fatalf("reloading software private key: %v", err)
	}
	reloadedSignature, err := reloaded.CreateSignature(digest[:], sec.KeyAlgorithmECDSASignatureDigestX962SHA256)
	if err != nil {
		t.Fatalf("signing with reloaded native key: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], reloadedSignature) {
		t.Fatal("Go could not verify signature from reloaded native key")
	}

	// A by-value copy shares cleanup and remains usable after GC.
	copied := *key
	*key = Key{}
	runtime.GC()
	runtime.Gosched()
	copiedSignature, err := copied.CreateSignature(digest[:], sec.KeyAlgorithmECDSASignatureDigestX962SHA256)
	if err != nil {
		t.Fatalf("signing with copied native key after GC: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], copiedSignature) {
		t.Fatal("Go could not verify signature from copied native key")
	}
}

func parseP256PublicKey(t *testing.T, data []byte) *ecdsa.PublicKey {
	t.Helper()
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), data)
	if err != nil {
		t.Fatalf("native public key is not uncompressed P-256 X9.63 data (%d bytes): %v", len(data), err)
	}
	return pub
}
