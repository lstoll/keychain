//go:build darwin

package security

import (
	"errors"
	"testing"

	cf "lds.li/keychain/internal/corefoundation"
)

func TestOptionalMLDSASymbolsCanBeMissingIndependently(t *testing.T) {
	f := &Framework{AttrLabel: 77}
	values := map[string]uintptr{
		"kSecAttrKeyTypeMLDSA":                  101,
		"kSecAttrKeySizeMLDSA65":                102,
		"kSecKeyAlgorithmMLDSASignatureMessage": 103,
		"kSecKeySignatureParameterContext":      104,
	}
	missing := errors.New("symbol unavailable")
	loadOptionalMLDSASymbols(
		f,
		func(name string) (uintptr, error) {
			if v, ok := values[name]; ok {
				return v, nil
			}
			return 0, missing
		},
		func() (uintptr, error) { return 105, nil },
		func(uintptr) (MLDSASignatureFunc, error) {
			return func(SecKeyRef, SecKeyAlgorithm, cf.DataRef, cf.DictionaryRef, *cf.ErrorRef) cf.DataRef { return 0 }, nil
		},
	)
	if !f.SupportsMLDSA(65) {
		t.Fatal("ML-DSA-65 availability was lost with ML-DSA-87 absent")
	}
	if f.SupportsMLDSA(87) {
		t.Fatal("reported ML-DSA-87 available without its size constant")
	}
	if !f.SupportsMLDSAContext() {
		t.Fatal("context availability was lost with ML-DSA-87 absent")
	}
	withoutContextAPI := *f
	withoutContextAPI.KeyCreateMLDSASignature = nil
	if !withoutContextAPI.SupportsMLDSA(65) || withoutContextAPI.SupportsMLDSAContext() {
		t.Fatal("empty-context availability incorrectly depended on the context API")
	}
	if f.AttrLabel != 77 {
		t.Fatal("optional loader changed unrelated framework fields")
	}

	older := &Framework{AttrLabel: 88}
	loadOptionalMLDSASymbols(
		older,
		func(string) (uintptr, error) { return 0, missing },
		func() (uintptr, error) { return 0, missing },
		func(uintptr) (MLDSASignatureFunc, error) { return nil, missing },
	)
	if older.AttrLabel != 88 || older.SupportsMLDSA(65) || older.SupportsMLDSA(87) || older.SupportsMLDSAContext() {
		t.Fatal("missing optional symbols corrupted the base framework or appeared supported")
	}
}

func TestIsAlgorithmSupportedRejectsZeroWithoutNativeCall(t *testing.T) {
	f := &Framework{KeyIsAlgorithmSupported: func(SecKeyRef, cf.Index, SecKeyAlgorithm) bool {
		t.Fatal("called native API with a zero algorithm")
		return false
	}}
	if f.AdoptKey(1).IsAlgorithmSupported(0) {
		t.Fatal("reported a zero algorithm as supported")
	}
}

func TestOptionalMLDSAParameterSetsAreIndependent(t *testing.T) {
	f := &Framework{
		AttrKeyTypeMLDSA:                  1,
		AttrKeySizeMLDSA65:                2,
		AttrKeySizeMLDSA87:                3,
		KeyAlgorithmMLDSASignatureMessage: 4,
		KeyCreateMLDSASignature:           func(SecKeyRef, SecKeyAlgorithm, cf.DataRef, cf.DictionaryRef, *cf.ErrorRef) cf.DataRef { return 0 },
	}
	if !f.SupportsMLDSA(65) || !f.SupportsMLDSA(87) {
		t.Fatal("available parameter sets were not reported")
	}
	f.AttrKeySizeMLDSA65 = 0
	if f.SupportsMLDSA(65) || !f.SupportsMLDSA(87) {
		t.Fatal("65/87 availability was not independent")
	}
	if f.SupportsMLDSA(44) {
		t.Fatal("accepted an unknown ML-DSA parameter set")
	}
}

func TestCreateMLDSASignatureRejectsUnavailableSymbolsBeforeNativeCall(t *testing.T) {
	f := &Framework{CoreFoundation: &cf.Framework{Release: func(cf.TypeRef) {}}, KeyCreateSignature: func(SecKeyRef, SecKeyAlgorithm, cf.DataRef, *cf.ErrorRef) cf.DataRef {
		t.Fatal("called required signature API without the optional ML-DSA algorithm constant")
		return 0
	}}
	key := f.AdoptKey(1)
	if _, err := key.CreateMLDSASignature([]byte("message"), nil); err == nil {
		t.Fatal("accepted unavailable ML-DSA algorithm")
	}
	if _, err := key.CreateMLDSASignature(nil, make([]byte, 256)); err == nil {
		t.Fatal("accepted context longer than 255 bytes")
	}
}

func TestCreateMLDSASignatureUsesContextEntryPointOnlyWithContext(t *testing.T) {
	core, err := cf.Get()
	if err != nil {
		t.Fatal(err)
	}
	testCore := *core
	testCore.Release = func(ref cf.TypeRef) {
		if uintptr(ref) != 1 {
			core.Release(ref)
		}
	}
	contextKey, err := core.CreateString("mldsa-test-context")
	if err != nil {
		t.Fatal(err)
	}
	defer core.Release(cf.TypeRef(contextKey))
	algorithm, err := core.CreateString("mldsa-test-algorithm")
	if err != nil {
		t.Fatal(err)
	}
	defer core.Release(cf.TypeRef(algorithm))

	var ordinaryCalls, contextCalls int
	f := &Framework{
		CoreFoundation:                    &testCore,
		KeyAlgorithmMLDSASignatureMessage: SecKeyAlgorithm(algorithm),
		KeySignatureParameterContext:      contextKey,
		KeyCreateSignature: func(_ SecKeyRef, _ SecKeyAlgorithm, data cf.DataRef, _ *cf.ErrorRef) cf.DataRef {
			ordinaryCalls++
			if got := string(core.BytesFromCFData(data)); got != "message" {
				t.Fatalf("ordinary message = %q", got)
			}
			return core.BytesToCFData([]byte("ordinary signature"))
		},
		KeyCreateMLDSASignature: func(_ SecKeyRef, _ SecKeyAlgorithm, data cf.DataRef, parameters cf.DictionaryRef, _ *cf.ErrorRef) cf.DataRef {
			contextCalls++
			if got := string(core.BytesFromCFData(data)); got != "message" {
				t.Fatalf("context message = %q", got)
			}
			if got, ok := core.GetDictionaryData(parameters, contextKey); !ok || string(got) != "ctx\x00bytes" {
				t.Fatalf("context parameter = %q, %v", got, ok)
			}
			return core.BytesToCFData([]byte("context signature"))
		},
	}
	key := f.AdoptKey(1)
	got, err := key.CreateMLDSASignature([]byte("message"), nil)
	if err != nil || string(got) != "ordinary signature" {
		t.Fatalf("empty-context result = %q, %v", got, err)
	}
	got, err = key.CreateMLDSASignature([]byte("message"), []byte("ctx\x00bytes"))
	if err != nil || string(got) != "context signature" {
		t.Fatalf("context result = %q, %v", got, err)
	}
	if ordinaryCalls != 1 || contextCalls != 1 {
		t.Fatalf("native calls ordinary=%d context=%d", ordinaryCalls, contextCalls)
	}
}
