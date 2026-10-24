//go:build darwin

package security

import (
	"errors"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	cf "lds.li/keychain/internal/corefoundation"
)

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		runtime.Gosched()
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true after forced GC")
}

func fakeCoreFoundation(releases *atomic.Int32) *cf.Framework {
	stringsByRef := map[cf.StringRef]string{51: "test.domain", 52: "native failure"}
	return &cf.Framework{
		Release:                         func(cf.TypeRef) { releases.Add(1) },
		ErrorGetDomain:                  func(cf.ErrorRef) cf.StringRef { return 51 },
		ErrorGetCode:                    func(cf.ErrorRef) cf.Index { return 73 },
		ErrorCopyDescription:            func(cf.ErrorRef) cf.StringRef { return 52 },
		StringGetLength:                 func(ref cf.StringRef) cf.Index { return cf.Index(len(stringsByRef[ref])) },
		StringGetMaximumSizeForEncoding: func(n cf.Index, _ cf.StringEncoding) cf.Index { return n },
		StringGetBytes: func(ref cf.StringRef, r cf.Range, _ cf.StringEncoding, _ byte, _ bool, buffer *byte, maxLen cf.Index, used *cf.Index) cf.Index {
			b := []byte(stringsByRef[ref])
			start, end := int(r.Location), int(r.Location+r.Length)
			if start < 0 || end > len(b) || end < start || cf.Index(len(b)) > maxLen {
				return 0
			}
			copy(unsafe.Slice(buffer, maxLen), b[start:end])
			*used = cf.Index(end - start)
			return r.Length
		},
	}
}

func TestKeyCopiesShareCleanupUntilFinalCopy(t *testing.T) {
	var releases atomic.Int32
	f := &Framework{CoreFoundation: &cf.Framework{Release: func(cf.TypeRef) { releases.Add(1) }}}
	firstCopy := f.AdoptKey(123)
	lastCopy := firstCopy
	firstCopy = Key{} //nolint:ineffassign // drop the reference so the GC can run its finalizer
	runtime.GC()
	runtime.Gosched()
	if got := releases.Load(); got != 0 {
		t.Fatalf("released while a key copy remains: %d", got)
	}
	if lastCopy.state == nil {
		t.Fatal("last copy lost its shared key state")
	}
	lastCopy = Key{}
	waitFor(t, func() bool { return releases.Load() == 1 })
	runtime.GC()
	runtime.Gosched()
	if got := releases.Load(); got != 1 {
		t.Fatalf("native key released %d times, want once", got)
	}
}

func TestKeyOperationKeepsStateAliveAcrossGC(t *testing.T) {
	entered := make(chan struct{})
	resume := make(chan struct{})
	var releases atomic.Int32
	f := &Framework{
		CoreFoundation: &cf.Framework{Release: func(cf.TypeRef) { releases.Add(1) }},
		KeyIsAlgorithmSupported: func(SecKeyRef, cf.Index, SecKeyAlgorithm) bool {
			close(entered)
			<-resume
			return true
		},
	}
	key := f.AdoptKey(456)
	done := make(chan bool, 1)
	go func(k Key) { done <- k.IsAlgorithmSupported(1) }(key)
	key = Key{} //nolint:ineffassign // drop the reference so the GC can run its finalizer
	<-entered
	runtime.GC()
	runtime.Gosched()
	if got := releases.Load(); got != 0 {
		t.Fatalf("released during native operation: %d", got)
	}
	close(resume)
	if !<-done {
		t.Fatal("native operation returned false")
	}
	waitFor(t, func() bool { return releases.Load() == 1 })
}

func TestCreateKeyErrorConsumesCFErrorAndAnyReturnedKey(t *testing.T) {
	for _, tc := range []struct {
		name   string
		keyRef SecKeyRef
	}{
		{name: "failure", keyRef: 0},
		{name: "unexpected key with error", keyRef: 321},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var releases atomic.Int32
			core := fakeCoreFoundation(&releases)
			f := &Framework{CoreFoundation: core, KeyCreateRandomKey: func(cf.DictionaryRef, *cf.ErrorRef) SecKeyRef { return 0 }}
			f.KeyCreateRandomKey = func(_ cf.DictionaryRef, out *cf.ErrorRef) SecKeyRef { *out = 99; return tc.keyRef }
			key, err := f.CreateRandomKey(0)
			if err == nil {
				t.Fatal("CreateRandomKey succeeded despite CFError")
			}
			if key.state != nil {
				t.Fatal("returned a key alongside native error")
			}
			var nativeErr *NativeError
			if !errors.As(err, &nativeErr) {
				t.Fatalf("error type = %T, want *NativeError", err)
			}
			if nativeErr.Domain != "test.domain" || nativeErr.Code != 73 || nativeErr.Description != "native failure" {
				t.Fatalf("unexpected native error: %#v", nativeErr)
			}
			want := int32(2)
			if tc.keyRef != 0 {
				want = 3
			}
			if got := releases.Load(); got != want {
				t.Fatalf("released refs %d times, want %d", got, want)
			}
		})
	}
}

func TestCreateKeySuccessAdoptsReturnedReference(t *testing.T) {
	var releases atomic.Int32
	f := &Framework{
		CoreFoundation:    &cf.Framework{Release: func(cf.TypeRef) { releases.Add(1) }},
		KeyCreateWithData: func(cf.DataRef, cf.DictionaryRef, *cf.ErrorRef) SecKeyRef { return 789 },
	}
	key, err := f.CreateKeyWithData(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.usable(); err != nil {
		t.Fatalf("returned key is not usable: %v", err)
	}
	key = Key{}
	waitFor(t, func() bool { return releases.Load() == 1 })
}

func TestNativeErrorFallback(t *testing.T) {
	if got := (&NativeError{Domain: "domain", Code: 4}).Error(); !strings.Contains(got, "domain") || !strings.Contains(got, "4") {
		t.Fatalf("fallback error text %q omits native details", got)
	}
}

func TestUpdateFileKeychainPasswordUsesNonNilEmptyData(t *testing.T) {
	for _, password := range [][]byte{nil, {}, []byte("value\x00tail")} {
		var gotRef SecKeychainItemRef
		var gotLength uint32
		var gotData []byte
		f := &Framework{SecKeychainItemModifyAttributesAndData: func(item SecKeychainItemRef, attributes unsafe.Pointer, length uint32, data *byte) OSStatus {
			gotRef = item
			gotLength = length
			if attributes != nil {
				t.Fatal("unexpected attribute update")
			}
			if data == nil {
				t.Fatal("data pointer must be nonnil for empty password")
			}
			gotData = append([]byte(nil), unsafe.Slice(data, length)...)
			if length == 0 && *data != 0 {
				t.Fatalf("empty sentinel byte = %d, want zero", *data)
			}
			return ErrSecSuccess
		}}
		if err := f.UpdateFileKeychainPassword(42, password); err != nil {
			t.Fatal(err)
		}
		if gotRef != 42 {
			t.Fatalf("item ref = %d, want 42", gotRef)
		}
		if gotLength != uint32(len(password)) {
			t.Fatalf("length = %d, want %d", gotLength, len(password))
		}
		if string(gotData) != string(password) {
			t.Fatalf("data = %q, want %q", gotData, password)
		}
	}
}

func TestFileKeychainPasswordLengthChecksUInt32(t *testing.T) {
	if got, err := fileKeychainPasswordLength(int(^uint32(0))); err != nil || got != ^uint32(0) {
		t.Fatalf("maximum length = %d, %v", got, err)
	}
	if _, err := fileKeychainPasswordLength(int(uint64(^uint32(0)) + 1)); err == nil {
		t.Fatal("accepted length larger than UInt32")
	}
}

func TestUpdateFileKeychainPasswordReturnsStructuredStatusError(t *testing.T) {
	f := &Framework{
		CoreFoundation:                         &cf.Framework{},
		CopyErrorMessageString:                 func(OSStatus, uintptr) cf.StringRef { return 0 },
		SecKeychainItemModifyAttributesAndData: func(SecKeychainItemRef, unsafe.Pointer, uint32, *byte) OSStatus { return ErrSecParam },
	}
	err := f.UpdateFileKeychainPassword(42, nil)
	var nativeErr *NativeError
	if !errors.As(err, &nativeErr) || nativeErr.Code != int64(ErrSecParam) {
		t.Fatalf("status error = %#v, want NativeError code %d", err, ErrSecParam)
	}
}
