//go:build darwin

package keychain

import (
	"testing"
	"unsafe"
)

func TestCFDict(t *testing.T) {
	cf, err := getCoreFoundation()
	if err != nil {
		t.Fatal(err)
	}

	k1 := cf.StringToCFString("k1")
	k2 := cf.StringToCFString("k2")

	v1 := cf.StringToCFString("xxxx")
	v2 := cf.StringToCFString("yyyy")

	keys := []unsafe.Pointer{unsafe.Pointer(k1), unsafe.Pointer(k2)}   //nolint:govet
	values := []unsafe.Pointer{unsafe.Pointer(v1), unsafe.Pointer(v2)} //nolint:govet

	res := cf.DictionaryCreate(kCFAllocatorDefault, &keys[0], &values[0], _CFIndex(2),
		*(**_CFDictionaryKeyCallBacks)(unsafe.Pointer(&cf.TypeDictionaryKeyCallBacks)),
		*(**_CFDictionaryValueCallBacks)(unsafe.Pointer(&cf.TypeDictionaryValueCallBacks)))

	t.Logf("res: %#v", res)
}
