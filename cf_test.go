//go:build darwin

package keychain

import (
	"testing"
	"unsafe"
)

func TestCFDict(t *testing.T) {
	k1 := stringToCFString("k1")
	k2 := stringToCFString("k2")

	v1 := stringToCFString("xxxx")
	v2 := stringToCFString("yyyy")

	keys := []unsafe.Pointer{unsafe.Pointer(k1), unsafe.Pointer(k2)}
	values := []unsafe.Pointer{unsafe.Pointer(v1), unsafe.Pointer(v2)}

	res := _CFDictionaryCreate(kCFAllocatorDefault, &keys[0], &values[0], _CFIndex(2),
		*(**_CFDictionaryKeyCallBacks)(unsafe.Pointer(&kCFTypeDictionaryKeyCallBacks)),
		*(**_CFDictionaryValueCallBacks)(unsafe.Pointer(&kCFTypeDictionaryValueCallBacks)))

	t.Logf("res: %#v", res)
}
