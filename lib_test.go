//go:build darwin

package keychain

import "testing"

/* commented to avoid vet error
func TestDoubleDeref(t *testing.T) {
	// vet calls unsafe.Pointer(uintptr) possible unsafe. this verifies a
	// workaround to avoid that.
	str := stringToCFString("hello")
	sgl := unsafe.Pointer(str)
	dbl := *(*unsafe.Pointer)(unsafe.Pointer(&str))
	if uintptr(sgl) != uintptr(dbl) {
		t.Error("addresses differ")
	}
}*/

func TestConstDeref(t *testing.T) {
	t.Log(cfStringtoString(kSecMatchLimit))
}
