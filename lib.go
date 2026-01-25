//go:build darwin

package keychain

import (
	"unsafe"

	"github.com/ebitengine/purego"
)

// constsym returns a uintptr to the value of the symbol, deferencing it from
// the memory location it's at. seems to be good for the kSec types, where the
// type is a pointer and we want that pointer, not the pointer to a pointer.
func constsym(handle uintptr, name string) (uintptr, error) {
	sym, err := purego.Dlsym(handle, name)
	if err != nil {
		return 0, err
	}
	return uintptr(valOf(sym)), nil
}

func dlopen(path string, mode int) (uintptr, error) {
	return purego.Dlopen(path, mode)
}

func registerFunc[T any](handle uintptr, name string) (T, error) {
	var ptr T
	sym, err := purego.Dlsym(handle, name)
	if err != nil {
		return ptr, err
	}
	purego.RegisterFunc(&ptr, sym)
	return ptr, nil
}

func valOf(v uintptr) unsafe.Pointer {
	return **(**unsafe.Pointer)(unsafe.Pointer(&v))
}

func (c _CFTypeRef) Ptr() unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&c))
}

func tPtr[T any](v uintptr) *T {
	return *(**T)(unsafe.Pointer(&v))
}

func ptrToPtr[T any](v *T) *unsafe.Pointer { //nolint:unused
	return (*unsafe.Pointer)(unsafe.Pointer(v))
}
