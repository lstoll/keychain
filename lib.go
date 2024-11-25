//go:build darwin

package keychain

import (
	"unsafe"

	"github.com/ebitengine/purego"
)

func dlsym(handle uintptr, name string) uintptr {
	h, err := purego.Dlsym(handle, name)
	if err != nil {
		panic(err)
	}
	return h
}

// constsym returns a uintptr to the value of the symbol, deferencing it from
// the memory location it's at. seems to be good for the kSec types, where the
// type is a pointer and we want that pointer, not the pointer to a pointer.
func constsym(handle uintptr, name string) uintptr {
	return uintptr(valOf(dlsym(handle, name)))
}

func dlopen(path string, mode int) uintptr {
	h, err := purego.Dlopen(path, mode)
	if err != nil {
		panic(err)
	}
	return h
}

func registerFunc[T any](handle uintptr, name string) T {
	var ptr T
	purego.RegisterLibFunc(&ptr, handle, name)
	return ptr
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

func ptrToPtr[T any](v *T) *unsafe.Pointer {
	return (*unsafe.Pointer)(unsafe.Pointer(v))
}
