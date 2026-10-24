//go:build darwin

package corefoundation

import (
	"unsafe"

	"github.com/ebitengine/purego"
)

func constsym(handle uintptr, name string) (uintptr, error) {
	sym, err := purego.Dlsym(handle, name)
	if err != nil {
		return 0, err
	}
	return uintptr(valOf(sym)), nil
}
func dlopen(path string, mode int) (uintptr, error) { return purego.Dlopen(path, mode) }
func registerFunc[T any](handle uintptr, name string) (T, error) {
	var ptr T
	sym, err := purego.Dlsym(handle, name)
	if err != nil {
		return ptr, err
	}
	purego.RegisterFunc(&ptr, sym)
	return ptr, nil
}
func valOf(v uintptr) unsafe.Pointer       { return **(**unsafe.Pointer)(unsafe.Pointer(&v)) }
func pointerToPointer[T any](v uintptr) *T { return *(**T)(unsafe.Pointer(&v)) }
func (c TypeRef) Ptr() unsafe.Pointer      { return *(*unsafe.Pointer)(unsafe.Pointer(&c)) }
