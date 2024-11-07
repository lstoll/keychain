//go:build darwin

package keychain

import (
	"unsafe"

	"github.com/ebitengine/purego"
)

type (
	_CFTypeRef                  uintptr
	_CFDictionaryRef            uintptr
	_CFAllocatorRef             uintptr
	_CFIndex                    int64
	_CFDictionaryKeyCallBacks   struct{}
	_CFDictionaryValueCallBacks struct{}
	_CFString                   uintptr
	_CFArrayRef                 uintptr
	_CFRange                    struct {
		length   _CFIndex
		location _CFIndex
	}
)

var kCFAllocatorDefault _CFAllocatorRef = 0

var (
	corefoundation = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY|purego.RTLD_GLOBAL)

	kCFBooleanTrue                  = dlsym(corefoundation, "kCFBooleanTrue")
	kCFTypeDictionaryKeyCallBacks   = dlsym(corefoundation, "kCFTypeDictionaryKeyCallBacks")
	kCFTypeDictionaryValueCallBacks = dlsym(corefoundation, "kCFTypeDictionaryValueCallBacks")
	kCFStringEncodingUTF8           = 0x08000100
)

var (
	_CFRelease                 = registerFunc[func(cf _CFTypeRef)](corefoundation, "CFRelease")
	_CFDictionaryCreate        = registerFunc[func(allocator _CFAllocatorRef, keys *unsafe.Pointer, values *unsafe.Pointer, numValues _CFIndex, keyCallBacks *_CFDictionaryKeyCallBacks, valueCallBacks *_CFDictionaryValueCallBacks) _CFDictionaryRef](corefoundation, "CFDictionaryCreate")
	_CFStringCreateWithCString = registerFunc[func(alloc _CFAllocatorRef, cStr string, encoding uint32) _CFString](corefoundation, "CFStringCreateWithCString")
	_CFArrayGetCount           = registerFunc[func(a _CFArrayRef) _CFIndex](corefoundation, "CFArrayGetCount")
	_CFArrayGetValues          = registerFunc[func(a _CFArrayRef, rnge _CFRange, res *unsafe.Pointer)](corefoundation, "CFArrayGetValues")
)

func stringToCFString(s string) _CFString {
	return _CFStringCreateWithCString(kCFAllocatorDefault, s, uint32(kCFStringEncodingUTF8))
}
