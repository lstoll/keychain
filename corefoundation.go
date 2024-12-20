//go:build darwin

package keychain

import (
	"fmt"
	"unsafe"

	"github.com/ebitengine/purego"
)

type (
	_CFTypeRef                  uintptr
	_CFDictionaryRef            _CFTypeRef
	_CFAllocatorRef             _CFTypeRef
	_CFIndex                    int64
	_CFDictionaryKeyCallBacks   struct{}
	_CFDictionaryValueCallBacks struct{}
	_CFStringRef                _CFTypeRef
	_CFArrayRef                 _CFTypeRef
	_CFBooleanRef               _CFTypeRef
	_CFRange                    struct {
		length   _CFIndex
		location _CFIndex
	}
	_CFStringEncoding uint32
)

var kCFAllocatorDefault _CFAllocatorRef = 0

var (
	corefoundation = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY|purego.RTLD_GLOBAL)

	kCFBooleanTrue                  _CFBooleanRef     = _CFBooleanRef(constsym(corefoundation, "kCFBooleanTrue"))
	kCFTypeDictionaryKeyCallBacks                     = constsym(corefoundation, "kCFTypeDictionaryKeyCallBacks")
	kCFTypeDictionaryValueCallBacks                   = constsym(corefoundation, "kCFTypeDictionaryValueCallBacks")
	kCFStringEncodingUTF8           _CFStringEncoding = 0x08000100
)

var (
	_CFRelease                 = registerFunc[func(cf _CFTypeRef)](corefoundation, "CFRelease")
	_CFDictionaryCreate        = registerFunc[func(allocator _CFAllocatorRef, keys *unsafe.Pointer, values *unsafe.Pointer, numValues _CFIndex, keyCallBacks *_CFDictionaryKeyCallBacks, valueCallBacks *_CFDictionaryValueCallBacks) _CFDictionaryRef](corefoundation, "CFDictionaryCreate")
	_CFStringCreateWithCString = registerFunc[func(alloc _CFAllocatorRef, cStr string, encoding uint32) _CFStringRef](corefoundation, "CFStringCreateWithCString")
	_CFArrayGetCount           = registerFunc[func(a _CFArrayRef) _CFIndex](corefoundation, "CFArrayGetCount")
	_CFArrayGetValues          = registerFunc[func(a _CFArrayRef, rnge _CFRange, res *unsafe.Pointer)](corefoundation, "CFArrayGetValues")
	_CFStringGetCString        = registerFunc[func(s _CFStringRef, buffer []byte, bufferSize _CFIndex, encoding _CFStringEncoding) bool](corefoundation, "CFStringGetCString")
	_CFStringGetLength         = registerFunc[func(theString _CFStringRef) _CFIndex](corefoundation, "CFStringGetLength")
)

func stringToCFString(s string) _CFStringRef {
	return _CFStringCreateWithCString(kCFAllocatorDefault, s, uint32(kCFStringEncodingUTF8))
}

func cfStringtoString(s _CFStringRef) string {
	len := _CFStringGetLength(s) + 1
	buf := make([]byte, len-1)
	_CFStringGetCString(s, buf[:], len, kCFStringEncodingUTF8)
	return string(buf)
}

func mapToCFDictionary(m map[_CFTypeRef]_CFTypeRef) (_CFDictionaryRef, error) {
	keys, values := make([]unsafe.Pointer, 0, len(m)), make([]unsafe.Pointer, 0, len(m))
	for k, v := range m {
		keys = append(keys, k.Ptr())
		values = append(values, v.Ptr())
	}
	dict := _CFDictionaryCreate(kCFAllocatorDefault, &keys[0], &values[0], _CFIndex(len(keys)),
		tPtr[_CFDictionaryKeyCallBacks](kCFTypeDictionaryKeyCallBacks),
		tPtr[_CFDictionaryValueCallBacks](kCFTypeDictionaryValueCallBacks))
	if dict == _CFDictionaryRef(0) {
		return _CFDictionaryRef(0), fmt.Errorf("creating dictionary failed")
	}
	return dict, nil
}
