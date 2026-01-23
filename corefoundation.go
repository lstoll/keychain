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
	_CFDataRef                  _CFTypeRef
	_CFNumberRef                _CFTypeRef
	_CFErrorRef                 _CFTypeRef
	_CFTypeID                   uint64
	_CFRange                    struct {
		length   _CFIndex
		location _CFIndex
	}
	_CFStringEncoding uint32
	_CFNumberType     int64
)

var kCFAllocatorDefault _CFAllocatorRef = 0

var (
	corefoundation = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY|purego.RTLD_GLOBAL)

	kCFBooleanTrue                  _CFBooleanRef     = _CFBooleanRef(constsym(corefoundation, "kCFBooleanTrue"))
	kCFTypeDictionaryKeyCallBacks                     = dlsym(corefoundation, "kCFTypeDictionaryKeyCallBacks")
	kCFTypeDictionaryValueCallBacks                   = dlsym(corefoundation, "kCFTypeDictionaryValueCallBacks")
	kCFStringEncodingUTF8           _CFStringEncoding = 0x08000100

	kCFNumberIntType _CFNumberType = 9
)

var (
	_CFRelease                    = registerFunc[func(cf _CFTypeRef)](corefoundation, "CFRelease")
	_CFRetain                     = registerFunc[func(cf _CFTypeRef) _CFTypeRef](corefoundation, "CFRetain")
	_CFDictionaryCreate           = registerFunc[func(allocator _CFAllocatorRef, keys *unsafe.Pointer, values *unsafe.Pointer, numValues _CFIndex, keyCallBacks *_CFDictionaryKeyCallBacks, valueCallBacks *_CFDictionaryValueCallBacks) _CFDictionaryRef](corefoundation, "CFDictionaryCreate")
	_CFStringCreateWithCString    = registerFunc[func(alloc _CFAllocatorRef, cStr string, encoding uint32) _CFStringRef](corefoundation, "CFStringCreateWithCString")
	_CFArrayGetCount              = registerFunc[func(a _CFArrayRef) _CFIndex](corefoundation, "CFArrayGetCount")
	_CFArrayGetValues             = registerFunc[func(a _CFArrayRef, rnge _CFRange, res *unsafe.Pointer)](corefoundation, "CFArrayGetValues")
	_CFStringGetCString           = registerFunc[func(s _CFStringRef, buffer []byte, bufferSize _CFIndex, encoding _CFStringEncoding) bool](corefoundation, "CFStringGetCString")
	_CFStringGetLength            = registerFunc[func(theString _CFStringRef) _CFIndex](corefoundation, "CFStringGetLength")
	_CFDataCreate                 = registerFunc[func(allocator _CFAllocatorRef, bytes *byte, length _CFIndex) _CFDataRef](corefoundation, "CFDataCreate")
	_CFDataGetLength              = registerFunc[func(theData _CFDataRef) _CFIndex](corefoundation, "CFDataGetLength")
	_CFDataGetBytePtr             = registerFunc[func(theData _CFDataRef) *byte](corefoundation, "CFDataGetBytePtr")
	_CFDataGetBytes               = registerFunc[func(theData _CFDataRef, range_ _CFRange, buffer *byte)](corefoundation, "CFDataGetBytes")
	_CFDictionaryGetCount         = registerFunc[func(theDict _CFDictionaryRef) _CFIndex](corefoundation, "CFDictionaryGetCount")
	_CFDictionaryGetKeysAndValues = registerFunc[func(theDict _CFDictionaryRef, keys *unsafe.Pointer, values *unsafe.Pointer)](corefoundation, "CFDictionaryGetKeysAndValues")
	_CFGetTypeID                  = registerFunc[func(cf _CFTypeRef) _CFTypeID](corefoundation, "CFGetTypeID")
	_CFStringGetTypeID            = registerFunc[func() _CFTypeID](corefoundation, "CFStringGetTypeID")
	_CFDataGetTypeID              = registerFunc[func() _CFTypeID](corefoundation, "CFDataGetTypeID")
	_CFNumberGetTypeID            = registerFunc[func() _CFTypeID](corefoundation, "CFNumberGetTypeID")
	_CFArrayGetTypeID             = registerFunc[func() _CFTypeID](corefoundation, "CFArrayGetTypeID")
	_CFNumberGetValue             = registerFunc[func(number _CFNumberRef, theType _CFNumberType, valuePtr unsafe.Pointer) bool](corefoundation, "CFNumberGetValue")
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

func mapFromCFDictionary(dict _CFDictionaryRef) map[_CFTypeRef]_CFTypeRef {
	count := _CFDictionaryGetCount(dict)
	if count == 0 {
		return make(map[_CFTypeRef]_CFTypeRef)
	}

	keys := make([]unsafe.Pointer, count)
	values := make([]unsafe.Pointer, count)

	_CFDictionaryGetKeysAndValues(dict, &keys[0], &values[0])

	m := make(map[_CFTypeRef]_CFTypeRef, count)
	for i := 0; i < int(count); i++ {
		m[_CFTypeRef(keys[i])] = _CFTypeRef(values[i])
	}
	return m
}

func bytesToCFData(b []byte) _CFDataRef {
	if len(b) == 0 {
		return _CFDataCreate(kCFAllocatorDefault, nil, 0)
	}
	return _CFDataCreate(kCFAllocatorDefault, &b[0], _CFIndex(len(b)))
}

func bytesFromCFData(d _CFDataRef) []byte {
	l := _CFDataGetLength(d)
	if l == 0 {
		return nil
	}
	ptr := _CFDataGetBytePtr(d)
	if ptr != nil {
		// Use unsafe.Slice to avoid copying if we were just reading, but here we return []byte
		// so we should probably copy to be safe and match Go semantics (don't return pointer to C memory)
		// But wait, C.GoBytes copies. unsafe.Slice doesn't.
		// Let's create a new slice and copy.
		s := unsafe.Slice(ptr, l)
		ret := make([]byte, l)
		copy(ret, s)
		return ret
	}

	// If no direct pointer, copy via GetBytes
	ret := make([]byte, l)
	_CFDataGetBytes(d, _CFRange{0, l}, &ret[0])
	return ret
}

func goSliceFromCFArray(arr _CFArrayRef) []_CFTypeRef {
	count := _CFArrayGetCount(arr)
	if count == 0 {
		return nil
	}
	vals := make([]unsafe.Pointer, count)
	_CFArrayGetValues(arr, _CFRange{0, count}, &vals[0])

	ret := make([]_CFTypeRef, count)
	for i, v := range vals {
		ret[i] = _CFTypeRef(v)
	}
	return ret
}

// cfDictLookup looks up a value in a CFDictionary by comparing string keys.
func cfDictLookup(attrs map[_CFTypeRef]_CFTypeRef, key _CFStringRef) (_CFTypeRef, bool) {
	keyStr := cfStringtoString(key)
	for k, v := range attrs {
		if _CFGetTypeID(k) == _CFStringGetTypeID() {
			if cfStringtoString(_CFStringRef(k)) == keyStr {
				return v, true
			}
		}
	}
	return 0, false
}

func getStringAttr(attrs map[_CFTypeRef]_CFTypeRef, key _CFStringRef) (string, bool) {
	if val, ok := cfDictLookup(attrs, key); ok {
		if _CFGetTypeID(val) == _CFStringGetTypeID() {
			return cfStringtoString(_CFStringRef(val)), true
		}
	}
	return "", false
}

func getDataAttr(attrs map[_CFTypeRef]_CFTypeRef, key _CFStringRef) ([]byte, bool) {
	if val, ok := cfDictLookup(attrs, key); ok {
		if _CFGetTypeID(val) == _CFDataGetTypeID() {
			return bytesFromCFData(_CFDataRef(val)), true
		}
	}
	return nil, false
}

func getIntAttr(attrs map[_CFTypeRef]_CFTypeRef, key _CFStringRef) (int, bool) {
	if val, ok := cfDictLookup(attrs, key); ok {
		if _CFGetTypeID(val) == _CFNumberGetTypeID() {
			var num int32
			if _CFNumberGetValue(_CFNumberRef(val), kCFNumberIntType, unsafe.Pointer(&num)) {
				return int(num), true
			}
			// Try int64 if int32 fails? Or just rely on kCFNumberIntType matching standard int
			var num64 int64
			if _CFNumberGetValue(_CFNumberRef(val), 4, unsafe.Pointer(&num64)) { // 4 = kCFNumberLongLongType
				return int(num64), true
			}
		}
	}
	return 0, false
}

// Helper to convert C arrays to Go slices for other types if needed?
// Not strictly needed if we just use pointer arithmetic or unsafe.Slice.
