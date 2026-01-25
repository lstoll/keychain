//go:build darwin

package keychain

import (
	"fmt"
	"sync"
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

type coreFoundation struct {
	BooleanTrue                  _CFBooleanRef
	TypeDictionaryKeyCallBacks   uintptr
	TypeDictionaryValueCallBacks uintptr
	StringEncodingUTF8           _CFStringEncoding

	NumberIntType _CFNumberType

	Release                    func(cf _CFTypeRef)
	Retain                     func(cf _CFTypeRef) _CFTypeRef
	DictionaryCreate           func(allocator _CFAllocatorRef, keys *unsafe.Pointer, values *unsafe.Pointer, numValues _CFIndex, keyCallBacks *_CFDictionaryKeyCallBacks, valueCallBacks *_CFDictionaryValueCallBacks) _CFDictionaryRef
	StringCreateWithCString    func(alloc _CFAllocatorRef, cStr string, encoding uint32) _CFStringRef
	ArrayGetCount              func(a _CFArrayRef) _CFIndex
	ArrayGetValues             func(a _CFArrayRef, rnge _CFRange, res *unsafe.Pointer)
	StringGetCString           func(s _CFStringRef, buffer []byte, bufferSize _CFIndex, encoding _CFStringEncoding) bool
	StringGetLength            func(theString _CFStringRef) _CFIndex
	DataCreate                 func(allocator _CFAllocatorRef, bytes *byte, length _CFIndex) _CFDataRef
	DataGetLength              func(theData _CFDataRef) _CFIndex
	DataGetBytePtr             func(theData _CFDataRef) *byte
	DataGetBytes               func(theData _CFDataRef, range_ _CFRange, buffer *byte)
	DictionaryGetCount         func(theDict _CFDictionaryRef) _CFIndex
	DictionaryGetKeysAndValues func(theDict _CFDictionaryRef, keys *unsafe.Pointer, values *unsafe.Pointer)
	DictionaryGetValue         func(theDict _CFDictionaryRef, key _CFTypeRef) _CFTypeRef
	GetTypeID                  func(cf _CFTypeRef) _CFTypeID
	StringGetTypeID            func() _CFTypeID
	DataGetTypeID              func() _CFTypeID
	NumberGetTypeID            func() _CFTypeID
	ArrayGetTypeID             func() _CFTypeID
	NumberGetValue             func(number _CFNumberRef, theType _CFNumberType, valuePtr unsafe.Pointer) bool
}

var (
	_cf     *coreFoundation
	_cfOnce sync.Once
)

func getCoreFoundation() (*coreFoundation, error) {
	var _cfErr error

	_cfOnce.Do(func() {
		handle, err := dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
		if err != nil {
			_cfErr = err
			return
		}

		c := &coreFoundation{}

		// Constants
		if kCFBooleanTrue, err := constsym(handle, "kCFBooleanTrue"); err == nil {
			c.BooleanTrue = _CFBooleanRef(kCFBooleanTrue)
		} else {
			_cfErr = err
			return
		}
		if kCFTypeDictionaryKeyCallBacks, err := purego.Dlsym(handle, "kCFTypeDictionaryKeyCallBacks"); err == nil {
			c.TypeDictionaryKeyCallBacks = kCFTypeDictionaryKeyCallBacks
		} else {
			_cfErr = err
			return
		}
		if kCFTypeDictionaryValueCallBacks, err := purego.Dlsym(handle, "kCFTypeDictionaryValueCallBacks"); err == nil {
			c.TypeDictionaryValueCallBacks = kCFTypeDictionaryValueCallBacks
		} else {
			_cfErr = err
			return
		}
		c.StringEncodingUTF8 = 0x08000100
		c.NumberIntType = 9

		// Functions
		if c.Release, err = registerFunc[func(cf _CFTypeRef)](handle, "CFRelease"); err != nil {
			_cfErr = err
			return
		}
		if c.Retain, err = registerFunc[func(cf _CFTypeRef) _CFTypeRef](handle, "CFRetain"); err != nil {
			_cfErr = err
			return
		}
		if c.DictionaryCreate, err = registerFunc[func(allocator _CFAllocatorRef, keys *unsafe.Pointer, values *unsafe.Pointer, numValues _CFIndex, keyCallBacks *_CFDictionaryKeyCallBacks, valueCallBacks *_CFDictionaryValueCallBacks) _CFDictionaryRef](handle, "CFDictionaryCreate"); err != nil {
			_cfErr = err
			return
		}
		if c.StringCreateWithCString, err = registerFunc[func(alloc _CFAllocatorRef, cStr string, encoding uint32) _CFStringRef](handle, "CFStringCreateWithCString"); err != nil {
			_cfErr = err
			return
		}
		if c.ArrayGetCount, err = registerFunc[func(a _CFArrayRef) _CFIndex](handle, "CFArrayGetCount"); err != nil {
			_cfErr = err
			return
		}
		if c.ArrayGetValues, err = registerFunc[func(a _CFArrayRef, rnge _CFRange, res *unsafe.Pointer)](handle, "CFArrayGetValues"); err != nil {
			_cfErr = err
			return
		}
		if c.StringGetCString, err = registerFunc[func(s _CFStringRef, buffer []byte, bufferSize _CFIndex, encoding _CFStringEncoding) bool](handle, "CFStringGetCString"); err != nil {
			_cfErr = err
			return
		}
		if c.StringGetLength, err = registerFunc[func(theString _CFStringRef) _CFIndex](handle, "CFStringGetLength"); err != nil {
			_cfErr = err
			return
		}
		if c.DataCreate, err = registerFunc[func(allocator _CFAllocatorRef, bytes *byte, length _CFIndex) _CFDataRef](handle, "CFDataCreate"); err != nil {
			_cfErr = err
			return
		}
		if c.DataGetLength, err = registerFunc[func(theData _CFDataRef) _CFIndex](handle, "CFDataGetLength"); err != nil {
			_cfErr = err
			return
		}
		if c.DataGetBytePtr, err = registerFunc[func(theData _CFDataRef) *byte](handle, "CFDataGetBytePtr"); err != nil {
			_cfErr = err
			return
		}
		if c.DataGetBytes, err = registerFunc[func(theData _CFDataRef, range_ _CFRange, buffer *byte)](handle, "CFDataGetBytes"); err != nil {
			_cfErr = err
			return
		}
		if c.DictionaryGetCount, err = registerFunc[func(theDict _CFDictionaryRef) _CFIndex](handle, "CFDictionaryGetCount"); err != nil {
			_cfErr = err
			return
		}
		if c.DictionaryGetKeysAndValues, err = registerFunc[func(theDict _CFDictionaryRef, keys *unsafe.Pointer, values *unsafe.Pointer)](handle, "CFDictionaryGetKeysAndValues"); err != nil {
			_cfErr = err
			return
		}
		if c.DictionaryGetValue, err = registerFunc[func(theDict _CFDictionaryRef, key _CFTypeRef) _CFTypeRef](handle, "CFDictionaryGetValue"); err != nil {
			_cfErr = err
			return
		}
		if c.GetTypeID, err = registerFunc[func(cf _CFTypeRef) _CFTypeID](handle, "CFGetTypeID"); err != nil {
			_cfErr = err
			return
		}
		if c.StringGetTypeID, err = registerFunc[func() _CFTypeID](handle, "CFStringGetTypeID"); err != nil {
			_cfErr = err
			return
		}
		if c.DataGetTypeID, err = registerFunc[func() _CFTypeID](handle, "CFDataGetTypeID"); err != nil {
			_cfErr = err
			return
		}
		if c.NumberGetTypeID, err = registerFunc[func() _CFTypeID](handle, "CFNumberGetTypeID"); err != nil {
			_cfErr = err
			return
		}
		if c.ArrayGetTypeID, err = registerFunc[func() _CFTypeID](handle, "CFArrayGetTypeID"); err != nil {
			_cfErr = err
			return
		}
		if c.NumberGetValue, err = registerFunc[func(number _CFNumberRef, theType _CFNumberType, valuePtr unsafe.Pointer) bool](handle, "CFNumberGetValue"); err != nil {
			_cfErr = err
			return
		}

		_cf = c
	})

	return _cf, _cfErr
}

func (c *coreFoundation) StringToCFString(s string) _CFStringRef {
	return c.StringCreateWithCString(kCFAllocatorDefault, s, uint32(c.StringEncodingUTF8))
}

func (c *coreFoundation) CFStringToString(s _CFStringRef) string {
	len := c.StringGetLength(s) + 1
	buf := make([]byte, len-1)
	c.StringGetCString(s, buf[:], len, c.StringEncodingUTF8)
	return string(buf)
}

func (c *coreFoundation) MapToCFDictionary(m map[_CFTypeRef]_CFTypeRef) (_CFDictionaryRef, error) {
	keys, values := make([]unsafe.Pointer, 0, len(m)), make([]unsafe.Pointer, 0, len(m))
	for k, v := range m {
		keys = append(keys, k.Ptr())
		values = append(values, v.Ptr())
	}
	dict := c.DictionaryCreate(kCFAllocatorDefault, &keys[0], &values[0], _CFIndex(len(keys)),
		tPtr[_CFDictionaryKeyCallBacks](c.TypeDictionaryKeyCallBacks),
		tPtr[_CFDictionaryValueCallBacks](c.TypeDictionaryValueCallBacks))
	if dict == _CFDictionaryRef(0) {
		return _CFDictionaryRef(0), fmt.Errorf("creating dictionary failed")
	}
	return dict, nil
}

func (c *coreFoundation) BytesToCFData(b []byte) _CFDataRef {
	if len(b) == 0 {
		return c.DataCreate(kCFAllocatorDefault, nil, 0)
	}
	return c.DataCreate(kCFAllocatorDefault, &b[0], _CFIndex(len(b)))
}

func (c *coreFoundation) BytesFromCFData(d _CFDataRef) []byte {
	l := c.DataGetLength(d)
	if l == 0 {
		return nil
	}
	ptr := c.DataGetBytePtr(d)
	if ptr != nil {
		s := unsafe.Slice(ptr, l)
		ret := make([]byte, l)
		copy(ret, s)
		return ret
	}

	ret := make([]byte, l)
	c.DataGetBytes(d, _CFRange{0, l}, &ret[0])
	return ret
}

func (c *coreFoundation) GoSliceFromCFArray(arr _CFArrayRef) []_CFTypeRef {
	count := c.ArrayGetCount(arr)
	if count == 0 {
		return nil
	}
	vals := make([]unsafe.Pointer, count)
	c.ArrayGetValues(arr, _CFRange{0, count}, &vals[0])

	ret := make([]_CFTypeRef, count)
	for i, v := range vals {
		ret[i] = _CFTypeRef(v)
	}
	return ret
}

func (c *coreFoundation) GetDictionaryValue(dict _CFDictionaryRef, key _CFStringRef) _CFTypeRef {
	return c.DictionaryGetValue(dict, _CFTypeRef(key))
}

func (c *coreFoundation) GetDictionaryString(dict _CFDictionaryRef, key _CFStringRef) (string, bool) {
	val := c.GetDictionaryValue(dict, key)
	if val != 0 && c.GetTypeID(val) == c.StringGetTypeID() {
		return c.CFStringToString(_CFStringRef(val)), true
	}
	return "", false
}

func (c *coreFoundation) GetDictionaryData(dict _CFDictionaryRef, key _CFStringRef) ([]byte, bool) {
	val := c.GetDictionaryValue(dict, key)
	if val != 0 && c.GetTypeID(val) == c.DataGetTypeID() {
		return c.BytesFromCFData(_CFDataRef(val)), true
	}
	return nil, false
}

func (c *coreFoundation) GetDictionaryInt(dict _CFDictionaryRef, key _CFStringRef) (int, bool) {
	val := c.GetDictionaryValue(dict, key)
	if val != 0 && c.GetTypeID(val) == c.NumberGetTypeID() {
		var num int32
		if c.NumberGetValue(_CFNumberRef(val), c.NumberIntType, unsafe.Pointer(&num)) {
			return int(num), true
		}
		var num64 int64
		if c.NumberGetValue(_CFNumberRef(val), 4, unsafe.Pointer(&num64)) {
			return int(num64), true
		}
	}
	return 0, false
}
