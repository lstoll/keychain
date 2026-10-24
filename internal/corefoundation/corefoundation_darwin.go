//go:build darwin

package corefoundation

import (
	"fmt"
	"sync"
	"unicode/utf8"
	"unsafe"

	"github.com/ebitengine/purego"
)

type (
	TypeRef                  uintptr
	DictionaryRef            TypeRef
	AllocatorRef             TypeRef
	Index                    int64
	DictionaryKeyCallBacks   struct{}
	DictionaryValueCallBacks struct{}
	StringRef                TypeRef
	ArrayRef                 TypeRef
	BooleanRef               TypeRef
	DataRef                  TypeRef
	NumberRef                TypeRef
	ErrorRef                 TypeRef
	TypeID                   uint64
	Range                    struct {
		Location Index
		Length   Index
	}
	StringEncoding uint32
	NumberType     int64
)

const NumberSInt64Type NumberType = 4

// AllocatorDefault is NULL, which selects the default allocator.
var AllocatorDefault AllocatorRef

type Framework struct {
	BooleanTrue                  BooleanRef
	BooleanFalse                 BooleanRef
	TypeDictionaryKeyCallBacks   uintptr
	TypeDictionaryValueCallBacks uintptr
	StringEncodingUTF8           StringEncoding

	NumberCreate  func(allocator AllocatorRef, numberType NumberType, value unsafe.Pointer) NumberRef
	NumberIntType NumberType

	Release                         func(cf TypeRef)
	Retain                          func(cf TypeRef) TypeRef
	DictionaryCreate                func(allocator AllocatorRef, keys *unsafe.Pointer, values *unsafe.Pointer, numValues Index, keyCallBacks *DictionaryKeyCallBacks, valueCallBacks *DictionaryValueCallBacks) DictionaryRef
	StringCreateWithBytes           func(alloc AllocatorRef, bytes *byte, numBytes Index, encoding StringEncoding, externalRepresentation bool) StringRef
	StringGetBytes                  func(s StringRef, range_ Range, encoding StringEncoding, lossByte byte, isExternalRepresentation bool, buffer *byte, maxBufLen Index, usedBufLen *Index) Index
	ArrayGetCount                   func(a ArrayRef) Index
	ArrayGetValues                  func(a ArrayRef, rnge Range, res *unsafe.Pointer)
	StringGetCString                func(s StringRef, buffer []byte, bufferSize Index, encoding StringEncoding) bool
	StringGetLength                 func(theString StringRef) Index
	StringGetMaximumSizeForEncoding func(numChars Index, encoding StringEncoding) Index
	DataCreate                      func(allocator AllocatorRef, bytes *byte, length Index) DataRef
	DataGetLength                   func(theData DataRef) Index
	DataGetBytePtr                  func(theData DataRef) *byte
	DataGetBytes                    func(theData DataRef, range_ Range, buffer *byte)
	DictionaryGetCount              func(theDict DictionaryRef) Index
	DictionaryGetKeysAndValues      func(theDict DictionaryRef, keys *unsafe.Pointer, values *unsafe.Pointer)
	DictionaryGetValue              func(theDict DictionaryRef, key TypeRef) TypeRef
	GetTypeID                       func(cf TypeRef) TypeID
	StringGetTypeID                 func() TypeID
	DataGetTypeID                   func() TypeID
	NumberGetTypeID                 func() TypeID
	ArrayGetTypeID                  func() TypeID
	NumberGetValue                  func(number NumberRef, theType NumberType, valuePtr unsafe.Pointer) bool

	TypeArrayCallBacks   uintptr // &kCFTypeArrayCallBacks
	ArrayCreate          func(allocator AllocatorRef, values *unsafe.Pointer, numValues Index, callBacks uintptr) ArrayRef
	ErrorCopyDescription func(err ErrorRef) StringRef
	ErrorGetDomain       func(err ErrorRef) StringRef
	ErrorGetCode         func(err ErrorRef) Index
}

var (
	framework     *Framework
	frameworkErr  error
	frameworkOnce sync.Once
)

func Get() (*Framework, error) {
	frameworkOnce.Do(func() {
		handle, err := dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
		if err != nil {
			frameworkErr = err
			return
		}

		c := &Framework{}

		// Constants
		if kCFBooleanTrue, err := constsym(handle, "kCFBooleanTrue"); err == nil {
			c.BooleanTrue = BooleanRef(kCFBooleanTrue)
		} else {
			frameworkErr = err
			return
		}
		if kCFBooleanFalse, err := constsym(handle, "kCFBooleanFalse"); err == nil {
			c.BooleanFalse = BooleanRef(kCFBooleanFalse)
		} else {
			frameworkErr = err
			return
		}
		if kCFTypeDictionaryKeyCallBacks, err := purego.Dlsym(handle, "kCFTypeDictionaryKeyCallBacks"); err == nil {
			c.TypeDictionaryKeyCallBacks = kCFTypeDictionaryKeyCallBacks
		} else {
			frameworkErr = err
			return
		}
		if kCFTypeDictionaryValueCallBacks, err := purego.Dlsym(handle, "kCFTypeDictionaryValueCallBacks"); err == nil {
			c.TypeDictionaryValueCallBacks = kCFTypeDictionaryValueCallBacks
		} else {
			frameworkErr = err
			return
		}
		c.StringEncodingUTF8 = 0x08000100
		c.NumberIntType = 9

		// Functions
		if c.NumberCreate, err = registerFunc[func(AllocatorRef, NumberType, unsafe.Pointer) NumberRef](handle, "CFNumberCreate"); err != nil {
			frameworkErr = err
			return
		}
		if c.Release, err = registerFunc[func(cf TypeRef)](handle, "CFRelease"); err != nil {
			frameworkErr = err
			return
		}
		if c.Retain, err = registerFunc[func(cf TypeRef) TypeRef](handle, "CFRetain"); err != nil {
			frameworkErr = err
			return
		}
		if c.DictionaryCreate, err = registerFunc[func(allocator AllocatorRef, keys *unsafe.Pointer, values *unsafe.Pointer, numValues Index, keyCallBacks *DictionaryKeyCallBacks, valueCallBacks *DictionaryValueCallBacks) DictionaryRef](handle, "CFDictionaryCreate"); err != nil {
			frameworkErr = err
			return
		}
		if c.StringCreateWithBytes, err = registerFunc[func(alloc AllocatorRef, bytes *byte, numBytes Index, encoding StringEncoding, externalRepresentation bool) StringRef](handle, "CFStringCreateWithBytes"); err != nil {
			frameworkErr = err
			return
		}
		if c.StringGetBytes, err = registerFunc[func(s StringRef, range_ Range, encoding StringEncoding, lossByte byte, external bool, buffer *byte, maxBufLen Index, usedBufLen *Index) Index](handle, "CFStringGetBytes"); err != nil {
			frameworkErr = err
			return
		}
		if c.ArrayGetCount, err = registerFunc[func(a ArrayRef) Index](handle, "CFArrayGetCount"); err != nil {
			frameworkErr = err
			return
		}
		if c.ArrayGetValues, err = registerFunc[func(a ArrayRef, rnge Range, res *unsafe.Pointer)](handle, "CFArrayGetValues"); err != nil {
			frameworkErr = err
			return
		}
		if c.StringGetCString, err = registerFunc[func(s StringRef, buffer []byte, bufferSize Index, encoding StringEncoding) bool](handle, "CFStringGetCString"); err != nil {
			frameworkErr = err
			return
		}
		if c.StringGetLength, err = registerFunc[func(theString StringRef) Index](handle, "CFStringGetLength"); err != nil {
			frameworkErr = err
			return
		}
		if c.StringGetMaximumSizeForEncoding, err = registerFunc[func(numChars Index, encoding StringEncoding) Index](handle, "CFStringGetMaximumSizeForEncoding"); err != nil {
			frameworkErr = err
			return
		}
		if c.DataCreate, err = registerFunc[func(allocator AllocatorRef, bytes *byte, length Index) DataRef](handle, "CFDataCreate"); err != nil {
			frameworkErr = err
			return
		}
		if c.DataGetLength, err = registerFunc[func(theData DataRef) Index](handle, "CFDataGetLength"); err != nil {
			frameworkErr = err
			return
		}
		if c.DataGetBytePtr, err = registerFunc[func(theData DataRef) *byte](handle, "CFDataGetBytePtr"); err != nil {
			frameworkErr = err
			return
		}
		if c.DataGetBytes, err = registerFunc[func(theData DataRef, range_ Range, buffer *byte)](handle, "CFDataGetBytes"); err != nil {
			frameworkErr = err
			return
		}
		if c.DictionaryGetCount, err = registerFunc[func(theDict DictionaryRef) Index](handle, "CFDictionaryGetCount"); err != nil {
			frameworkErr = err
			return
		}
		if c.DictionaryGetKeysAndValues, err = registerFunc[func(theDict DictionaryRef, keys *unsafe.Pointer, values *unsafe.Pointer)](handle, "CFDictionaryGetKeysAndValues"); err != nil {
			frameworkErr = err
			return
		}
		if c.DictionaryGetValue, err = registerFunc[func(theDict DictionaryRef, key TypeRef) TypeRef](handle, "CFDictionaryGetValue"); err != nil {
			frameworkErr = err
			return
		}
		if c.GetTypeID, err = registerFunc[func(cf TypeRef) TypeID](handle, "CFGetTypeID"); err != nil {
			frameworkErr = err
			return
		}
		if c.StringGetTypeID, err = registerFunc[func() TypeID](handle, "CFStringGetTypeID"); err != nil {
			frameworkErr = err
			return
		}
		if c.DataGetTypeID, err = registerFunc[func() TypeID](handle, "CFDataGetTypeID"); err != nil {
			frameworkErr = err
			return
		}
		if c.NumberGetTypeID, err = registerFunc[func() TypeID](handle, "CFNumberGetTypeID"); err != nil {
			frameworkErr = err
			return
		}
		if c.ArrayGetTypeID, err = registerFunc[func() TypeID](handle, "CFArrayGetTypeID"); err != nil {
			frameworkErr = err
			return
		}
		if c.NumberGetValue, err = registerFunc[func(number NumberRef, theType NumberType, valuePtr unsafe.Pointer) bool](handle, "CFNumberGetValue"); err != nil {
			frameworkErr = err
			return
		}
		if kCFTypeArrayCallBacks, err := purego.Dlsym(handle, "kCFTypeArrayCallBacks"); err == nil {
			c.TypeArrayCallBacks = kCFTypeArrayCallBacks
		} else {
			frameworkErr = err
			return
		}
		if c.ArrayCreate, err = registerFunc[func(allocator AllocatorRef, values *unsafe.Pointer, numValues Index, callBacks uintptr) ArrayRef](handle, "CFArrayCreate"); err != nil {
			frameworkErr = err
			return
		}
		if c.ErrorCopyDescription, err = registerFunc[func(err ErrorRef) StringRef](handle, "CFErrorCopyDescription"); err != nil {
			frameworkErr = err
			return
		}
		if c.ErrorGetDomain, err = registerFunc[func(err ErrorRef) StringRef](handle, "CFErrorGetDomain"); err != nil {
			frameworkErr = err
			return
		}
		if c.ErrorGetCode, err = registerFunc[func(err ErrorRef) Index](handle, "CFErrorGetCode"); err != nil {
			frameworkErr = err
			return
		}

		framework = c
	})

	return framework, frameworkErr
}

// CreateString creates a caller-owned CFString, preserving embedded NULs.
// Invalid UTF-8 returns an error.
func (c *Framework) CreateString(s string) (StringRef, error) {
	if !utf8.ValidString(s) {
		return 0, fmt.Errorf("string is not valid UTF-8")
	}
	ref := c.StringToCFString(s)
	if ref == 0 {
		return 0, fmt.Errorf("CFStringCreateWithBytes returned null")
	}
	return ref, nil
}

// StringToCFString creates a caller-owned CFString, or returns zero for invalid UTF-8.
func (c *Framework) StringToCFString(s string) StringRef {
	if !utf8.ValidString(s) {
		return 0
	}
	b := []byte(s)
	var ptr *byte
	if len(b) > 0 {
		ptr = &b[0]
	}
	return c.StringCreateWithBytes(AllocatorDefault, ptr, Index(len(b)), c.StringEncodingUTF8, false)
}

// CFStringToString converts by explicit UTF-16 character length, preserving embedded NULs.
func (c *Framework) CFStringToString(s StringRef) string {
	if s == 0 {
		return ""
	}
	chars := c.StringGetLength(s)
	if chars <= 0 {
		return ""
	}
	maxBytes := c.StringGetMaximumSizeForEncoding(chars, c.StringEncodingUTF8)
	if maxBytes <= 0 {
		return ""
	}
	buf := make([]byte, maxBytes)
	used := Index(0)
	converted := c.StringGetBytes(s, Range{Location: 0, Length: chars}, c.StringEncodingUTF8, 0, false, &buf[0], maxBytes, &used)
	if converted != chars || used < 0 || used > maxBytes {
		return ""
	}
	return string(buf[:used])
}

func (c *Framework) MapToCFDictionary(m map[TypeRef]TypeRef) (DictionaryRef, error) {
	keys, values := make([]unsafe.Pointer, 0, len(m)), make([]unsafe.Pointer, 0, len(m))
	for k, v := range m {
		keys = append(keys, k.Ptr())
		values = append(values, v.Ptr())
	}
	var kp, vp *unsafe.Pointer
	if len(keys) > 0 {
		kp, vp = &keys[0], &values[0]
	}
	dict := c.DictionaryCreate(AllocatorDefault, kp, vp, Index(len(keys)),
		pointerToPointer[DictionaryKeyCallBacks](c.TypeDictionaryKeyCallBacks),
		pointerToPointer[DictionaryValueCallBacks](c.TypeDictionaryValueCallBacks))
	if dict == DictionaryRef(0) {
		return DictionaryRef(0), fmt.Errorf("creating dictionary failed")
	}
	return dict, nil
}

func (c *Framework) BytesToCFData(b []byte) DataRef {
	if len(b) == 0 {
		return c.DataCreate(AllocatorDefault, nil, 0)
	}
	return c.DataCreate(AllocatorDefault, &b[0], Index(len(b)))
}

func (c *Framework) BytesFromCFData(d DataRef) []byte {
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
	c.DataGetBytes(d, Range{Location: 0, Length: l}, &ret[0])
	return ret
}

// ArrayOfRefs returns a retained CFArray of Core Foundation objects.
func (c *Framework) ArrayOfRefs(values []TypeRef) ArrayRef {
	if len(values) == 0 {
		return c.ArrayCreate(AllocatorDefault, nil, 0, c.TypeArrayCallBacks)
	}
	ptrs := make([]unsafe.Pointer, len(values))
	for i, v := range values {
		ptrs[i] = v.Ptr()
	}
	return c.ArrayCreate(AllocatorDefault, &ptrs[0], Index(len(ptrs)), c.TypeArrayCallBacks)
}

func (c *Framework) GoSliceFromCFArray(arr ArrayRef) []TypeRef {
	count := c.ArrayGetCount(arr)
	if count == 0 {
		return nil
	}
	vals := make([]unsafe.Pointer, count)
	c.ArrayGetValues(arr, Range{Location: 0, Length: count}, &vals[0])

	ret := make([]TypeRef, count)
	for i, v := range vals {
		ret[i] = TypeRef(v)
	}
	return ret
}

func (c *Framework) GetDictionaryValue(dict DictionaryRef, key StringRef) TypeRef {
	return c.DictionaryGetValue(dict, TypeRef(key))
}

func (c *Framework) GetDictionaryString(dict DictionaryRef, key StringRef) (string, bool) {
	val := c.GetDictionaryValue(dict, key)
	if val != 0 && c.GetTypeID(val) == c.StringGetTypeID() {
		return c.CFStringToString(StringRef(val)), true
	}
	return "", false
}

func (c *Framework) GetDictionaryData(dict DictionaryRef, key StringRef) ([]byte, bool) {
	val := c.GetDictionaryValue(dict, key)
	if val != 0 && c.GetTypeID(val) == c.DataGetTypeID() {
		return c.BytesFromCFData(DataRef(val)), true
	}
	return nil, false
}

func (c *Framework) GetDictionaryInt(dict DictionaryRef, key StringRef) (int, bool) {
	val := c.GetDictionaryValue(dict, key)
	if val != 0 && c.GetTypeID(val) == c.NumberGetTypeID() {
		var num int32
		if c.NumberGetValue(NumberRef(val), c.NumberIntType, unsafe.Pointer(&num)) {
			return int(num), true
		}
		var num64 int64
		if c.NumberGetValue(NumberRef(val), 4, unsafe.Pointer(&num64)) {
			return int(num64), true
		}
	}
	return 0, false
}

// NumberFromInt creates a caller-owned CFNumber.
func (c *Framework) NumberFromInt(value int64) NumberRef {
	v := value
	return c.NumberCreate(AllocatorDefault, NumberSInt64Type, unsafe.Pointer(&v))
}

// Int64FromNumber reads a CFNumber as an int64.
func (c *Framework) Int64FromNumber(number NumberRef) (int64, bool) {
	var value int64
	if !c.NumberGetValue(number, 4, unsafe.Pointer(&value)) {
		return 0, false
	}
	return value, true
}
