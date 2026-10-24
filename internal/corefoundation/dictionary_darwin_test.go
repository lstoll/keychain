//go:build darwin

package corefoundation

import (
	"testing"
	"unsafe"
)

func TestStringRoundTrip(t *testing.T) {
	cf, err := Get()
	if err != nil {
		t.Fatal(err)
	}
	in := "hello world"
	s := cf.StringToCFString(in)
	defer cf.Release(TypeRef(s))
	if out := cf.CFStringToString(s); out != in {
		t.Errorf("want %s, got: %s", in, out)
	}
}

func TestMapToCFDictionary(t *testing.T) {
	cf, err := Get()
	if err != nil {
		t.Fatal(err)
	}
	k, v := cf.StringToCFString("hello"), cf.StringToCFString("world")
	defer cf.Release(TypeRef(k))
	defer cf.Release(TypeRef(v))
	dict, err := cf.MapToCFDictionary(map[TypeRef]TypeRef{TypeRef(k): TypeRef(v)})
	if err != nil {
		t.Fatal(err)
	}
	defer cf.Release(TypeRef(dict))
	if got, ok := cf.GetDictionaryString(dict, k); !ok || got != "world" {
		t.Fatalf("lookup = %q, %v", got, ok)
	}
}

func TestCFDict(t *testing.T) {
	cf, err := Get()
	if err != nil {
		t.Fatal(err)
	}

	k1 := cf.StringToCFString("k1")
	k2 := cf.StringToCFString("k2")

	v1 := cf.StringToCFString("xxxx")
	v2 := cf.StringToCFString("yyyy")

	keys := []unsafe.Pointer{TypeRef(k1).Ptr(), TypeRef(k2).Ptr()}
	values := []unsafe.Pointer{TypeRef(v1).Ptr(), TypeRef(v2).Ptr()}

	res := cf.DictionaryCreate(AllocatorDefault, &keys[0], &values[0], Index(2),
		*(**DictionaryKeyCallBacks)(unsafe.Pointer(&cf.TypeDictionaryKeyCallBacks)),
		*(**DictionaryValueCallBacks)(unsafe.Pointer(&cf.TypeDictionaryValueCallBacks)))

	if res == 0 {
		t.Fatal("CFDictionaryCreate returned null")
	}
	defer cf.Release(TypeRef(res))
	for _, ref := range []StringRef{k1, k2, v1, v2} {
		defer cf.Release(TypeRef(ref))
	}
	if count := cf.DictionaryGetCount(res); count != 2 {
		t.Fatalf("count = %d", count)
	}
}
