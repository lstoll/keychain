//go:build darwin

package corefoundation

import (
	"testing"
)

func TestStringLengthsAndValidation(t *testing.T) {
	f, err := Get()
	if err != nil {
		t.Fatal(err)
	}
	input := "before\x00after 🐈"
	ref, err := f.CreateString(input)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Release(TypeRef(ref))
	if got := f.CFStringToString(ref); got != input {
		t.Fatalf("round trip = %q, want %q", got, input)
	}
	if _, err := f.CreateString(string([]byte{0xff})); err == nil {
		t.Fatal("accepted invalid UTF-8")
	}
	if f.StringToCFString(string([]byte{0xff})) != 0 {
		t.Fatal("unchecked helper accepted invalid UTF-8")
	}
}

func TestEmptyDictionaryAndNumber(t *testing.T) {
	f, err := Get()
	if err != nil {
		t.Fatal(err)
	}
	dict, err := f.MapToCFDictionary(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Release(TypeRef(dict))
	if count := f.DictionaryGetCount(dict); count != 0 {
		t.Fatalf("empty dictionary count = %d", count)
	}
	number := f.NumberFromInt(1<<40 + 7)
	if number == 0 {
		t.Fatal("CFNumberCreate returned null")
	}
	defer f.Release(TypeRef(number))
	got, ok := f.Int64FromNumber(number)
	if !ok || got != 1<<40+7 {
		t.Fatalf("number = %d, %v", got, ok)
	}
}

func TestCreateStringReportsNativeFailure(t *testing.T) {
	f := &Framework{StringCreateWithBytes: func(AllocatorRef, *byte, Index, StringEncoding, bool) StringRef { return 0 }}
	if _, err := f.CreateString("valid"); err == nil {
		t.Fatal("CreateString succeeded when CFStringCreateWithBytes returned null")
	}
}
