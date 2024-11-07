//go:build darwin

package keychain

import "testing"

func TestString(t *testing.T) {
	in := "hello world"
	cfs := stringToCFString(in)
	out := cfStringtoString(cfs)
	if out != in {
		t.Errorf("want %s, got: %s", in, out)
	}
}

func TestMap(t *testing.T) {
	dict, err := mapToCFDictionary(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(stringToCFString("hello")): _CFTypeRef(stringToCFString("world")),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = dict
}
