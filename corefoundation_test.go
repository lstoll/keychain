//go:build darwin

package keychain

import "testing"

func TestString(t *testing.T) {
	cf, err := getCoreFoundation()
	if err != nil {
		t.Fatal(err)
	}
	in := "hello world"
	cfs := cf.StringToCFString(in)
	out := cf.CFStringToString(cfs)
	if out != in {
		t.Errorf("want %s, got: %s", in, out)
	}
}

func TestMap(t *testing.T) {
	cf, err := getCoreFoundation()
	if err != nil {
		t.Fatal(err)
	}
	dict, err := cf.MapToCFDictionary(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(cf.StringToCFString("hello")): _CFTypeRef(cf.StringToCFString("world")),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = dict
}
