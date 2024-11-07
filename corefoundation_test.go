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
