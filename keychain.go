//go:build darwin

package keychain

import (
	"fmt"
	"unsafe"
)

type Identity struct {
	ref _SecIdentityRef
}

func Identities() ([]*Identity, error) {
	keys := []unsafe.Pointer{
		valOf(kSecClass),
		valOf(kSecReturnRef),
		valOf(kSecMatchLimit),
	}
	values := []unsafe.Pointer{
		valOf(kSecClassIdentity),
		valOf(kCFBooleanTrue),
		valOf(kSecMatchLimitAll),
	}
	query := _CFDictionaryCreate(kCFAllocatorDefault, &keys[0], &values[0], _CFIndex(len(keys)),
		tPtr[_CFDictionaryKeyCallBacks](kCFTypeDictionaryKeyCallBacks),
		tPtr[_CFDictionaryValueCallBacks](kCFTypeDictionaryValueCallBacks))
	if query == _CFDictionaryRef(0) {
		return nil, fmt.Errorf("creating query failed")
	}
	defer _CFRelease(_CFTypeRef(query))

	var res _CFTypeRef
	osstatus := _SecItemCopyMatching(query, &res)
	if err := secOSStatusErr(osstatus); err != nil {
		return nil, fmt.Errorf("error copying item from query: %w", err)
	}
	defer _CFRelease(res)

	n := _CFArrayGetCount(_CFArrayRef(res))
	idents := make([]_CFTypeRef, n)

	_CFArrayGetValues(_CFArrayRef(res), _CFRange{0, n}, ptrToPtr(&idents[0]))

	var ret []*Identity
	for _, i := range idents {
		ret = append(ret, &Identity{
			ref: _SecIdentityRef(i),
		})
	}

	return ret, nil
}
