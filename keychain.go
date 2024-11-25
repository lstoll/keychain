//go:build darwin

package keychain

import (
	"fmt"
)

type Identity struct {
	ref _SecIdentityRef
}

func Identities() ([]*Identity, error) {
	query, err := mapToCFDictionary(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(kSecClass):      _CFTypeRef(kSecClassIdentity),
		_CFTypeRef(kSecReturnRef):  _CFTypeRef(kCFBooleanTrue),
		_CFTypeRef(kSecMatchLimit): _CFTypeRef(kSecMatchLimitAll),
	})
	if err != nil {
		return nil, fmt.Errorf("creating query: %w", err)
	}

	defer _CFRelease(_CFTypeRef(query))

	var res _CFTypeRef
	osstatus := _SecItemCopyMatching(query, &res)
	if err := secOSStatusErr(osstatus); err != nil {
		if err.Code == errSecItemNotFound {
			return nil, nil
		}
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
