//go:build darwin

package keychain

import (
	"fmt"
	"maps"
)

// GenericPassword are the values for creating or updating a generic
// password keychain entry.
//
// https://developer.apple.com/documentation/security/ksecclassgenericpassword?language=objc
type GenericPassword struct {
	// Account name of this item. This is part of the primary key.
	//
	// https://developer.apple.com/documentation/security/ksecattraccount?language=objc
	Account string
	// Service name of this item. This is part of the primary key.
	//
	// https://developer.apple.com/documentation/security/ksecattrservice?language=objc
	Service string
	// Label is the user facing label of this item.
	//
	// https://developer.apple.com/documentation/security/ksecattrlabel?language=objc
	Label string
	// Value is the password to store in the keychain. This is only used on
	// creation, it will not be returned on list or lookups.
	//
	// https://developer.apple.com/documentation/security/ksecvaluedata?language=objc
	Value []byte
	// GenericAttributes are the items user-defined attributes.
	//
	// https://developer.apple.com/documentation/security/ksecattrgeneric?language=objc
	GenericAttributes []byte
}

func (g *GenericPassword) toAttributes() (_CFDictionaryRef, error) {
	attrs := map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(kSecClass): _CFTypeRef(kSecClassGenericPassword),
	}

	if g.Account != "" {
		accountRef := stringToCFString(g.Account)
		defer _CFRelease(_CFTypeRef(accountRef))
		attrs[_CFTypeRef(kSecAttrAccount)] = _CFTypeRef(accountRef)
	}
	if g.Service != "" {
		serviceRef := stringToCFString(g.Service)
		defer _CFRelease(_CFTypeRef(serviceRef))
		attrs[_CFTypeRef(kSecAttrService)] = _CFTypeRef(serviceRef)
	}
	if g.Label != "" {
		labelRef := stringToCFString(g.Label)
		defer _CFRelease(_CFTypeRef(labelRef))
		attrs[_CFTypeRef(kSecAttrLabel)] = _CFTypeRef(labelRef)
	}
	if len(g.GenericAttributes) > 0 {
		genericRef := bytesToCFData(g.GenericAttributes)
		defer _CFRelease(_CFTypeRef(genericRef))
		attrs[_CFTypeRef(kSecAttrGeneric)] = _CFTypeRef(genericRef)
	}
	if len(g.Value) > 0 {
		valueRef := bytesToCFData(g.Value)
		defer _CFRelease(_CFTypeRef(valueRef))
		attrs[_CFTypeRef(kSecValueData)] = _CFTypeRef(valueRef)
	}

	return mapToCFDictionary(attrs)
}

func newGenericPasswordFromResult(result map[_CFTypeRef]_CFTypeRef) (GenericPassword, error) {
	gpa := GenericPassword{}
	if account, ok := getStringAttr(result, kSecAttrAccount); ok {
		gpa.Account = account
	}
	if service, ok := getStringAttr(result, kSecAttrService); ok {
		gpa.Service = service
	}
	if label, ok := getStringAttr(result, kSecAttrLabel); ok {
		gpa.Label = label
	}
	if generic, ok := getDataAttr(result, kSecAttrGeneric); ok {
		gpa.GenericAttributes = generic
	}
	if value, ok := getDataAttr(result, kSecValueData); ok {
		gpa.Value = value
	}

	return gpa, nil
}

func CreateGenericPassword(args GenericPassword) error {
	attrs, err := args.toAttributes()
	if err != nil {
		return err
	}
	defer _CFRelease(_CFTypeRef(attrs))

	status := _SecItemAdd(attrs, nil)
	if err := secOSStatusErr(status); err != nil {
		return fmt.Errorf("creating generic password: %w", err)
	}

	return nil
}

type GenericPasswordQuery struct {
	// Account name of this item. This is part of the primary key.
	//
	// https://developer.apple.com/documentation/security/ksecattraccount?language=objc
	Account string
	// Service name of this item. This is part of the primary key.
	//
	// https://developer.apple.com/documentation/security/ksecattrservice?language=objc
	Service string
}

func (g *GenericPasswordQuery) toQueryMap(addlAttrs map[_CFTypeRef]_CFTypeRef) (_CFDictionaryRef, error) {
	query := map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(kSecClass): _CFTypeRef(kSecClassGenericPassword),
	}

	if g.Account != "" {
		accountRef := stringToCFString(g.Account)
		defer _CFRelease(_CFTypeRef(accountRef))
		query[_CFTypeRef(kSecAttrAccount)] = _CFTypeRef(accountRef)
	}

	if g.Service != "" {
		serviceRef := stringToCFString(g.Service)
		defer _CFRelease(_CFTypeRef(serviceRef))
		query[_CFTypeRef(kSecAttrService)] = _CFTypeRef(serviceRef)
	}

	maps.Copy(query, addlAttrs)

	return mapToCFDictionary(query)
}

func GetGenericPasswordAttributes(query GenericPasswordQuery) (GenericPassword, error) {
	q, err := query.toQueryMap(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(kSecReturnAttributes): _CFTypeRef(kCFBooleanTrue),
		_CFTypeRef(kSecMatchLimit):       _CFTypeRef(kSecMatchLimitOne),
	})
	if err != nil {
		return GenericPassword{}, err
	}
	defer _CFRelease(_CFTypeRef(q))

	var r _CFTypeRef
	status := _SecItemCopyMatching(q, &r)
	if err := secOSStatusErr(status); err != nil {
		return GenericPassword{}, fmt.Errorf("getting generic password attributes: %w", err)
	}
	defer _CFRelease(_CFTypeRef(r))

	result := mapFromCFDictionary(_CFDictionaryRef(r))

	return newGenericPasswordFromResult(result)
}

func GetGenericPassword(query GenericPasswordQuery) ([]byte, error) {
	q, err := query.toQueryMap(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(kSecReturnData): _CFTypeRef(kCFBooleanTrue),
		_CFTypeRef(kSecMatchLimit): _CFTypeRef(kSecMatchLimitOne),
	})
	if err != nil {
		return nil, err
	}
	defer _CFRelease(_CFTypeRef(q))

	var r _CFTypeRef
	status := _SecItemCopyMatching(q, &r)
	if err := secOSStatusErr(status); err != nil {
		return nil, fmt.Errorf("getting generic password attributes: %w", err)
	}
	defer _CFRelease(_CFTypeRef(r))

	return bytesFromCFData(_CFDataRef(r)), nil
}

func ListGenericPasswords(query GenericPasswordQuery) ([]GenericPassword, error) {
	q, err := query.toQueryMap(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(kSecReturnAttributes): _CFTypeRef(kCFBooleanTrue),
		_CFTypeRef(kSecMatchLimit):       _CFTypeRef(kSecMatchLimitAll),
	})
	if err != nil {
		return nil, err
	}
	defer _CFRelease(_CFTypeRef(q))

	var r _CFTypeRef
	status := _SecItemCopyMatching(q, &r)
	if err := secOSStatusErr(status); err != nil {
		return nil, fmt.Errorf("listing generic passwords: %w", err)
	}
	defer _CFRelease(_CFTypeRef(r))

	// result can be a single item if only one matches?
	// But we asked for All. Usually it returns Array even if one.
	// But check type just in case or rely on MatchLimitAll behavior.
	// The C API documentation says it returns an array for MatchLimitAll.

	result := goSliceFromCFArray(_CFArrayRef(r))

	passwords := make([]GenericPassword, len(result))
	for i, r := range result {
		var err error
		passwords[i], err = newGenericPasswordFromResult(mapFromCFDictionary(_CFDictionaryRef(r)))
		if err != nil {
			return nil, fmt.Errorf("listing generic passwords: %w", err)
		}
	}

	return passwords, nil
}

// DeleteGenericPassword deletes all items from the keychain that match the
// query.
func DeleteGenericPassword(query GenericPasswordQuery) error {
	if query.Service == "" && query.Account == "" {
		return fmt.Errorf("cannot delete generic password without service or account")
	}

	q, err := query.toQueryMap(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(kSecMatchLimit): _CFTypeRef(kSecMatchLimitAll),
	})
	if err != nil {
		return err
	}
	defer _CFRelease(_CFTypeRef(q))

	status := _SecItemDelete(q)
	if err := secOSStatusErr(status); err != nil {
		return fmt.Errorf("deleting generic password: %w", err)
	}

	return nil
}
