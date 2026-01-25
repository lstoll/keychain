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

func (g *GenericPassword) toAttributes(cf *coreFoundation, sec *securityFramework) (_CFDictionaryRef, error) {
	attrs := map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(sec.Class): _CFTypeRef(sec.ClassGenericPassword),
	}

	if g.Account != "" {
		accountRef := cf.StringToCFString(g.Account)
		defer cf.Release(_CFTypeRef(accountRef))
		attrs[_CFTypeRef(sec.AttrAccount)] = _CFTypeRef(accountRef)
	}
	if g.Service != "" {
		serviceRef := cf.StringToCFString(g.Service)
		defer cf.Release(_CFTypeRef(serviceRef))
		attrs[_CFTypeRef(sec.AttrService)] = _CFTypeRef(serviceRef)
	}
	if g.Label != "" {
		labelRef := cf.StringToCFString(g.Label)
		defer cf.Release(_CFTypeRef(labelRef))
		attrs[_CFTypeRef(sec.AttrLabel)] = _CFTypeRef(labelRef)
	}
	if len(g.GenericAttributes) > 0 {
		genericRef := cf.BytesToCFData(g.GenericAttributes)
		defer cf.Release(_CFTypeRef(genericRef))
		attrs[_CFTypeRef(sec.AttrGeneric)] = _CFTypeRef(genericRef)
	}
	if len(g.Value) > 0 {
		valueRef := cf.BytesToCFData(g.Value)
		defer cf.Release(_CFTypeRef(valueRef))
		attrs[_CFTypeRef(sec.ValueData)] = _CFTypeRef(valueRef)
	}

	return cf.MapToCFDictionary(attrs)
}

func newGenericPasswordFromResult(result _CFDictionaryRef, cf *coreFoundation, sec *securityFramework) (GenericPassword, error) {
	gpa := GenericPassword{}
	if account, ok := cf.GetDictionaryString(result, sec.AttrAccount); ok {
		gpa.Account = account
	}
	if service, ok := cf.GetDictionaryString(result, sec.AttrService); ok {
		gpa.Service = service
	}
	if label, ok := cf.GetDictionaryString(result, sec.AttrLabel); ok {
		gpa.Label = label
	}
	if generic, ok := cf.GetDictionaryData(result, sec.AttrGeneric); ok {
		gpa.GenericAttributes = generic
	}
	if value, ok := cf.GetDictionaryData(result, sec.ValueData); ok {
		gpa.Value = value
	}

	return gpa, nil
}

func CreateGenericPassword(args GenericPassword) error {
	cf, err := getCoreFoundation()
	if err != nil {
		return err
	}
	sec, err := getSecurity()
	if err != nil {
		return err
	}

	attrs, err := args.toAttributes(cf, sec)
	if err != nil {
		return err
	}
	defer cf.Release(_CFTypeRef(attrs))

	status := sec.ItemAdd(attrs, nil)
	if err := sec.newError(status); err != nil {
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

func (g *GenericPasswordQuery) toQueryMap(addlAttrs map[_CFTypeRef]_CFTypeRef, cf *coreFoundation, sec *securityFramework) (_CFDictionaryRef, error) {
	query := map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(sec.Class): _CFTypeRef(sec.ClassGenericPassword),
	}

	if g.Account != "" {
		accountRef := cf.StringToCFString(g.Account)
		defer cf.Release(_CFTypeRef(accountRef))
		query[_CFTypeRef(sec.AttrAccount)] = _CFTypeRef(accountRef)
	}

	if g.Service != "" {
		serviceRef := cf.StringToCFString(g.Service)
		defer cf.Release(_CFTypeRef(serviceRef))
		query[_CFTypeRef(sec.AttrService)] = _CFTypeRef(serviceRef)
	}

	maps.Copy(query, addlAttrs)

	return cf.MapToCFDictionary(query)
}

func GetGenericPasswordAttributes(query GenericPasswordQuery) (GenericPassword, error) {
	cf, err := getCoreFoundation()
	if err != nil {
		return GenericPassword{}, err
	}
	sec, err := getSecurity()
	if err != nil {
		return GenericPassword{}, err
	}

	q, err := query.toQueryMap(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(sec.ReturnAttributes): _CFTypeRef(cf.BooleanTrue),
		_CFTypeRef(sec.MatchLimit):       _CFTypeRef(sec.MatchLimitOne),
	}, cf, sec)
	if err != nil {
		return GenericPassword{}, err
	}
	defer cf.Release(_CFTypeRef(q))

	var r _CFTypeRef
	status := sec.ItemCopyMatching(q, &r)
	if err := sec.newError(status); err != nil {
		return GenericPassword{}, fmt.Errorf("getting generic password attributes: %w", err)
	}
	defer cf.Release(_CFTypeRef(r))

	return newGenericPasswordFromResult(_CFDictionaryRef(r), cf, sec)
}

func GetGenericPassword(query GenericPasswordQuery) ([]byte, error) {
	cf, err := getCoreFoundation()
	if err != nil {
		return nil, err
	}
	sec, err := getSecurity()
	if err != nil {
		return nil, err
	}

	q, err := query.toQueryMap(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(sec.ReturnData): _CFTypeRef(cf.BooleanTrue),
		_CFTypeRef(sec.MatchLimit): _CFTypeRef(sec.MatchLimitOne),
	}, cf, sec)
	if err != nil {
		return nil, err
	}
	defer cf.Release(_CFTypeRef(q))

	var r _CFTypeRef
	status := sec.ItemCopyMatching(q, &r)
	if err := sec.newError(status); err != nil {
		return nil, fmt.Errorf("getting generic password attributes: %w", err)
	}
	defer cf.Release(_CFTypeRef(r))

	return cf.BytesFromCFData(_CFDataRef(r)), nil
}

func ListGenericPasswords(query GenericPasswordQuery) ([]GenericPassword, error) {
	cf, err := getCoreFoundation()
	if err != nil {
		return nil, err
	}
	sec, err := getSecurity()
	if err != nil {
		return nil, err
	}

	q, err := query.toQueryMap(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(sec.ReturnAttributes): _CFTypeRef(cf.BooleanTrue),
		_CFTypeRef(sec.MatchLimit):       _CFTypeRef(sec.MatchLimitAll),
	}, cf, sec)
	if err != nil {
		return nil, err
	}
	defer cf.Release(_CFTypeRef(q))

	var r _CFTypeRef
	status := sec.ItemCopyMatching(q, &r)
	if err := sec.newError(status); err != nil {
		return nil, fmt.Errorf("listing generic passwords: %w", err)
	}
	defer cf.Release(_CFTypeRef(r))

	result := cf.GoSliceFromCFArray(_CFArrayRef(r))

	passwords := make([]GenericPassword, len(result))
	for i, r := range result {
		var err error
		passwords[i], err = newGenericPasswordFromResult(_CFDictionaryRef(r), cf, sec)
		if err != nil {
			return nil, fmt.Errorf("listing generic passwords: %w", err)
		}
	}

	return passwords, nil
}

// DeleteGenericPassword deletes all items from the keychain that match the
// query.
func DeleteGenericPassword(query GenericPasswordQuery) error {
	cf, err := getCoreFoundation()
	if err != nil {
		return err
	}
	sec, err := getSecurity()
	if err != nil {
		return err
	}

	if query.Service == "" && query.Account == "" {
		return fmt.Errorf("cannot delete generic password without service or account")
	}

	q, err := query.toQueryMap(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(sec.MatchLimit): _CFTypeRef(sec.MatchLimitAll),
	}, cf, sec)
	if err != nil {
		return err
	}
	defer cf.Release(_CFTypeRef(q))

	status := sec.ItemDelete(q)
	if err := sec.newError(status); err != nil {
		return fmt.Errorf("deleting generic password: %w", err)
	}

	return nil
}
