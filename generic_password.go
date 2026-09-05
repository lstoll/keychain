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
	// Synchronizable, if non-nil, sets kSecAttrSynchronizable. Queries must
	// set this true to see iCloud Keychain items.
	//
	// https://developer.apple.com/documentation/security/ksecattrsynchronizable
	Synchronizable *bool
	// UseDataProtectionKeychain, if non-nil, sets kSecUseDataProtectionKeychain.
	// Implied by Synchronizable; set it explicitly anyway.
	//
	// https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain
	UseDataProtectionKeychain *bool
	// AccessGroup is kSecAttrAccessGroup (typically TEAMID.bundleID).
	//
	// https://developer.apple.com/documentation/security/ksecattraccessgroup
	AccessGroup string
	// Accessible is kSecAttrAccessible. Do not set this when AccessControl is set.
	//
	// https://developer.apple.com/documentation/security/ksecattraccessible
	Accessible Accessible
	// AccessControl is kSecAttrAccessControl (Touch ID / passcode). Do not also
	// set Accessible or kSecAttrAccess (legacy ACL).
	AccessControl *AccessControl
}

func (g *GenericPassword) toAttributes(cf *coreFoundation, sec *securityFramework) (_CFDictionaryRef, error) {
	attrs := map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(sec.Class): _CFTypeRef(sec.ClassGenericPassword),
	}
	var owned []_CFTypeRef
	defer func() { releaseAll(cf, owned) }()

	if g.Account != "" {
		accountRef := cf.StringToCFString(g.Account)
		owned = append(owned, _CFTypeRef(accountRef))
		attrs[_CFTypeRef(sec.AttrAccount)] = _CFTypeRef(accountRef)
	}
	if g.Service != "" {
		serviceRef := cf.StringToCFString(g.Service)
		owned = append(owned, _CFTypeRef(serviceRef))
		attrs[_CFTypeRef(sec.AttrService)] = _CFTypeRef(serviceRef)
	}
	if g.Label != "" {
		labelRef := cf.StringToCFString(g.Label)
		owned = append(owned, _CFTypeRef(labelRef))
		attrs[_CFTypeRef(sec.AttrLabel)] = _CFTypeRef(labelRef)
	}
	if len(g.GenericAttributes) > 0 {
		genericRef := cf.BytesToCFData(g.GenericAttributes)
		owned = append(owned, _CFTypeRef(genericRef))
		attrs[_CFTypeRef(sec.AttrGeneric)] = _CFTypeRef(genericRef)
	}
	if len(g.Value) > 0 {
		valueRef := cf.BytesToCFData(g.Value)
		owned = append(owned, _CFTypeRef(valueRef))
		attrs[_CFTypeRef(sec.ValueData)] = _CFTypeRef(valueRef)
	}

	if err := putSharedItemAttrs(attrs, sharedItemAttrs{
		Synchronizable:            g.Synchronizable,
		UseDataProtectionKeychain: g.UseDataProtectionKeychain,
		AccessGroup:               g.AccessGroup,
		Accessible:                g.Accessible,
		AccessControl:             g.AccessControl,
	}, &owned, cf, sec); err != nil {
		return 0, err
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
	// Synchronizable, if non-nil, sets kSecAttrSynchronizable. Queries must
	// set this true to see iCloud Keychain items.
	Synchronizable *bool
	// SynchronizableAny, if true, matches both synchronizable and local items.
	// Mutually exclusive with Synchronizable.
	SynchronizableAny bool
	// UseDataProtectionKeychain, if non-nil, sets kSecUseDataProtectionKeychain.
	UseDataProtectionKeychain *bool
	// AccessGroup is kSecAttrAccessGroup.
	AccessGroup string
	// AuthenticationContext is kSecUseAuthenticationContext. Pass on secret
	// reads of userPresence items; do not pass on attributes-only queries.
	AuthenticationContext *AuthContext
	// OperationPrompt is kSecUseOperationPrompt.
	OperationPrompt string
}

func (g *GenericPasswordQuery) toQueryMap(addlAttrs map[_CFTypeRef]_CFTypeRef, cf *coreFoundation, sec *securityFramework) (_CFDictionaryRef, error) {
	query := map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(sec.Class): _CFTypeRef(sec.ClassGenericPassword),
	}
	var owned []_CFTypeRef
	defer func() { releaseAll(cf, owned) }()

	if g.Account != "" {
		accountRef := cf.StringToCFString(g.Account)
		owned = append(owned, _CFTypeRef(accountRef))
		query[_CFTypeRef(sec.AttrAccount)] = _CFTypeRef(accountRef)
	}

	if g.Service != "" {
		serviceRef := cf.StringToCFString(g.Service)
		owned = append(owned, _CFTypeRef(serviceRef))
		query[_CFTypeRef(sec.AttrService)] = _CFTypeRef(serviceRef)
	}

	if g.SynchronizableAny {
		if g.Synchronizable != nil {
			return 0, fmt.Errorf("cannot set both Synchronizable and SynchronizableAny")
		}
		query[_CFTypeRef(sec.AttrSynchronizable)] = _CFTypeRef(sec.AttrSynchronizableAny)
	}
	if err := putSharedItemAttrs(query, sharedItemAttrs{
		Synchronizable:            g.Synchronizable,
		UseDataProtectionKeychain: g.UseDataProtectionKeychain,
		AccessGroup:               g.AccessGroup,
	}, &owned, cf, sec); err != nil {
		return 0, err
	}
	if g.AuthenticationContext != nil {
		query[_CFTypeRef(sec.UseAuthenticationContext)] = _CFTypeRef(g.AuthenticationContext.id)
	}
	if g.OperationPrompt != "" {
		promptRef := cf.StringToCFString(g.OperationPrompt)
		owned = append(owned, _CFTypeRef(promptRef))
		query[_CFTypeRef(sec.UseOperationPrompt)] = _CFTypeRef(promptRef)
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
		return nil, fmt.Errorf("getting generic password: %w", err)
	}
	defer cf.Release(_CFTypeRef(r))

	return cf.BytesFromCFData(_CFDataRef(r)), nil
}

// UpdateGenericPasswordAttributes sets kSecAttrGeneric on the matching item.
// The secret (kSecValueData) is not modified.
func UpdateGenericPasswordAttributes(query GenericPasswordQuery, generic []byte) error {
	cf, err := getCoreFoundation()
	if err != nil {
		return err
	}
	sec, err := getSecurity()
	if err != nil {
		return err
	}
	if query.Service == "" && query.Account == "" {
		return fmt.Errorf("cannot update generic password without service or account")
	}

	q, err := query.toQueryMap(nil, cf, sec)
	if err != nil {
		return err
	}
	defer cf.Release(_CFTypeRef(q))

	genericRef := cf.BytesToCFData(generic)
	defer cf.Release(_CFTypeRef(genericRef))
	attrs, err := cf.MapToCFDictionary(map[_CFTypeRef]_CFTypeRef{
		_CFTypeRef(sec.AttrGeneric): _CFTypeRef(genericRef),
	})
	if err != nil {
		return err
	}
	defer cf.Release(_CFTypeRef(attrs))

	status := sec.ItemUpdate(q, attrs)
	if err := sec.newError(status); err != nil {
		return fmt.Errorf("updating generic password attributes: %w", err)
	}
	return nil
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

type sharedItemAttrs struct {
	Synchronizable            *bool
	UseDataProtectionKeychain *bool
	AccessGroup               string
	Accessible                Accessible
	AccessControl             *AccessControl
}

func putSharedItemAttrs(attrs map[_CFTypeRef]_CFTypeRef, a sharedItemAttrs, owned *[]_CFTypeRef, cf *coreFoundation, sec *securityFramework) error {
	putOptionalBool(attrs, sec.AttrSynchronizable, a.Synchronizable, cf)
	putOptionalBool(attrs, sec.UseDataProtectionKeychain, a.UseDataProtectionKeychain, cf)
	if a.AccessGroup != "" {
		ag := cf.StringToCFString(a.AccessGroup)
		*owned = append(*owned, _CFTypeRef(ag))
		attrs[_CFTypeRef(sec.AttrAccessGroup)] = _CFTypeRef(ag)
	}
	if a.AccessControl != nil && a.Accessible != AccessibleUnspecified {
		return fmt.Errorf("cannot set both Accessible and AccessControl")
	}
	if a.Accessible != AccessibleUnspecified {
		ref, err := sec.accessibleRef(a.Accessible)
		if err != nil {
			return err
		}
		attrs[_CFTypeRef(sec.AttrAccessible)] = _CFTypeRef(ref)
	}
	if a.AccessControl != nil {
		sac, err := sec.createAccessControl(cf, *a.AccessControl)
		if err != nil {
			return err
		}
		*owned = append(*owned, _CFTypeRef(sac))
		attrs[_CFTypeRef(sec.AttrAccessControl)] = _CFTypeRef(sac)
	}
	return nil
}

func releaseAll(cf *coreFoundation, refs []_CFTypeRef) {
	for _, r := range refs {
		cf.Release(r)
	}
}
