//go:build darwin

package keychain

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unicode/utf8"

	"lds.li/keychain/internal/corefoundation"
	"lds.li/keychain/internal/security"
)

// Backend selects the keychain implementation used by a password store.
type Backend int

const (
	// BackendFile uses the default file-based keychain and works without access-group entitlements.
	BackendFile Backend = iota
	// BackendDataProtection uses the entitlement-controlled data protection keychain.
	BackendDataProtection
)

// PasswordStoreOptions fixes the scope and creation policy for a store.
type PasswordStoreOptions struct {
	// Service scopes the store (kSecAttrService). Required.
	Service string
	// Backend selects the file or data protection keychain. The default is the file keychain.
	Backend Backend
	// Synchronizable syncs items through iCloud Keychain. Data protection backend only.
	Synchronizable bool
	// AccessGroup restricts data protection items to one access group.
	// When empty, lookups match any group the binary is entitled to.
	AccessGroup string
	// AccessControl applies to newly created data protection items. Zero protection defaults to WhenUnlocked.
	AccessControl AccessControl
	// AuthContext is shared by all operations to reuse authentication and prompt text.
	AuthContext *AuthContext
}

// PasswordStore stores passwords under one service, backend, and synchronization scope.
// Its zero value is unusable. AuthContext, if supplied, is shared by its operations.
type PasswordStore struct {
	options PasswordStoreOptions
	cf      *corefoundation.Framework
	sec     *security.Framework
}

// NewPasswordStore validates and fixes the store scope. It does not create a keychain item.
// Service and account names must be valid UTF-8 without NUL characters.
func NewPasswordStore(options PasswordStoreOptions) (*PasswordStore, error) {
	if options.Service == "" {
		return nil, fmt.Errorf("password store service is required")
	}
	for _, s := range []string{options.Service, options.AccessGroup} {
		if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
			return nil, fmt.Errorf("password store strings must be valid UTF-8 without NUL characters")
		}
	}
	switch options.Backend {
	case BackendFile:
		if options.Synchronizable || options.AccessGroup != "" || options.AccessControl != (AccessControl{}) {
			return nil, fmt.Errorf("synchronization, access groups, and protection classes require the data protection backend")
		}
	case BackendDataProtection:
		if options.AccessControl.Protection == AccessibleUnspecified {
			options.AccessControl.Protection = AccessibleWhenUnlocked
		}
		if options.Synchronizable && (options.AccessControl.Protection.thisDeviceOnly() || options.AccessControl.Flags != 0) {
			return nil, fmt.Errorf("synchronizable passwords require a migratable protection class without authentication constraints")
		}
	default:
		return nil, fmt.Errorf("unknown keychain backend %d", options.Backend)
	}
	if options.AuthContext != nil && options.AuthContext.id == 0 {
		return nil, fmt.Errorf("uninitialized authentication context")
	}
	cf, err := corefoundation.Get()
	if err != nil {
		return nil, err
	}
	sec, err := security.Get()
	if err != nil {
		return nil, err
	}
	if options.Backend == BackendDataProtection {
		if _, err := accessibleRef(sec, options.AccessControl.Protection); err != nil {
			return nil, err
		}
	}
	return &PasswordStore{options: options, cf: cf, sec: sec}, nil
}

// PasswordAttributes contains caller-controlled metadata, separate from the secret.
type PasswordAttributes struct {
	Label             string
	GenericAttributes []byte
}

// PasswordMetadata describes an account in the store. It never contains a password.
type PasswordMetadata struct {
	Account string
	PasswordAttributes
}

func (s *PasswordStore) dictionary(account *string, extra map[corefoundation.TypeRef]corefoundation.TypeRef, creation bool) (corefoundation.DictionaryRef, error) {
	if s == nil || s.cf == nil || s.sec == nil {
		return 0, fmt.Errorf("uninitialized password store")
	}
	cf, sec := s.cf, s.sec
	attrs := map[corefoundation.TypeRef]corefoundation.TypeRef{corefoundation.TypeRef(sec.Class): corefoundation.TypeRef(sec.ClassGenericPassword)}
	var owned []corefoundation.TypeRef
	putString := func(key corefoundation.StringRef, value string) error {
		ref, err := cf.CreateString(value)
		if err != nil {
			return err
		}
		owned = append(owned, corefoundation.TypeRef(ref))
		attrs[corefoundation.TypeRef(key)] = corefoundation.TypeRef(ref)
		return nil
	}
	defer func() { releaseAll(cf, owned) }()
	if err := putString(sec.AttrService, s.options.Service); err != nil {
		return 0, err
	}
	if account != nil {
		if strings.ContainsRune(*account, 0) {
			return 0, fmt.Errorf("password account must not contain NUL characters")
		}
		if err := putString(sec.AttrAccount, *account); err != nil {
			return 0, err
		}
	}
	backend := s.options.Backend == BackendDataProtection
	putBool(attrs, sec.UseDataProtectionKeychain, backend, cf)
	if backend {
		putBool(attrs, sec.AttrSynchronizable, s.options.Synchronizable, cf)
	}
	if s.options.AccessGroup != "" {
		if err := putString(sec.AttrAccessGroup, s.options.AccessGroup); err != nil {
			return 0, err
		}
	}
	if s.options.AuthContext != nil {
		attrs[corefoundation.TypeRef(sec.UseAuthenticationContext)] = corefoundation.TypeRef(s.options.AuthContext.id)
	}
	if creation && backend {
		ac := s.options.AccessControl
		if ac.Flags == 0 {
			ref, err := accessibleRef(sec, ac.Protection)
			if err != nil {
				return 0, err
			}
			attrs[corefoundation.TypeRef(sec.AttrAccessible)] = corefoundation.TypeRef(ref)
		} else {
			ref, err := createAccessControl(sec, ac)
			if err != nil {
				return 0, err
			}
			owned = append(owned, corefoundation.TypeRef(ref))
			attrs[corefoundation.TypeRef(sec.AttrAccessControl)] = corefoundation.TypeRef(ref)
		}
	}
	for k, v := range extra {
		attrs[k] = v
	}
	return cf.MapToCFDictionary(attrs)
}
func releaseAll(cf *corefoundation.Framework, refs []corefoundation.TypeRef) {
	for _, r := range refs {
		cf.Release(r)
	}
}

// Create adds a password or returns ErrDuplicateItem if the account exists.
// Accounts and passwords may be empty. Non-nil attributes are stored with the
// item; nil leaves the label and generic data unset.
func (s *PasswordStore) Create(account string, password []byte, attributes *PasswordAttributes) error {
	if s == nil || s.cf == nil {
		return fmt.Errorf("uninitialized password store")
	}
	defer runtime.KeepAlive(s.options.AuthContext)
	data := s.cf.BytesToCFData(password)
	if data == 0 {
		return fmt.Errorf("creating password data")
	}
	defer s.cf.Release(corefoundation.TypeRef(data))
	extra := map[corefoundation.TypeRef]corefoundation.TypeRef{corefoundation.TypeRef(s.sec.ValueData): corefoundation.TypeRef(data)}
	if attributes != nil {
		label, err := s.cf.CreateString(attributes.Label)
		if err != nil {
			return err
		}
		defer s.cf.Release(corefoundation.TypeRef(label))
		generic := s.cf.BytesToCFData(attributes.GenericAttributes)
		if generic == 0 {
			return fmt.Errorf("creating keychain data")
		}
		defer s.cf.Release(corefoundation.TypeRef(generic))
		extra[corefoundation.TypeRef(s.sec.AttrLabel)] = corefoundation.TypeRef(label)
		extra[corefoundation.TypeRef(s.sec.AttrGeneric)] = corefoundation.TypeRef(generic)
	}
	q, err := s.dictionary(&account, extra, true)
	if err != nil {
		return err
	}
	defer s.cf.Release(corefoundation.TypeRef(q))
	return newError(s.sec, s.sec.ItemAdd(q, nil))
}

// Set creates or replaces one account's password. Existing metadata and access rules are
// preserved; a missing account is created without attributes (use Create to set them).
func (s *PasswordStore) Set(account string, password []byte) error {
	err := s.update(account, PasswordAttributes{}, password, false)
	if !errors.Is(err, ErrItemNotFound) {
		return err
	}
	err = s.Create(account, password, nil)
	if errors.Is(err, ErrDuplicateItem) {
		return s.update(account, PasswordAttributes{}, password, false)
	}
	return err
}
func (s *PasswordStore) update(account string, metadata PasswordAttributes, password []byte, attributes bool) error {
	// The legacy SecItem bridge turns zero-length data into NULL (meaning unchanged).
	// Use a retained exact item reference and the legacy API's nonnil empty buffer.
	if s != nil && s.cf != nil && s.sec != nil && !attributes && len(password) == 0 && s.options.Backend == BackendFile {
		q, err := s.dictionary(&account, map[corefoundation.TypeRef]corefoundation.TypeRef{corefoundation.TypeRef(s.sec.ReturnRef): corefoundation.TypeRef(s.cf.BooleanTrue), corefoundation.TypeRef(s.sec.MatchLimit): corefoundation.TypeRef(s.sec.MatchLimitOne)}, false)
		if err != nil {
			return err
		}
		defer s.cf.Release(corefoundation.TypeRef(q))
		defer runtime.KeepAlive(s.options.AuthContext)
		var item corefoundation.TypeRef
		err = newError(s.sec, s.sec.ItemCopyMatching(q, &item))
		if item != 0 {
			defer s.cf.Release(item)
		}
		if err != nil {
			return err
		}
		return normalizeNativeError(s.sec.UpdateFileKeychainPassword(security.SecKeychainItemRef(item), password))
	}
	q, err := s.dictionary(&account, nil, false)
	if err != nil {
		return err
	}
	defer s.cf.Release(corefoundation.TypeRef(q))
	defer runtime.KeepAlive(s.options.AuthContext)
	attrs := map[corefoundation.TypeRef]corefoundation.TypeRef{}
	var owned []corefoundation.TypeRef
	defer func() { releaseAll(s.cf, owned) }()
	if attributes {
		label, err := s.cf.CreateString(metadata.Label)
		if err != nil {
			return err
		}
		owned = append(owned, corefoundation.TypeRef(label))
		attrs[corefoundation.TypeRef(s.sec.AttrLabel)] = corefoundation.TypeRef(label)
		data := s.cf.BytesToCFData(metadata.GenericAttributes)
		if data == 0 {
			return fmt.Errorf("creating keychain data")
		}
		owned = append(owned, corefoundation.TypeRef(data))
		attrs[corefoundation.TypeRef(s.sec.AttrGeneric)] = corefoundation.TypeRef(data)
	} else {
		data := s.cf.BytesToCFData(password)
		if data == 0 {
			return fmt.Errorf("creating keychain data")
		}
		owned = append(owned, corefoundation.TypeRef(data))
		attrs[corefoundation.TypeRef(s.sec.ValueData)] = corefoundation.TypeRef(data)
	}
	changes, err := s.cf.MapToCFDictionary(attrs)
	if err != nil {
		return err
	}
	defer s.cf.Release(corefoundation.TypeRef(changes))
	return newError(s.sec, s.sec.ItemUpdate(q, changes))
}

// SetAttributes replaces the label and generic metadata without changing the password or access rules.
func (s *PasswordStore) SetAttributes(account string, attributes PasswordAttributes) error {
	return s.update(account, attributes, nil, true)
}
func (s *PasswordStore) lookup(account *string, data, all bool) (corefoundation.TypeRef, error) {
	if s == nil || s.sec == nil {
		return 0, fmt.Errorf("uninitialized password store")
	}
	key := s.sec.ReturnAttributes
	if data {
		key = s.sec.ReturnData
	}
	limit := s.sec.MatchLimitOne
	if all {
		limit = s.sec.MatchLimitAll
	}
	q, err := s.dictionary(account, map[corefoundation.TypeRef]corefoundation.TypeRef{corefoundation.TypeRef(key): corefoundation.TypeRef(s.cf.BooleanTrue), corefoundation.TypeRef(s.sec.MatchLimit): corefoundation.TypeRef(limit)}, false)
	if err != nil {
		return 0, err
	}
	defer s.cf.Release(corefoundation.TypeRef(q))
	defer runtime.KeepAlive(s.options.AuthContext)
	var result corefoundation.TypeRef
	err = newError(s.sec, s.sec.ItemCopyMatching(q, &result))
	if err != nil {
		if result != 0 {
			s.cf.Release(result)
		}
		return 0, err
	}
	return result, nil
}

// Get returns the password for exactly one account, or ErrItemNotFound.
func (s *PasswordStore) Get(account string) ([]byte, error) {
	r, err := s.lookup(&account, true, false)
	if err != nil {
		return nil, err
	}
	defer s.cf.Release(r)
	return s.cf.BytesFromCFData(corefoundation.DataRef(r)), nil
}
func (s *PasswordStore) metadata(r corefoundation.DictionaryRef) PasswordMetadata {
	account, _ := s.cf.GetDictionaryString(r, s.sec.AttrAccount)
	label, _ := s.cf.GetDictionaryString(r, s.sec.AttrLabel)
	generic, _ := s.cf.GetDictionaryData(r, s.sec.AttrGeneric)
	return PasswordMetadata{Account: account, PasswordAttributes: PasswordAttributes{Label: label, GenericAttributes: generic}}
}

// Metadata reads account metadata without requesting its secret.
func (s *PasswordStore) Metadata(account string) (PasswordMetadata, error) {
	r, err := s.lookup(&account, false, false)
	if err != nil {
		return PasswordMetadata{}, err
	}
	defer s.cf.Release(r)
	return s.metadata(corefoundation.DictionaryRef(r)), nil
}

// List returns metadata for all accounts in this store. An empty store returns an empty slice.
func (s *PasswordStore) List() ([]PasswordMetadata, error) {
	r, err := s.lookup(nil, false, true)
	if errors.Is(err, ErrItemNotFound) {
		return []PasswordMetadata{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer s.cf.Release(r)
	items := s.cf.GoSliceFromCFArray(corefoundation.ArrayRef(r))
	out := make([]PasswordMetadata, len(items))
	for i, item := range items {
		out[i] = s.metadata(corefoundation.DictionaryRef(item))
	}
	return out, nil
}

// Delete removes exactly one account. Deleting a missing account succeeds.
func (s *PasswordStore) Delete(account string) error {
	q, err := s.dictionary(&account, nil, false)
	if err != nil {
		return err
	}
	defer s.cf.Release(corefoundation.TypeRef(q))
	defer runtime.KeepAlive(s.options.AuthContext)
	err = newError(s.sec, s.sec.ItemDelete(q))
	if errors.Is(err, ErrItemNotFound) {
		return nil
	}
	return err
}
