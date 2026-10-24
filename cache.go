//go:build darwin

package keychain

import (
	"bytes"
	"errors"
	"fmt"

	"lds.li/keychain/internal/corefoundation"
	"lds.li/keychain/internal/security"
)

// Cache stores replaceable secrets in the file keychain. Entries with a
// different identity are deleted and treated as misses without reading their
// secrets, avoiding access prompts after a rebuild or executable rename.
//
// Use a dedicated service: Cache treats every item in it as a cache entry. Get
// and Put delete an item under their key that has a different identity, and
// Clear deletes every item in the service, including ones Cache did not write
// and ones from differently named executables.
type Cache struct {
	store    *PasswordStore
	identity []byte
}

// CacheOptions configures a Cache.
type CacheOptions struct {
	// Service scopes the cache. Required; use a dedicated service.
	Service string
	// Identity overrides the binding identity. Defaults to BinaryIdentity(). A
	// stable value preserves hits across builds, but does not change the
	// keychain's access rules - reading an older entry may still prompt.
	Identity string
}

// CacheEntry describes a cache entry belonging to this identity.
type CacheEntry struct {
	Key, Label string
}

// NewCache validates the options and resolves the binding identity.
func NewCache(opts CacheOptions) (*Cache, error) {
	store, err := NewPasswordStore(PasswordStoreOptions{Service: opts.Service})
	if err != nil {
		return nil, err
	}
	id := opts.Identity
	if id == "" {
		id, err = BinaryIdentity()
		if err != nil {
			return nil, fmt.Errorf("getting binary identity: %w", err)
		}
	}
	if id == "" {
		return nil, fmt.Errorf("cache identity is empty")
	}
	return &Cache{store: store, identity: []byte(id)}, nil
}

// Get returns the value for key. Missing entries, and entries written under a
// different identity (which are removed), report ok=false. The secret of a
// mismatched entry is never read.
func (c *Cache) Get(key string) (value []byte, ok bool, err error) {
	e, err := c.find(key)
	if e == nil || err != nil {
		return nil, false, err
	}
	defer c.store.cf.Release(e.ref)
	if !bytes.Equal(e.identity, c.identity) {
		if err := c.deleteRef(e.ref); err != nil && !errors.Is(err, errReplaced) {
			return nil, false, err
		}
		return nil, false, nil
	}
	// Read through the checked item, so a concurrent replacement is a miss
	// rather than a read of another binary's item.
	value, err = c.readRef(e.ref)
	if errors.Is(err, errReplaced) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

// Put stores value under key, replacing any existing entry. An empty label
// defaults to key.
func (c *Cache) Put(key string, value []byte, label string) error {
	if label == "" {
		label = key
	}
	attrs := &PasswordAttributes{Label: label, GenericAttributes: c.identity}
	var err error
	for range 2 {
		if err = c.remove(key); err != nil {
			return err
		}
		// Retry once if a concurrent writer created the item in between.
		if err = c.store.Create(key, value, attrs); !errors.Is(err, ErrDuplicateItem) {
			return err
		}
	}
	return err
}

// Delete removes key. Deleting a missing entry succeeds.
func (c *Cache) Delete(key string) error {
	return c.remove(key)
}

// List returns this identity's entries without reading any secrets.
func (c *Cache) List() ([]CacheEntry, error) {
	items, err := c.store.List()
	if err != nil {
		return nil, err
	}
	out := []CacheEntry{}
	for _, it := range items {
		if bytes.Equal(it.GenericAttributes, c.identity) {
			out = append(out, CacheEntry{Key: it.Account, Label: it.Label})
		}
	}
	return out, nil
}

// Clear deletes every item in the service: entries of any identity, and any
// other items stored there, even ones created by other applications.
func (c *Cache) Clear() error {
	items, err := c.store.List()
	if err != nil {
		return err
	}
	var errs []error
	for _, it := range items {
		if err := c.remove(it.Account); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// errReplaced reports that the item a ref names was deleted or replaced since
// it was looked up.
var errReplaced = errors.New("cache entry was replaced concurrently")

// errSecInvalidRecord is returned when deleting through a ref whose item no
// longer exists.
const errSecInvalidRecord = -67701

type cacheItem struct {
	ref      corefoundation.TypeRef
	identity []byte
}

// find looks up key's item and its identity in one query. It returns nil if
// there is no item. The caller releases ref. A ref names one specific item: reads and deletes through
// it fail, rather than reaching a replacement, if the item is replaced.
func (c *Cache) find(key string) (*cacheItem, error) {
	s := c.store
	q, err := s.dictionary(&key, map[corefoundation.TypeRef]corefoundation.TypeRef{
		corefoundation.TypeRef(s.sec.ReturnRef):        corefoundation.TypeRef(s.cf.BooleanTrue),
		corefoundation.TypeRef(s.sec.ReturnAttributes): corefoundation.TypeRef(s.cf.BooleanTrue),
		corefoundation.TypeRef(s.sec.MatchLimit):       corefoundation.TypeRef(s.sec.MatchLimitOne),
	}, false)
	if err != nil {
		return nil, err
	}
	defer s.cf.Release(corefoundation.TypeRef(q))
	var r corefoundation.TypeRef
	err = newError(s.sec, s.sec.ItemCopyMatching(q, &r))
	if r != 0 {
		defer s.cf.Release(r)
	}
	if errors.Is(err, ErrItemNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	id, _ := s.cf.GetDictionaryData(corefoundation.DictionaryRef(r), s.sec.AttrGeneric)
	ref := s.cf.GetDictionaryValue(corefoundation.DictionaryRef(r), s.sec.ValueRef)
	if ref == 0 {
		return nil, fmt.Errorf("keychain returned no item reference for %q", key)
	}
	s.cf.Retain(ref)
	return &cacheItem{ref: ref, identity: id}, nil
}

// readRef reads the secret of the item ref names.
func (c *Cache) readRef(ref corefoundation.TypeRef) ([]byte, error) {
	s := c.store
	q, err := s.cf.MapToCFDictionary(map[corefoundation.TypeRef]corefoundation.TypeRef{
		corefoundation.TypeRef(s.sec.Class):                     corefoundation.TypeRef(s.sec.ClassGenericPassword),
		corefoundation.TypeRef(s.sec.ValueRef):                  ref,
		corefoundation.TypeRef(s.sec.ReturnData):                corefoundation.TypeRef(s.cf.BooleanTrue),
		corefoundation.TypeRef(s.sec.UseDataProtectionKeychain): corefoundation.TypeRef(s.cf.BooleanFalse),
	})
	if err != nil {
		return nil, err
	}
	defer s.cf.Release(corefoundation.TypeRef(q))
	var r corefoundation.TypeRef
	err = newError(s.sec, s.sec.ItemCopyMatching(q, &r))
	if r != 0 {
		defer s.cf.Release(r)
	}
	if errors.Is(err, ErrItemNotFound) {
		return nil, errReplaced
	}
	if err != nil {
		return nil, err
	}
	return s.cf.BytesFromCFData(corefoundation.DataRef(r)), nil
}

// deleteRef deletes the item ref names with SecKeychainItemDelete. Unlike
// SecItemDelete, this does not refuse items created by a differently named
// executable (see security.Framework.DeleteFileKeychainItem).
func (c *Cache) deleteRef(ref corefoundation.TypeRef) error {
	err := normalizeNativeError(c.store.sec.DeleteFileKeychainItem(security.SecKeychainItemRef(ref)))
	var e *Error
	if errors.Is(err, ErrItemNotFound) || errors.As(err, &e) && e.Status() == errSecInvalidRecord {
		return errReplaced
	}
	return err
}

// remove deletes key's cache entry, whichever binary wrote it. If the entry is
// replaced while deleting, the replacement is removed too.
func (c *Cache) remove(key string) error {
	for range 3 {
		e, err := c.find(key)
		if e == nil || err != nil {
			return err
		}
		err = c.deleteRef(e.ref)
		c.store.cf.Release(e.ref)
		if !errors.Is(err, errReplaced) {
			return err
		}
	}
	return fmt.Errorf("removing %q: %w", key, errReplaced)
}
