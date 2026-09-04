//go:build darwin

package keychain

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

const testService = "li.lds.oauth2ext.keychain.test"

func TestKeychainE2E(t *testing.T) {
	if os.Getenv("TEST_KEYCHAIN") != "1" {
		t.Skip("TEST_KEYCHAIN is not set")
	}

	account := "test"

	// clean up any existing items. Run this before to ensure a clean slate, and
	// after to not leave stuff lying around.
	cleanup := func() {
		if err := DeleteGenericPassword(GenericPasswordQuery{
			Service: testService,
		}); err != nil {
			var kcErr *Error
			if !errors.As(err, &kcErr) || kcErr.Code() != ErrorCodeItemNotFound {
				t.Fatalf("deleteKeychainPassword failed: %v", err)
			}
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	password := []byte("test")

	createArgs := GenericPassword{
		Account: account,
		Service: testService,
		Label:   "test-label",
		Value:   password,
	}

	if err := CreateGenericPassword(createArgs); err != nil {
		t.Fatalf("CreateGenericPassword failed: %v", err)
	}

	attrs, err := GetGenericPasswordAttributes(GenericPasswordQuery{
		Account: account,
		Service: testService,
	})
	if err != nil {
		t.Fatalf("GetGenericPasswordAttributes failed: %v", err)
	}

	if attrs.Account != account {
		t.Fatalf("account mismatch: want %s, got %s", account, attrs.Account)
	}
	if attrs.Service != testService {
		t.Fatalf("service mismatch: want %s, got %s", testService, attrs.Service)
	}
	if len(attrs.Value) > 0 {
		t.Fatalf("value should be empty, got %s", attrs.Value)
	}

	gotPassword, err := GetGenericPassword(GenericPasswordQuery{
		Account: account,
		Service: testService,
	})
	if err != nil {
		t.Fatalf("getKeychainPassword failed: %v", err)
	}

	if !bytes.Equal(password, gotPassword) {
		t.Fatalf("password mismatch: want %s, got %s", string(password), string(gotPassword))
	}

	// re-try, to ensure it fails how we'd expect
	if err := CreateGenericPassword(createArgs); err != nil {
		var kcErr *Error
		if !errors.As(err, &kcErr) || kcErr.Code() != ErrorCodeDuplicateItem {
			t.Fatalf("CreateGenericPassword should have failed with duplicate item: %v", err)
		}
	}

	// Create a second one, to verify list works.
	if err := CreateGenericPassword(GenericPassword{
		Account: "second-account",
		Service: testService,
		Value:   []byte("second-password"),
	}); err != nil {
		var kcErr *Error
		if !errors.As(err, &kcErr) || kcErr.Code() != ErrorCodeDuplicateItem {
			t.Fatalf("CreateGenericPassword should have failed with duplicate item: %v", err)
		}
	}

	list, err := ListGenericPasswords(GenericPasswordQuery{
		Service: testService,
	})
	if err != nil {
		t.Fatalf("ListGenericPasswords failed: %v", err)
	}

	t.Logf("list: %#v", list)

	if len(list) != 2 {
		t.Fatalf("ListGenericPasswords should have returned 2 items, got %d", len(list))
	}

	if err := DeleteGenericPassword(GenericPasswordQuery{
		Account: account,
		Service: testService,
	}); err != nil {
		t.Fatalf("deleteKeychainPassword failed: %v", err)
	}
}

func TestAccessibleAndAccessControlMutuallyExclusive(t *testing.T) {
	err := CreateGenericPassword(GenericPassword{
		Account:    "x",
		Service:    testService,
		Value:      []byte("x"),
		Accessible: AccessibleAfterFirstUnlock,
		AccessControl: &AccessControl{
			Protection: AccessibleWhenUnlocked,
			Flags:      AccessControlUserPresence,
		},
	})
	if err == nil {
		t.Fatal("expected error when both Accessible and AccessControl are set")
	}
}

func TestAuthContext(t *testing.T) {
	ctx, err := NewAuthContext()
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.SetLocalizedReason("keychain test"); err != nil {
		t.Fatal(err)
	}
	if err := ctx.SetMaximumTouchIDReuseDuration(); err != nil {
		t.Fatal(err)
	}
	d, err := MaximumTouchIDReuseDuration()
	if err != nil {
		t.Fatal(err)
	}
	if d <= 0 {
		t.Fatalf("expected positive reuse duration, got %v", d)
	}
	t.Logf("LATouchIDAuthenticationMaximumAllowableReuseDuration=%v", d)
}

func TestTeamIdentifier(t *testing.T) {
	team, err := TeamIdentifier()
	if err != nil {
		t.Logf("TeamIdentifier (unsigned/ad-hoc is expected): %v", err)
		return
	}
	if team == "" {
		t.Fatal("empty Team ID")
	}
	t.Logf("TeamIdentifier=%s", team)
}

func TestKeychainDataProtectionSync(t *testing.T) {
	if os.Getenv("TEST_KEYCHAIN") != "1" {
		t.Skip("TEST_KEYCHAIN is not set")
	}

	const service = "li.lds.keychain.test.sync"
	account := "sync-test"
	cleanup := func() {
		q := GenericPasswordQuery{Service: service, Synchronizable: Bool(true), UseDataProtectionKeychain: Bool(true)}
		if team, err := TeamIdentifier(); err == nil {
			q.AccessGroup = team + ".li.lds.keychain"
		}
		if err := DeleteGenericPassword(q); err != nil {
			var kcErr *Error
			if !errors.As(err, &kcErr) || kcErr.Code() != ErrorCodeItemNotFound {
				t.Logf("cleanup delete: %v", err)
			}
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	item := GenericPassword{
		Account:                   account,
		Service:                   service,
		Label:                     "keychain sync test",
		Value:                     []byte("sync-secret"),
		GenericAttributes:         []byte("public-attr"),
		Synchronizable:            Bool(true),
		UseDataProtectionKeychain: Bool(true),
		Accessible:                AccessibleAfterFirstUnlock,
	}
	if team, err := TeamIdentifier(); err == nil {
		item.AccessGroup = team + ".li.lds.keychain"
	}

	if err := CreateGenericPassword(item); err != nil {
		var kcErr *Error
		if errors.As(err, &kcErr) && kcErr.Code() == ErrorCodeMissingEntitlement {
			t.Skipf("data-protection keychain requires a signed binary: %v", err)
		}
		t.Fatalf("CreateGenericPassword: %v", err)
	}

	q := GenericPasswordQuery{
		Account:                   account,
		Service:                   service,
		Synchronizable:            Bool(true),
		UseDataProtectionKeychain: Bool(true),
		AccessGroup:               item.AccessGroup,
	}
	attrs, err := GetGenericPasswordAttributes(q)
	if err != nil {
		t.Fatalf("GetGenericPasswordAttributes: %v", err)
	}
	if attrs.Account != account {
		t.Fatalf("account: got %q", attrs.Account)
	}
	if string(attrs.GenericAttributes) != "public-attr" {
		t.Fatalf("generic: got %q", attrs.GenericAttributes)
	}
	if len(attrs.Value) > 0 {
		t.Fatalf("attributes-only read returned secret")
	}

	got, err := GetGenericPassword(q)
	if err != nil {
		t.Fatalf("GetGenericPassword: %v", err)
	}
	if string(got) != "sync-secret" {
		t.Fatalf("secret: got %q", got)
	}
}

func TestKeychainUserPresenceSync(t *testing.T) {
	if os.Getenv("TEST_KEYCHAIN_USERPRESENCE") != "1" {
		t.Skip("TEST_KEYCHAIN_USERPRESENCE is not set")
	}

	const service = "li.lds.keychain.test.userpresence"
	account := "up-test"
	cleanup := func() {
		q := GenericPasswordQuery{Service: service, Synchronizable: Bool(true), UseDataProtectionKeychain: Bool(true)}
		if err := DeleteGenericPassword(q); err != nil {
			var kcErr *Error
			if !errors.As(err, &kcErr) || kcErr.Code() != ErrorCodeItemNotFound {
				t.Logf("cleanup delete: %v", err)
			}
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	item := GenericPassword{
		Account:                   account,
		Service:                   service,
		Label:                     "keychain userPresence sync test",
		Value:                     []byte("up-secret"),
		Synchronizable:            Bool(true),
		UseDataProtectionKeychain: Bool(true),
		AccessControl: &AccessControl{
			Protection: AccessibleWhenUnlocked,
			Flags:      AccessControlUserPresence,
		},
	}
	if err := CreateGenericPassword(item); err != nil {
		var kcErr *Error
		if errors.As(err, &kcErr) && kcErr.Code() == ErrorCodeParam {
			t.Skip("iCloud Keychain rejects synchronizable + userPresence (errSecParam)")
		}
		t.Fatalf("SecItemAdd synchronizable+userPresence: %v", err)
	}
	t.Log("SecItemAdd of synchronizable + userPresence succeeded")

	ctx, err := NewAuthContext()
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.SetLocalizedReason("keychain userPresence test"); err != nil {
		t.Fatal(err)
	}
	if err := ctx.SetMaximumTouchIDReuseDuration(); err != nil {
		t.Fatal(err)
	}

	got, err := GetGenericPassword(GenericPasswordQuery{
		Account:                   account,
		Service:                   service,
		Synchronizable:            Bool(true),
		UseDataProtectionKeychain: Bool(true),
		AuthenticationContext:     ctx,
	})
	if err != nil {
		t.Fatalf("GetGenericPassword: %v", err)
	}
	if string(got) != "up-secret" {
		t.Fatalf("secret: got %q", got)
	}
}
