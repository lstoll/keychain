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
