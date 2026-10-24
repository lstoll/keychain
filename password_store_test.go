//go:build darwin

package keychain

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestPasswordStoreValidation(t *testing.T) {
	for _, opts := range []PasswordStoreOptions{{}, {Service: "x", Backend: 42}, {Service: "x", Synchronizable: true}, {Service: "x", AccessGroup: "group"}, {Service: "x", AccessControl: AccessControl{Flags: AccessControlUserPresence}}, {Service: "\xff"}, {Service: "x", Backend: BackendDataProtection, Synchronizable: true, AccessControl: AccessControl{Protection: AccessibleWhenUnlockedThisDeviceOnly}}} {
		if _, err := NewPasswordStore(opts); err == nil {
			t.Fatalf("accepted %+v", opts)
		}
	}
	var s PasswordStore
	if _, err := s.Get(""); err == nil {
		t.Fatal("accepted zero store")
	}
}
func TestAccessibleThisDeviceOnly(t *testing.T) {
	for a, want := range map[Accessible]bool{
		AccessibleUnspecified:                    false,
		AccessibleWhenUnlocked:                   false,
		AccessibleAfterFirstUnlock:               false,
		AccessibleWhenUnlockedThisDeviceOnly:     true,
		AccessibleAfterFirstUnlockThisDeviceOnly: true,
		AccessibleWhenPasscodeSetThisDeviceOnly:  true,
	} {
		if got := a.thisDeviceOnly(); got != want {
			t.Errorf("%d: got %v want %v", a, got, want)
		}
	}
}

func TestPasswordStoreE2E(t *testing.T) {
	requireIntegration(t)
	s, err := NewPasswordStore(PasswordStoreOptions{Service: fmt.Sprintf("lds.li/keychain/test/%d", time.Now().UnixNano())})
	if err != nil {
		t.Fatal(err)
	}
	accounts := []string{"", "account", "other"}
	for _, a := range accounts {
		t.Cleanup(func() {
			if err := s.Delete(a); err != nil {
				t.Error(err)
			}
		})
	}
	list, err := s.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("empty list: %v %v", list, err)
	}
	for i, a := range accounts {
		if err := s.Create(a, []byte{byte(i)}, nil); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if err := s.Delete("with-attrs"); err != nil {
			t.Error(err)
		}
	})
	if err := s.Create("with-attrs", []byte("p"), &PasswordAttributes{Label: "created", GenericAttributes: []byte("generic")}); err != nil {
		t.Fatal(err)
	}
	if m, err := s.Metadata("with-attrs"); err != nil || m.Label != "created" || string(m.GenericAttributes) != "generic" {
		t.Fatalf("create attributes: %+v %v", m, err)
	}
	if err := s.Create("account", nil, nil); !errors.Is(err, ErrDuplicateItem) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := s.SetAttributes("", PasswordAttributes{Label: "label", GenericAttributes: []byte("metadata")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("", []byte{}); err != nil {
		t.Fatal(err)
	}
	for i, a := range accounts {
		got, err := s.Get(a)
		want := []byte{byte(i)}
		if i == 0 {
			want = []byte{}
		}
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("account %q got %x, %v", a, got, err)
		}
	}
	if err := s.Delete("account\x00suffix"); err == nil {
		t.Fatal("accepted NUL selector")
	}
	fresh, err := NewPasswordStore(PasswordStoreOptions{Service: s.options.Service})
	if err != nil {
		t.Fatal(err)
	}
	got, err := fresh.Get("account")
	if err != nil || !bytes.Equal(got, []byte{1}) {
		t.Fatalf("fresh store: %x %v", got, err)
	}
	other, err := NewPasswordStore(PasswordStoreOptions{Service: s.options.Service + "/other"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Get("account"); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("service scope: %v", err)
	}
	if err := s.SetAttributes("", PasswordAttributes{}); err != nil {
		t.Fatal(err)
	}
	cleared, err := s.Metadata("")
	if err != nil || cleared.Label != "" || len(cleared.GenericAttributes) != 0 {
		t.Fatalf("clear metadata: %+v %v", cleared, err)
	}
	if err := s.SetAttributes("", PasswordAttributes{Label: "label", GenericAttributes: []byte("metadata")}); err != nil {
		t.Fatal(err)
	}
	meta, err := s.Metadata("")
	if err != nil || meta.Label != "label" || string(meta.GenericAttributes) != "metadata" {
		t.Fatalf("metadata: %+v %v", meta, err)
	}
	list, err = s.List()
	if err != nil || len(list) != 4 {
		t.Fatalf("list: %v %v", list, err)
	}
	if err := s.Delete(""); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(""); !errors.Is(err, ErrItemNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if err := s.Set("", nil); err != nil {
		t.Fatal(err)
	}
}

func TestPasswordStoreDataProtection(t *testing.T) {
	requireIntegration(t)
	s, err := NewPasswordStore(PasswordStoreOptions{Service: fmt.Sprintf("lds.li/keychain/dp-test/%d", time.Now().UnixNano()), Backend: BackendDataProtection, AccessControl: AccessControl{Protection: AccessibleAfterFirstUnlockThisDeviceOnly}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create("account", []byte("password"), nil); err != nil {
		if errors.Is(err, ErrMissingEntitlement) {
			t.Skip("test binary lacks data protection keychain entitlements")
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Delete("account"); err != nil {
			t.Error(err)
		}
	})
	got, err := s.Get("account")
	if err != nil || string(got) != "password" {
		t.Fatalf("Get: %q %v", got, err)
	}
	if err := s.Set("account", nil); err != nil {
		t.Fatal(err)
	}
	got, err = s.Get("account")
	if err != nil || len(got) != 0 {
		t.Fatalf("empty Get: %x %v", got, err)
	}
}
