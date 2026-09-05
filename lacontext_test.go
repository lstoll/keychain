//go:build darwin

package keychain

import (
	"os"
	"testing"
)

func TestEvaluatePolicyRequiresReason(t *testing.T) {
	ctx, err := NewAuthContext()
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.EvaluatePolicy(AuthPolicyDeviceOwnerAuthentication, ""); err == nil {
		t.Fatal("expected error for empty reason")
	}
}

func TestEvaluatePolicyDeviceOwnerAuthentication(t *testing.T) {
	if os.Getenv("TEST_KEYCHAIN_USERPRESENCE") != "1" {
		t.Skip("TEST_KEYCHAIN_USERPRESENCE is not set")
	}
	ctx, err := NewAuthContext()
	if err != nil {
		t.Fatal(err)
	}
	if err := ctx.SetMaximumTouchIDReuseDuration(); err != nil {
		t.Fatal(err)
	}
	if err := ctx.EvaluatePolicy(AuthPolicyDeviceOwnerAuthentication, "keychain EvaluatePolicy test"); err != nil {
		t.Fatal(err)
	}
}
