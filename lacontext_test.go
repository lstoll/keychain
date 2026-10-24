//go:build darwin

package keychain

import (
	"runtime"
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
	requireInteractive(t)
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

func TestAuthContext(t *testing.T) {
	ctx, err := NewAuthContext()
	if err != nil {
		t.Fatal(err)
	}
	copied := *ctx
	ctx = nil //nolint:ineffassign // drop the reference so the GC can run its finalizer
	runtime.GC()
	ctx = &copied
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
