//go:build darwin

package keychain

import (
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

// AuthPolicy is an LAPolicy value.
//
// https://developer.apple.com/documentation/localauthentication/lapolicy
type AuthPolicy int64

const (
	// AuthPolicyDeviceOwnerAuthentication is LAPolicyDeviceOwnerAuthentication
	// (Touch ID, with device passcode fallback).
	AuthPolicyDeviceOwnerAuthentication AuthPolicy = 2
)

const (
	laErrorAuthenticationFailed int64 = -1
	laErrorUserCancel           int64 = -2
	laErrorSystemCancel         int64 = -4
	laErrorAppCancel            int64 = -9
	laErrorNotInteractive       int64 = -1004
)

// AuthContext is an LAContext. Use EvaluatePolicy for an app-level presence
// prompt, or pass it as kSecUseAuthenticationContext when the item itself has
// AccessControl + userPresence.
//
// https://developer.apple.com/documentation/localauthentication/lacontext
type AuthContext struct {
	id objc.ID
}

var (
	selAlloc            = objc.RegisterName("alloc")
	selInit             = objc.RegisterName("init")
	selSetReason        = objc.RegisterName("setLocalizedReason:")
	selSetTouchIDReuse  = objc.RegisterName("setTouchIDAuthenticationAllowableReuseDuration:")
	selEvaluatePolicy   = objc.RegisterName("evaluatePolicy:localizedReason:reply:")
	selCode             = objc.RegisterName("code")
	selLocalizedDesc    = objc.RegisterName("localizedDescription")
	selUTF8String       = objc.RegisterName("UTF8String")
	laOnce              sync.Once
	laErr               error
	laClass             objc.Class
	maxTouchIDReuseSecs float64
)

func initLocalAuthentication() error {
	laOnce.Do(func() {
		handle, err := dlopen("/System/Library/Frameworks/LocalAuthentication.framework/LocalAuthentication", purego.RTLD_LAZY|purego.RTLD_GLOBAL)
		if err != nil {
			laErr = err
			return
		}
		laClass = objc.GetClass("LAContext")
		if laClass == 0 {
			laErr = fmt.Errorf("LAContext class not found")
			return
		}
		ptr, err := purego.Dlsym(handle, "LATouchIDAuthenticationMaximumAllowableReuseDuration")
		if err == nil && ptr != 0 {
			maxTouchIDReuseSecs = *tPtr[float64](ptr)
		}
		if maxTouchIDReuseSecs == 0 {
			maxTouchIDReuseSecs = 300 // documented maximum: 5 minutes
		}
	})
	return laErr
}

// NewAuthContext allocates an LAContext. Reuse one per process so a successful
// EvaluatePolicy is not repeated, and so Keychain can skip a second ACL prompt.
func NewAuthContext() (*AuthContext, error) {
	if err := initLocalAuthentication(); err != nil {
		return nil, err
	}
	id := objc.ID(laClass).Send(selAlloc)
	if id == 0 {
		return nil, fmt.Errorf("LAContext alloc failed")
	}
	id = id.Send(selInit)
	if id == 0 {
		return nil, fmt.Errorf("LAContext init failed")
	}
	return &AuthContext{id: id}, nil
}

// SetLocalizedReason sets the prompt shown if Keychain needs user presence.
func (c *AuthContext) SetLocalizedReason(reason string) error {
	if c == nil || c.id == 0 {
		return fmt.Errorf("nil AuthContext")
	}
	cf, err := getCoreFoundation()
	if err != nil {
		return err
	}
	s := cf.StringToCFString(reason)
	defer cf.Release(_CFTypeRef(s))
	objc.Send[objc.ID](c.id, selSetReason, objc.ID(s))
	return nil
}

// SetTouchIDReuseDuration sets touchIDAuthenticationAllowableReuseDuration.
// This reuses a recent Mac unlock with Touch ID, not a previous evaluation.
func (c *AuthContext) SetTouchIDReuseDuration(seconds float64) error {
	if c == nil || c.id == 0 {
		return fmt.Errorf("nil AuthContext")
	}
	objc.Send[struct{}](c.id, selSetTouchIDReuse, seconds)
	return nil
}

// SetMaximumTouchIDReuseDuration sets the duration to
// LATouchIDAuthenticationMaximumAllowableReuseDuration (5 minutes).
func (c *AuthContext) SetMaximumTouchIDReuseDuration() error {
	if err := initLocalAuthentication(); err != nil {
		return err
	}
	return c.SetTouchIDReuseDuration(maxTouchIDReuseSecs)
}

// MaximumTouchIDReuseDuration returns LATouchIDAuthenticationMaximumAllowableReuseDuration.
func MaximumTouchIDReuseDuration() (float64, error) {
	if err := initLocalAuthentication(); err != nil {
		return 0, err
	}
	return maxTouchIDReuseSecs, nil
}

// EvaluatePolicy runs LAContext evaluatePolicy:localizedReason:reply: and
// waits for the reply. Policy DeviceOwnerAuthentication is Touch ID with
// passcode fallback.
func (c *AuthContext) EvaluatePolicy(policy AuthPolicy, reason string) error {
	if c == nil || c.id == 0 {
		return fmt.Errorf("nil AuthContext")
	}
	if reason == "" {
		return fmt.Errorf("EvaluatePolicy requires a localized reason")
	}
	cf, err := getCoreFoundation()
	if err != nil {
		return err
	}
	s := cf.StringToCFString(reason)
	defer cf.Release(_CFTypeRef(s))

	done := make(chan error, 1)
	block := objc.NewBlock(func(_ objc.Block, success uint8, nsErr objc.ID) {
		if success != 0 {
			done <- nil
			return
		}
		done <- laReplyError(nsErr)
	})
	defer block.Release()

	objc.Send[struct{}](c.id, selEvaluatePolicy, int64(policy), objc.ID(s), block)
	return <-done
}

func laReplyError(nsErr objc.ID) error {
	if nsErr == 0 {
		return &Error{code: ErrorCodeAuthFailed, message: "LocalAuthentication failed"}
	}
	code := objc.Send[int64](nsErr, selCode)
	msg := "LocalAuthentication failed"
	if desc := objc.Send[objc.ID](nsErr, selLocalizedDesc); desc != 0 {
		if utf8 := objc.Send[string](desc, selUTF8String); utf8 != "" {
			msg = utf8
		}
	}
	errCode := ErrorCodeUnknown
	switch code {
	case laErrorAuthenticationFailed:
		errCode = ErrorCodeAuthFailed
	case laErrorUserCancel, laErrorSystemCancel, laErrorAppCancel:
		errCode = ErrorCodeUserCanceled
	case laErrorNotInteractive:
		errCode = ErrorCodeInteractionNotAllowed
	}
	return &Error{code: errCode, message: msg}
}
