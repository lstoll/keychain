//go:build darwin

package keychain

import (
	"fmt"
	"sync"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
)

// AuthContext is an LAContext used as kSecUseAuthenticationContext.
// Keep it alive for as long as it is passed to Keychain queries; Keychain owns
// the Touch ID / passcode UI when the item has AccessControl + userPresence.
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

// NewAuthContext allocates an LAContext. Callers should create one per process
// and reuse it for every secret read so Keychain can skip a second prompt.
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
// This reuses a recent Mac unlock with Touch ID, not a previous Keychain read.
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
