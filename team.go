//go:build darwin

package keychain

import (
	"fmt"

	"lds.li/keychain/internal/corefoundation"
	"lds.li/keychain/internal/security"
)

// TeamIdentifier returns the Apple Team ID from the running binary's code
// signature. Data-protection / iCloud Keychain access groups are TEAMID.bundleID;
// an unsigned or ad-hoc-signed binary has no Team ID.
func TeamIdentifier() (string, error) {
	cf, err := corefoundation.Get()
	if err != nil {
		return "", err
	}
	sec, err := security.Get()
	if err != nil {
		return "", err
	}

	var code security.SecCodeRef
	status := sec.CodeCopySelf(security.SecCSDefaultFlags, &code)
	if err := newError(sec, status); err != nil {
		return "", fmt.Errorf("SecCodeCopySelf: %w", err)
	}
	defer cf.Release(corefoundation.TypeRef(code))

	var info corefoundation.DictionaryRef
	status = sec.CodeCopySigningInformation(security.SecStaticCodeRef(code), security.SecCSSigningInformation, &info)
	if err := newError(sec, status); err != nil {
		return "", fmt.Errorf("SecCodeCopySigningInformation: %w", err)
	}
	defer cf.Release(corefoundation.TypeRef(info))

	team, ok := cf.GetDictionaryString(info, sec.CodeInfoTeamIdentifier)
	if !ok || team == "" {
		return "", fmt.Errorf("binary is not signed with an Apple Team ID")
	}
	return team, nil
}
