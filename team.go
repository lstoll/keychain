//go:build darwin

package keychain

import "fmt"

// TeamIdentifier returns the Apple Team ID from the running binary's code
// signature. Data-protection / iCloud Keychain access groups are TEAMID.bundleID;
// an unsigned or ad-hoc-signed binary has no Team ID.
func TeamIdentifier() (string, error) {
	cf, err := getCoreFoundation()
	if err != nil {
		return "", err
	}
	sec, err := getSecurity()
	if err != nil {
		return "", err
	}

	var code _SecCodeRef
	status := sec.CodeCopySelf(kSecCSDefaultFlags, &code)
	if err := sec.newError(status); err != nil {
		return "", fmt.Errorf("SecCodeCopySelf: %w", err)
	}
	defer cf.Release(_CFTypeRef(code))

	var info _CFDictionaryRef
	status = sec.CodeCopySigningInformation(_SecStaticCodeRef(code), kSecCSSigningInformation, &info)
	if err := sec.newError(status); err != nil {
		return "", fmt.Errorf("SecCodeCopySigningInformation: %w", err)
	}
	defer cf.Release(_CFTypeRef(info))

	team, ok := cf.GetDictionaryString(info, sec.CodeInfoTeamIdentifier)
	if !ok || team == "" {
		return "", fmt.Errorf("binary is not signed with an Apple Team ID")
	}
	return team, nil
}
