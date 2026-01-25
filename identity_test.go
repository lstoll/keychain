//go:build darwin

package keychain

import "testing"

func TestListIdentities(t *testing.T) {
	identities, err := ListIdentities(IdentityQuery{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("found %d identities", len(identities))
	for _, id := range identities {
		t.Logf("  %s (%s)", id.Label(), id.Type())
	}
}
