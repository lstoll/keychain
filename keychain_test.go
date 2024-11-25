package keychain

import "testing"

func TestGetIdentities(t *testing.T) {
	identities, err := Identities()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("identities: %#v", identities)
}
