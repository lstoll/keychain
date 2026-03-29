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

		cert, err := id.Certificate()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("  certificate: %s", cert.Subject)

		chain, err := id.CertificateChain(nil)
		if err != nil {
			t.Logf("  CertificateChain: %v", err)
			continue
		}
		t.Logf("  chain: %d certificates", len(chain))
		for _, cert := range chain {
			t.Logf("    %s", cert.Subject)
		}
	}
}
