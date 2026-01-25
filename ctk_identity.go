//go:build darwin

package keychain

import (
	"encoding/hex"
	"fmt"
	"os/exec"
)

/* CTK identities created with: sc_auth create-ctk-identity -l <label> -k p-256-ne -t none */

// CTKCardTokenID is the token ID for CTK smart card identities created with
// sc_auth create-ctk-identity. These keys are stored in the Secure Enclave
// but accessed via the CryptoTokenKit card emulation layer.
const CTKCardTokenID = "com.apple.ctkcard:user"

// CTKKeyType represents the key algorithm for CTK identities.
type CTKKeyType string

const (
	// CTKKeyTypeP256 creates a P-256 (secp256r1) key in the Secure Enclave (non-extractable).
	CTKKeyTypeP256 CTKKeyType = "p-256-ne"
	// CTKKeyTypeP384 creates a P-384 (secp384r1) key in the Secure Enclave (non-extractable).
	CTKKeyTypeP384 CTKKeyType = "p-384-ne"
)

// CreateCTKIdentity creates a new CTK identity with the given label and key type.
// This shells out to sc_auth create-ctk-identity.
// Returns the created identity. Note: Multiple identities can have the same label.
func CreateCTKIdentity(label string, keyType CTKKeyType) (*Identity, error) {
	if label == "" {
		return nil, fmt.Errorf("label is required")
	}
	if keyType == "" {
		keyType = CTKKeyTypeP256
	}

	// Get existing identity hashes before creation
	beforeList, err := ListIdentities(IdentityQuery{Type: IdentityQueryTypeCTK})
	if err != nil {
		return nil, fmt.Errorf("listing identities before creation: %w", err)
	}
	existingHashes := make(map[string]bool)
	for _, id := range beforeList {
		if hash, err := id.PublicKeyHash(); err == nil && hash != nil {
			existingHashes[hex.EncodeToString(hash)] = true
		}
	}

	// Create the identity
	cmd := exec.Command("sc_auth", "create-ctk-identity", "-l", label, "-k", string(keyType), "-t", "none")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sc_auth create-ctk-identity failed: %w: %s", err, string(output))
	}

	// Get identities after creation and find the new one
	afterList, err := ListIdentities(IdentityQuery{Type: IdentityQueryTypeCTK})
	if err != nil {
		return nil, fmt.Errorf("listing identities after creation: %w", err)
	}

	for _, id := range afterList {
		hash, err := id.PublicKeyHash()
		if err != nil || hash == nil {
			continue
		}
		hashHex := hex.EncodeToString(hash)
		if !existingHashes[hashHex] && id.Label() == label {
			return id, nil
		}
	}

	return nil, fmt.Errorf("created identity but could not find it in keychain")
}

// DeleteCTKIdentity deletes a CTK identity by its public key hash.
// This shells out to sc_auth delete-ctk-identity.
func DeleteCTKIdentity(publicKeyHash []byte) error {
	if publicKeyHash == nil {
		return fmt.Errorf("publicKeyHash is required")
	}

	hashHex := hex.EncodeToString(publicKeyHash)
	cmd := exec.Command("sc_auth", "delete-ctk-identity", "-h", hashHex)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc_auth delete-ctk-identity failed: %w: %s", err, string(output))
	}

	return nil
}

// DeleteCTKIdentityByLabel deletes a CTK identity by its label.
// Returns an error if multiple identities have the same label.
func DeleteCTKIdentityByLabel(label string) error {
	identity, err := GetIdentity(IdentityQuery{Label: label, Type: IdentityQueryTypeCTK})
	if err != nil {
		return fmt.Errorf("finding identity to delete: %w", err)
	}

	hash, err := identity.PublicKeyHash()
	if err != nil {
		return fmt.Errorf("getting public key hash: %w", err)
	}
	return DeleteCTKIdentity(hash)
}
