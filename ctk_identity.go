//go:build darwin

package keychain

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

type CreateCTKIdentityInput struct {
	Label      string
	KeyType    CTKKeyType
	CommonName string
}

// CreateCTKIdentity creates a new CTK identity with the given label and key
// type. This shells out to sc_auth create-ctk-identity and returns the created
// identity. Note: Multiple identities can have the same label.
func CreateCTKIdentity(input CreateCTKIdentityInput) (*Identity, error) {
	if input.Label == "" {
		return nil, fmt.Errorf("label is required")
	}
	if input.KeyType == "" {
		input.KeyType = CTKKeyTypeP256
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
	args := []string{
		"create-ctk-identity",
		"-l", input.Label,
		"-k", string(input.KeyType),
		"-t", "none",
	}
	if input.CommonName != "" {
		args = append(args, "-N", input.CommonName)
	}

	cmd := exec.Command("sc_auth", args...)
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
		if !existingHashes[hashHex] && id.Label() == input.Label {
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

type CreateCTKIdentityCSRInput struct {
	CommonName string
}

// CreateCTKIdentityCSR creates a CSR for a given CTK identity. This will return
// the PEM formatted CSR for this identity.
//
// This shells out to sc_auth create-ctk-csr.
func CreateCTKIdentityCSR(identity *Identity, input CreateCTKIdentityCSRInput) ([]byte, error) {
	if identity == nil {
		return nil, fmt.Errorf("identity is required")
	}

	hash, err := identity.PublicKeyHash()
	if err != nil {
		return nil, fmt.Errorf("getting public key hash: %w", err)
	}

	// Pattern has no extension: ctkcard appends ".csr" to the -f path.
	csrFile, err := tempFilename("csr-*")
	if err != nil {
		return nil, fmt.Errorf("getting temporary filename: %w", err)
	}

	args := []string{
		"create-ctk-csr",
		"-h", hex.EncodeToString(hash),
		"-f", csrFile,
	}
	if input.CommonName != "" {
		args = append(args, "-N", input.CommonName)
	}

	cmd := exec.Command("sc_auth", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sc_auth create-ctk-csr failed: %w: %s", err, string(output))
	}

	// ctkcard writes the CSR to -f path + ".csr" (see CryptoTokenKit ctkcard create-csr).
	csrOutPath := csrFile + ".csr"
	csrPEM, err := os.ReadFile(csrOutPath)
	if err != nil {
		return nil, fmt.Errorf("reading CSR file: %w: %s", err, strings.TrimSpace(string(output)))
	}
	_ = os.Remove(csrOutPath)

	return csrPEM, nil
}

// ImportCTKCertificate imports a certificate into the keychain. This must be
// issued from a CSR that was created for a CTK identity using [CreateCTKIdentityCSR].
//
// This shells out to sc_auth import-ctk-certificate.
func ImportCTKCertificate(certificate []byte) error {
	if certificate == nil {
		return fmt.Errorf("certificate is required")
	}

	certFile, err := tempFilename("certificate-*")
	if err != nil {
		return fmt.Errorf("getting temporary filename: %w", err)
	}

	if err := os.WriteFile(certFile, certificate, 0600); err != nil {
		return fmt.Errorf("writing certificate file: %w", err)
	}

	args := []string{
		"import-ctk-certificate",
		"-f", certFile,
	}
	cmd := exec.Command("sc_auth", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc_auth import-ctk-certificate failed: %w: %s", err, string(output))
	}
	_ = os.Remove(certFile)

	return nil
}

func tempFilename(pattern string) (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		panic(fmt.Sprintf("generating random bytes: %v", err))
	}
	hexPrefix := hex.EncodeToString(randomBytes)

	var name string
	if before, after, ok := strings.Cut(pattern, "*"); ok {
		name = before + hexPrefix + after
	} else {
		name = hexPrefix + pattern
	}

	tempDir := os.TempDir()
	return filepath.Join(tempDir, name), nil
}
