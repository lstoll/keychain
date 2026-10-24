//go:build darwin && go1.27

package keychain

import (
	"crypto"
	"crypto/mldsa"
	"fmt"
)

const stdlibMLDSAAvailable = true

func parseMLDSAPublicKey(algorithm SecureEnclaveAlgorithm, data []byte) (crypto.PublicKey, error) {
	params := mldsa.MLDSA65()
	if algorithm == SecureEnclaveMLDSA87 {
		params = mldsa.MLDSA87()
	}
	return mldsa.NewPublicKey(params, data)
}
func mldsaSigningContext(opts crypto.SignerOpts) (string, error) {
	if opts == nil {
		return "", nil
	}
	if opts.HashFunc() != 0 {
		return "", fmt.Errorf("ML-DSA requires the original message, not a digest or external mu")
	}
	if opts, ok := opts.(*mldsa.Options); ok && opts != nil {
		if len(opts.Context) > 255 {
			return "", fmt.Errorf("ML-DSA context exceeds 255 bytes")
		}
		return opts.Context, nil
	}
	return "", nil
}
