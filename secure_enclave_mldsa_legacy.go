//go:build darwin && !go1.27

package keychain

import "crypto"

const stdlibMLDSAAvailable = false

func parseMLDSAPublicKey(SecureEnclaveAlgorithm, []byte) (crypto.PublicKey, error) {
	return nil, ErrUnsupportedAlgorithm
}
func mldsaSigningContext(crypto.SignerOpts) (string, error) { return "", ErrUnsupportedAlgorithm }
