//go:build darwin

package keychain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"unsafe"

	"lds.li/keychain/internal/corefoundation"
	"lds.li/keychain/internal/security"
)

var preferredCDHashes = []codeSignatureHash{
	codeSignatureHashSHA256,
	codeSignatureHashSHA256Truncated,
	codeSignatureHashSHA384,
	codeSignatureHashSHA512,
	codeSignatureHashSHA1,
}

// BinaryIdentity identifies the current executable for Cache. It uses a code
// directory hash for signed binaries, or the executable's SHA-256 otherwise.
// The identity changes when the binary changes.
func BinaryIdentity() (string, error) {
	cdHashes, err := getSelfCDHashes()
	if err == nil {
		for _, hash := range preferredCDHashes {
			if cdHash, ok := cdHashes[hash]; ok {
				return cdHash, nil
			}
		}
	}

	// Fall back to hashing the executable if signing information is unavailable.
	return hashExecutableFile()
}

// hashExecutableFile calculates the SHA-256 hash of the current executable file.
func hashExecutableFile() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("os.Executable: %w", err)
	}

	f, err := os.Open(execPath)
	if err != nil {
		return "", fmt.Errorf("os.Open: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("io.Copy: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

type codeSignatureHash string

const (
	codeSignatureHashSHA1            codeSignatureHash = "sha1"
	codeSignatureHashSHA256          codeSignatureHash = "sha256"
	codeSignatureHashSHA256Truncated codeSignatureHash = "sha256_truncated"
	codeSignatureHashSHA384          codeSignatureHash = "sha384"
	codeSignatureHashSHA512          codeSignatureHash = "sha512"
)

// getSelfCDHashes retrieves a map of all Code Directory Hashes (CDHashes) for
// the running binary, keyed by their digest algorithm type.
func getSelfCDHashes() (map[codeSignatureHash]string, error) {
	cf, err := corefoundation.Get()
	if err != nil {
		return nil, err
	}
	sec, err := security.Get()
	if err != nil {
		return nil, err
	}

	// Get a reference to the static code of the currently running process.
	var myselfCode security.SecCodeRef
	status := sec.CodeCopySelf(security.SecCSDefaultFlags, &myselfCode)
	if err := newError(sec, status); err != nil {
		return nil, fmt.Errorf("failed to get SecCodeRef for self: %w", err)
	}
	defer cf.Release(corefoundation.TypeRef(myselfCode))

	// Validate the code signature first, to see if we're signed and it's valid.
	// If not, we can fallback later.
	status = sec.CodeCheckValidity(myselfCode, security.SecCSDefaultFlags, 0)
	if err := newError(sec, status); err != nil {
		return nil, err
	}

	// Get the code signing information dictionary.
	var signingInfo corefoundation.DictionaryRef
	// SecStaticCodeRef is same as SecCodeRef in structure (ptr), just stricter type in C.
	status = sec.CodeCopySigningInformation(security.SecStaticCodeRef(myselfCode), security.SecCSDefaultFlags, &signingInfo)
	if err := newError(sec, status); err != nil {
		return nil, fmt.Errorf("failed to copy signing information: %w", err)
	}
	defer cf.Release(corefoundation.TypeRef(signingInfo))

	hashesPtr := cf.GetDictionaryValue(signingInfo, sec.CodeInfoCdHashes)
	algsPtr := cf.GetDictionaryValue(signingInfo, sec.CodeInfoDigestAlgorithms)

	if hashesPtr == 0 || algsPtr == 0 {
		return nil, fmt.Errorf("kSecCodeInfoCdHashes or kSecCodeInfoDigestAlgorithms key not found")
	}

	if cf.GetTypeID(hashesPtr) != cf.ArrayGetTypeID() || cf.GetTypeID(algsPtr) != cf.ArrayGetTypeID() {
		return nil, fmt.Errorf("hashes or algorithms value is not a CFArray")
	}

	hashesArray := corefoundation.ArrayRef(hashesPtr)
	algsArray := corefoundation.ArrayRef(algsPtr)

	hashesSlice := cf.GoSliceFromCFArray(hashesArray)
	algsSlice := cf.GoSliceFromCFArray(algsArray)

	if len(hashesSlice) != len(algsSlice) {
		return nil, fmt.Errorf("hashes and algorithms arrays have different lengths")
	}
	if len(hashesSlice) < 1 {
		return nil, fmt.Errorf("no hashes found in signing information")
	}

	resultMap := make(map[codeSignatureHash]string)
	for i := range hashesSlice {
		algPtr := algsSlice[i]
		if cf.GetTypeID(algPtr) != cf.NumberGetTypeID() {
			continue // Skip if not a number
		}
		var algID int32
		if !cf.NumberGetValue(corefoundation.NumberRef(algPtr), cf.NumberIntType, unsafe.Pointer(&algID)) {
			continue
		}

		hashPtr := hashesSlice[i]
		if cf.GetTypeID(hashPtr) != cf.DataGetTypeID() {
			continue // Skip if not data
		}
		hashData := corefoundation.DataRef(hashPtr)

		hashBytes := cf.BytesFromCFData(hashData)
		if len(hashBytes) > 0 {
			algName, err := mapAlgorithmIDToString(algID, sec)
			if err != nil {
				return nil, fmt.Errorf("failed to map algorithm ID to string: %w", err)
			}
			resultMap[algName] = hex.EncodeToString(hashBytes)
		}
	}

	return resultMap, nil
}

// mapAlgorithmIDToString converts a macOS digest algorithm constant to a string.
func mapAlgorithmIDToString(algID int32, sec *security.Framework) (codeSignatureHash, error) {
	switch algID {
	case sec.CodeSignatureHashSHA1:
		return codeSignatureHashSHA1, nil
	case sec.CodeSignatureHashSHA256:
		return codeSignatureHashSHA256, nil
	case sec.CodeSignatureHashSHA256Truncated:
		return codeSignatureHashSHA256Truncated, nil
	case sec.CodeSignatureHashSHA384:
		return codeSignatureHashSHA384, nil
	case sec.CodeSignatureHashSHA512:
		return codeSignatureHashSHA512, nil
	default:
		return "", fmt.Errorf("unknown code signature hash algorithm: %d", algID)
	}
}
