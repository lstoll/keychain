//go:build darwin

package keychain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"unsafe"
)

var preferredCDHashes = []CodeSignatureHash{
	CodeSignatureHashSHA256,
	CodeSignatureHashSHA256Truncated,
	CodeSignatureHashSHA384,
	CodeSignatureHashSHA512,
	CodeSignatureHashSHA1,
}

// GetBinaryIdentity returns a unique identifier for the current binary. This
// can be used to key items for use by this build of the app only, ignoring them
// silently if the binary changes. This is useful in ad-hoc/temporary items, to
// avoid prompting the user to unlock the keychain when reading a secret. By
// default on ARM platforms all binaries must be codesigned, which may be an
// ad-hoc or formal signature. If the binary is signed, this will return the
// code signing hash. If the binary is unsigned or verification fails, this will
// return the SHA-256 hash of the executable file.
func GetBinaryIdentity() (string, error) {
	// TODO - handle legit code-signed binaries, and use something consistent
	// across versions of them.

	// First, try the preferred method: getting the OS-level CDHash.
	cdHashes, err := getSelfCDHashes()
	if err == nil {
		for _, hash := range preferredCDHashes {
			if cdHash, ok := cdHashes[hash]; ok {
				return cdHash, nil
			}
		}
	}

	// if that fails, fallback to the executable file hash
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

type CodeSignatureHash string

const (
	CodeSignatureHashSHA1            CodeSignatureHash = "sha1"
	CodeSignatureHashSHA256          CodeSignatureHash = "sha256"
	CodeSignatureHashSHA256Truncated CodeSignatureHash = "sha256_truncated"
	CodeSignatureHashSHA384          CodeSignatureHash = "sha384"
	CodeSignatureHashSHA512          CodeSignatureHash = "sha512"
)

// getSelfCDHashes retrieves a map of all Code Directory Hashes (CDHashes) for
// the running binary, keyed by their digest algorithm type.
func getSelfCDHashes() (map[CodeSignatureHash]string, error) {
	cf, err := getCoreFoundation()
	if err != nil {
		return nil, err
	}
	sec, err := getSecurity()
	if err != nil {
		return nil, err
	}

	// Get a reference to the static code of the currently running process.
	var myselfCode _SecCodeRef
	status := sec.CodeCopySelf(kSecCSDefaultFlags, &myselfCode)
	if err := sec.newError(status); err != nil {
		return nil, fmt.Errorf("failed to get SecCodeRef for self: %w", err)
	}
	defer cf.Release(_CFTypeRef(myselfCode))

	// Validate the code signature first, to see if we're signed and it's valid.
	// If not, we can fallback later.
	status = sec.CodeCheckValidity(myselfCode, kSecCSDefaultFlags, 0)
	if err := sec.newError(status); err != nil {
		return nil, err
	}

	// Get the code signing information dictionary.
	var signingInfo _CFDictionaryRef
	// SecStaticCodeRef is same as SecCodeRef in structure (ptr), just stricter type in C.
	status = sec.CodeCopySigningInformation(_SecStaticCodeRef(myselfCode), kSecCSDefaultFlags, &signingInfo)
	if err := sec.newError(status); err != nil {
		return nil, fmt.Errorf("failed to copy signing information: %w", err)
	}
	defer cf.Release(_CFTypeRef(signingInfo))

	hashesPtr := cf.GetDictionaryValue(signingInfo, sec.CodeInfoCdHashes)
	algsPtr := cf.GetDictionaryValue(signingInfo, sec.CodeInfoDigestAlgorithms)

	if hashesPtr == 0 || algsPtr == 0 {
		return nil, fmt.Errorf("kSecCodeInfoCdHashes or kSecCodeInfoDigestAlgorithms key not found")
	}

	if cf.GetTypeID(hashesPtr) != cf.ArrayGetTypeID() || cf.GetTypeID(algsPtr) != cf.ArrayGetTypeID() {
		return nil, fmt.Errorf("hashes or algorithms value is not a CFArray")
	}

	hashesArray := _CFArrayRef(hashesPtr)
	algsArray := _CFArrayRef(algsPtr)

	hashesSlice := cf.GoSliceFromCFArray(hashesArray)
	algsSlice := cf.GoSliceFromCFArray(algsArray)

	if len(hashesSlice) != len(algsSlice) {
		return nil, fmt.Errorf("hashes and algorithms arrays have different lengths")
	}
	if len(hashesSlice) < 1 {
		return nil, fmt.Errorf("no hashes found in signing information")
	}

	resultMap := make(map[CodeSignatureHash]string)
	for i := range hashesSlice {
		algPtr := algsSlice[i]
		if cf.GetTypeID(algPtr) != cf.NumberGetTypeID() {
			continue // Skip if not a number
		}
		var algID int32
		if !cf.NumberGetValue(_CFNumberRef(algPtr), cf.NumberIntType, unsafe.Pointer(&algID)) {
			continue
		}

		hashPtr := hashesSlice[i]
		if cf.GetTypeID(hashPtr) != cf.DataGetTypeID() {
			continue // Skip if not data
		}
		hashData := _CFDataRef(hashPtr)

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
func mapAlgorithmIDToString(algID int32, sec *securityFramework) (CodeSignatureHash, error) {
	switch algID {
	case sec.CodeSignatureHashSHA1:
		return CodeSignatureHashSHA1, nil
	case sec.CodeSignatureHashSHA256:
		return CodeSignatureHashSHA256, nil
	case sec.CodeSignatureHashSHA256Truncated:
		return CodeSignatureHashSHA256Truncated, nil
	case sec.CodeSignatureHashSHA384:
		return CodeSignatureHashSHA384, nil
	case sec.CodeSignatureHashSHA512:
		return CodeSignatureHashSHA512, nil
	default:
		return "", fmt.Errorf("unknown code signature hash algorithm: %d", algID)
	}
}
