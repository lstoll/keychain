//go:build darwin

package keychain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// testLabel generates a unique label for test identities
func testLabel(suffix string) string {
	return "oauth2ext-test-" + suffix
}

func TestCreateAndDeleteCTKIdentity(t *testing.T) {
	if os.Getenv("TEST_CTK_IDENTITY") != "1" {
		t.Skip("TEST_CTK_IDENTITY is not set")
	}

	label := testLabel("create-delete")

	// Create a new identity
	identity, err := CreateCTKIdentity(label, CTKKeyTypeP256)
	if err != nil {
		t.Fatalf("CreateCTKIdentity failed: %v", err)
	}

	ctkId, ok := identity.(*ctkIdentity)
	if !ok {
		t.Fatalf("expected *ctkIdentity, got %T", identity)
	}

	t.Logf("Created identity: Label=%q PublicKeyHash=%s KeySize=%d",
		ctkId.Label(), hex.EncodeToString(ctkId.PublicKeyHash), ctkId.KeySizeInBits)

	// Verify the identity exists
	if ctkId.Label() != label {
		t.Errorf("expected label %q, got %q", label, ctkId.Label())
	}
	if ctkId.KeySizeInBits != 256 {
		t.Errorf("expected key size 256, got %d", ctkId.KeySizeInBits)
	}

	// Delete the identity
	err = DeleteCTKIdentity(ctkId.PublicKeyHash)
	if err != nil {
		t.Fatalf("DeleteCTKIdentity failed: %v", err)
	}

	// Verify it's gone
	_, err = GetCTKIdentity(label, nil)
	if err == nil {
		t.Error("expected error getting deleted identity")
	}
}

func TestListCTKIdentities(t *testing.T) {
	if os.Getenv("TEST_CTK_IDENTITY") != "1" {
		t.Skip("TEST_CTK_IDENTITY is not set")
	}

	// Create two test identities
	label1 := testLabel("list-1")
	label2 := testLabel("list-2")

	id1, err := CreateCTKIdentity(label1, CTKKeyTypeP256)
	if err != nil {
		t.Fatalf("CreateCTKIdentity (1) failed: %v", err)
	}
	ctkId1 := id1.(*ctkIdentity)
	t.Cleanup(func() {
		if err := DeleteCTKIdentity(ctkId1.PublicKeyHash); err != nil {
			t.Fatalf("DeleteCTKIdentity (1) failed: %v", err)
		}
	})

	id2, err := CreateCTKIdentity(label2, CTKKeyTypeP256)
	if err != nil {
		t.Fatalf("CreateCTKIdentity (2) failed: %v", err)
	}
	ctkId2 := id2.(*ctkIdentity)
	t.Cleanup(func() {
		if err := DeleteCTKIdentity(ctkId2.PublicKeyHash); err != nil {
			t.Fatalf("DeleteCTKIdentity (2) failed: %v", err)
		}
	})

	// List all identities
	identities, err := ListCTKIdentities()
	if err != nil {
		t.Fatalf("ListCTKIdentities failed: %v", err)
	}

	t.Logf("Found %d CTK identities", len(identities))

	// Verify our test identities are in the list
	found1, found2 := false, false
	for _, id := range identities {
		if ctkId, ok := id.(*ctkIdentity); ok {
			t.Logf("  Label=%q PublicKeyHash=%s KeySize=%d",
				ctkId.Label(), hex.EncodeToString(ctkId.PublicKeyHash), ctkId.KeySizeInBits)
			if ctkId.Label() == label1 {
				found1 = true
			}
			if ctkId.Label() == label2 {
				found2 = true
			}
		}
	}

	if !found1 {
		t.Errorf("identity %q not found in list", label1)
	}
	if !found2 {
		t.Errorf("identity %q not found in list", label2)
	}
}

func TestGetCTKIdentityByLabel(t *testing.T) {
	if os.Getenv("TEST_CTK_IDENTITY") != "1" {
		t.Skip("TEST_CTK_IDENTITY is not set")
	}

	label := testLabel("get-by-label")

	// Create a test identity
	created, err := CreateCTKIdentity(label, CTKKeyTypeP256)
	if err != nil {
		t.Fatalf("CreateCTKIdentity failed: %v", err)
	}
	createdCtk := created.(*ctkIdentity)
	t.Cleanup(func() {
		if err := DeleteCTKIdentity(createdCtk.PublicKeyHash); err != nil {
			t.Fatalf("DeleteCTKIdentity failed: %v", err)
		}
	})

	// Get it back by label
	identity, err := GetCTKIdentity(label, nil)
	if err != nil {
		t.Fatalf("GetCTKIdentity failed: %v", err)
	}
	defer identity.Close()

	ctkId := identity.(*ctkIdentity)

	t.Logf("Found identity: Label=%q PublicKeyHash=%s KeySize=%d",
		ctkId.Label(), hex.EncodeToString(ctkId.PublicKeyHash), ctkId.KeySizeInBits)

	// Verify we got the right one
	if hex.EncodeToString(ctkId.PublicKeyHash) != hex.EncodeToString(createdCtk.PublicKeyHash) {
		t.Errorf("public key hash mismatch")
	}
}

func TestGetCTKIdentityByPublicKeyHash(t *testing.T) {
	if os.Getenv("TEST_CTK_IDENTITY") != "1" {
		t.Skip("TEST_CTK_IDENTITY is not set")
	}

	label := testLabel("get-by-hash")

	// Create a test identity
	created, err := CreateCTKIdentity(label, CTKKeyTypeP256)
	if err != nil {
		t.Fatalf("CreateCTKIdentity failed: %v", err)
	}
	createdCtk := created.(*ctkIdentity)
	t.Cleanup(func() {
		if err := DeleteCTKIdentity(createdCtk.PublicKeyHash); err != nil {
			t.Fatalf("DeleteCTKIdentity failed: %v", err)
		}
	})

	// Get it back by public key hash
	identity, err := GetCTKIdentity("", createdCtk.PublicKeyHash)
	if err != nil {
		t.Fatalf("GetCTKIdentity by hash failed: %v", err)
	}
	defer identity.Close()

	ctkId := identity.(*ctkIdentity)

	t.Logf("Found identity: Label=%q PublicKeyHash=%s",
		ctkId.Label(), hex.EncodeToString(ctkId.PublicKeyHash))

	if ctkId.Label() != label {
		t.Errorf("expected label %q, got %q", label, ctkId.Label())
	}
}

func TestCTKIdentitySigning(t *testing.T) {
	if os.Getenv("TEST_CTK_IDENTITY") != "1" {
		t.Skip("TEST_CTK_IDENTITY is not set")
	}

	label := testLabel("signing")

	// Create a test identity
	created, err := CreateCTKIdentity(label, CTKKeyTypeP256)
	if err != nil {
		t.Fatalf("CreateCTKIdentity failed: %v", err)
	}
	createdCtk := created.(*ctkIdentity)
	t.Cleanup(func() {
		if err := DeleteCTKIdentity(createdCtk.PublicKeyHash); err != nil {
			t.Fatalf("DeleteCTKIdentity failed: %v", err)
		}
	})

	// Get identity with signing capability
	identity, err := GetCTKIdentity(label, nil)
	if err != nil {
		t.Fatalf("GetCTKIdentity failed: %v", err)
	}
	defer identity.Close()

	// Get signer
	signer, err := identity.Signer()
	if err != nil {
		t.Fatalf("Signer failed: %v", err)
	}

	pubKey, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", signer.Public())
	}
	t.Logf("Public key curve: %s", pubKey.Curve.Params().Name)

	// Sign some data
	message := []byte("test message for CTK signing")
	hash := sha256.Sum256(message)
	signature, err := signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	t.Logf("Signature length: %d bytes", len(signature))

	// Verify the signature
	if !ecdsa.VerifyASN1(pubKey, hash[:], signature) {
		t.Fatal("signature verification failed")
	}
	t.Log("Signature verified successfully!")
}

func TestCTKIdentitySelectsCorrectKey(t *testing.T) {
	if os.Getenv("TEST_CTK_IDENTITY") != "1" {
		t.Skip("TEST_CTK_IDENTITY is not set")
	}

	label1 := testLabel("select-1")
	label2 := testLabel("select-2")

	// Create two test identities
	id1, err := CreateCTKIdentity(label1, CTKKeyTypeP256)
	if err != nil {
		t.Fatalf("CreateCTKIdentity (1) failed: %v", err)
	}
	ctkId1 := id1.(*ctkIdentity)
	t.Cleanup(func() {
		if err := DeleteCTKIdentity(ctkId1.PublicKeyHash); err != nil {
			t.Fatalf("DeleteCTKIdentity (1) failed: %v", err)
		}
	})

	id2, err := CreateCTKIdentity(label2, CTKKeyTypeP256)
	if err != nil {
		t.Fatalf("CreateCTKIdentity (2) failed: %v", err)
	}
	ctkId2 := id2.(*ctkIdentity)
	t.Cleanup(func() {
		if err := DeleteCTKIdentity(ctkId2.PublicKeyHash); err != nil {
			t.Fatalf("DeleteCTKIdentity (2) failed: %v", err)
		}
	})

	// Get first key by label
	key1, err := GetCTKIdentity(label1, nil)
	if err != nil {
		t.Fatalf("GetCTKIdentity (1) failed: %v", err)
	}
	defer key1.Close()
	ctkKey1 := key1.(*ctkIdentity)

	// Get second key by label
	key2, err := GetCTKIdentity(label2, nil)
	if err != nil {
		t.Fatalf("GetCTKIdentity (2) failed: %v", err)
	}
	defer key2.Close()
	ctkKey2 := key2.(*ctkIdentity)

	hash1 := hex.EncodeToString(ctkKey1.PublicKeyHash)
	hash2 := hex.EncodeToString(ctkKey2.PublicKeyHash)

	t.Logf("Key 1 (%s): %s", label1, hash1)
	t.Logf("Key 2 (%s): %s", label2, hash2)

	// Verify they're different keys
	if hash1 == hash2 {
		t.Error("both queries returned the same key!")
	}

	// Verify we got the right keys
	if hash1 != hex.EncodeToString(ctkId1.PublicKeyHash) {
		t.Errorf("key 1 has wrong hash")
	}
	if hash2 != hex.EncodeToString(ctkId2.PublicKeyHash) {
		t.Errorf("key 2 has wrong hash")
	}
}

func TestCTKIdentityDuplicateLabelError(t *testing.T) {
	if os.Getenv("TEST_CTK_IDENTITY") != "1" {
		t.Skip("TEST_CTK_IDENTITY is not set")
	}

	label := testLabel("duplicate")

	// Create two identities with the same label
	id1, err := CreateCTKIdentity(label, CTKKeyTypeP256)
	if err != nil {
		t.Fatalf("CreateCTKIdentity (1) failed: %v", err)
	}
	ctkId1 := id1.(*ctkIdentity)
	t.Cleanup(func() {
		if err := DeleteCTKIdentity(ctkId1.PublicKeyHash); err != nil {
			t.Fatalf("DeleteCTKIdentity (1) failed: %v", err)
		}
	})

	id2, err := CreateCTKIdentity(label, CTKKeyTypeP256)
	if err != nil {
		t.Fatalf("CreateCTKIdentity (2) failed: %v", err)
	}
	ctkId2 := id2.(*ctkIdentity)
	t.Cleanup(func() {
		if err := DeleteCTKIdentity(ctkId2.PublicKeyHash); err != nil {
			t.Fatalf("DeleteCTKIdentity (2) failed: %v", err)
		}
	})

	// Try to get by label - should error due to duplicates
	_, err = GetCTKIdentity(label, nil)
	if err == nil {
		t.Error("expected error when multiple identities have the same label")
	} else {
		t.Logf("Got expected error: %v", err)
	}

	// But we can still get each by hash
	key1, err := GetCTKIdentity("", ctkId1.PublicKeyHash)
	if err != nil {
		t.Fatalf("GetCTKIdentity by hash (1) failed: %v", err)
	}
	key1.Close()

	key2, err := GetCTKIdentity("", ctkId2.PublicKeyHash)
	if err != nil {
		t.Fatalf("GetCTKIdentity by hash (2) failed: %v", err)
	}
	key2.Close()
}

func TestGetCTKIdentityRequiresLabelOrHash(t *testing.T) {
	if os.Getenv("TEST_CTK_IDENTITY") != "1" {
		t.Skip("TEST_CTK_IDENTITY is not set")
	}

	_, err := GetCTKIdentity("", nil)
	if err == nil {
		t.Error("expected error when neither label nor publicKeyHash provided")
	}
}

func TestDeleteCTKIdentityByLabel(t *testing.T) {
	if os.Getenv("TEST_CTK_IDENTITY") != "1" {
		t.Skip("TEST_CTK_IDENTITY is not set")
	}

	label := testLabel("delete-by-label")

	// Create a test identity
	created, err := CreateCTKIdentity(label, CTKKeyTypeP256)
	if err != nil {
		t.Fatalf("CreateCTKIdentity failed: %v", err)
	}
	// Use type assertion to get PublicKeyHash for verification later
	createdCtk := created.(*ctkIdentity)

	// Delete by label
	err = DeleteCTKIdentityByLabel(label)
	if err != nil {
		t.Fatalf("DeleteCTKIdentityByLabel failed: %v", err)
	}

	// Verify it's gone
	_, err = GetCTKIdentity("", createdCtk.PublicKeyHash)
	if err == nil {
		t.Error("expected error getting deleted identity")
	}
}