# keychain
[![Go Reference](https://pkg.go.dev/badge/lds.li/keychain.svg)](https://pkg.go.dev/lds.li/keychain?GOOS=darwin)

Go access to the macOS Keychain and Secure Enclave, using
[purego](https://github.com/ebitengine/purego) to support easy using in
cross-compiled binaries.

## Passwords

`PasswordStore` stores passwords under a service:

```go
store, err := keychain.NewPasswordStore(keychain.PasswordStoreOptions{
    Service: "example.com/my-tool",
})
// Handle err.
err = store.Set("alice", []byte("password"))
// Handle err.
password, err := store.Get("alice")
// Handle err.
```

By default it uses the file-backed keychain, which works from ad-hoc binaries.
Changing the binary will cause a user prompt to grant permissions, unless the
binary is signed with a valid ID. Use `Backend: keychain.BackendDataProtection`
for protection classes, authentication constraints, access groups, or iCloud
synchronization. This will require the binaries to be signed by a valid
developer ID.

P-256 keys are supported, alongside ML-DSA-65 and ML-DSA-87 on Go 1.27 / macOS
Tahoe (26) and later.

## Cache

`Cache` stores replaceable secrets, such as OAuth2 tokens, in the file keychain.
By default, it records `BinaryIdentity()` with each entry. When the identity
changes, it deletes the stale entry without reading its secret and reports a
miss, avoiding the usual access prompt after a rebuild.

Use a dedicated service, `Cache` treats every item in the service as a cache
entry.

```go
c, err := keychain.NewCache(keychain.CacheOptions{Service: "com.example.mytool.cache"})
// Handle err.
tok, ok, err := c.Get("oauth2-token")
// Handle err.
if !ok {
    // Obtain a fresh token, then cache it.
    err = c.Put("oauth2-token", newTokenJSON, "mytool OAuth2 token")
    // Handle err.
}
```

## Secure Enclave keys

Create a signing key without adding a keychain item:

```go
key, err := keychain.CreateSecureEnclaveKey(keychain.SecureEnclaveKeyOptions{
    AccessControl: &keychain.AccessControl{
        Protection: keychain.AccessibleWhenUnlockedThisDeviceOnly,
        Flags:      keychain.AccessControlUserPresence,
    },
})
// Handle err.
blob := key.DataRepresentation() // Save in protected storage.
loaded, err := keychain.LoadSecureEnclaveKey(blob, keychain.SecureEnclaveLoadOptions{})
// Handle err. Both key and loaded implement crypto.Signer.
```

The returned representation is an opaque blob, that is bound to the machine it
was created on. It can not be used on any other hardware. This is useful for
DPoP signing keys, where the blob can be cached alongside the respective
access/refresh token.

## Identities

`ListIdentities` and `GetIdentity` find existing certificate/private-key pairs,
including CryptoTokenKit identities. `Identity.Signer` returns a
`crypto.Signer`, `Identity.CertificateChain` builds a chain with SecTrust.
`sc_auth create-ctk-identity` can be used to create hardware-backed identities.

