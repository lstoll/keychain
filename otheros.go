//go:build !darwin

package keychain

// no-op file, lets the module be included on other platforms, but does not
// allow it to do anything.
