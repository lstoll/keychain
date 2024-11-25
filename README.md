# keychain
[![Go Reference](https://pkg.go.dev/badge/github.com/lstoll/keychain.svg)](https://pkg.go.dev/github.com/lstoll/keychain)

Status: early development

Module to provide "pure go" access to the macOS Keychain, using [purego])https://github.com/ebitengine/purego). Rather than requiring cgo, this loads and calls the Frameworks at runtime. This allows easy cross-compilation without a macOS SDK and compiler, which is useful for simple builds for tools in Linux-based CI.
