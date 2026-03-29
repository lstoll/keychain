//go:build darwin

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"lds.li/keychain"
)

func cmdCreateCTKCSR(args []string) {
	fs := flag.NewFlagSet("create-ctk-csr", flag.ExitOnError)
	label := fs.String("label", "", "identity label (required)")
	cn := fs.String("cn", "", "common name (subject) for the identity and CSR")
	keyType := fs.String("key", "p256", "key algorithm: p256 or p384 (Secure Enclave non-extractable)")
	outPath := fs.String("out", "", "write CSR PEM to this file (default: stdout)")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: keychain create-ctk-csr [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Creates a new CTK identity in the Secure Enclave and outputs a PEM CSR for it.")
		fmt.Fprintln(os.Stderr, "Metadata is printed to stderr; the CSR PEM goes to stdout or -out.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if *label == "" {
		fmt.Fprintln(os.Stderr, "error: -label is required")
		fs.Usage()
		os.Exit(1)
	}

	var kt keychain.CTKKeyType
	switch *keyType {
	case "p256":
		kt = keychain.CTKKeyTypeP256
	case "p384":
		kt = keychain.CTKKeyTypeP384
	default:
		fmt.Fprintf(os.Stderr, "invalid -key %q (use p256 or p384)\n", *keyType)
		os.Exit(1)
	}

	identity, err := keychain.CreateCTKIdentity(keychain.CreateCTKIdentityInput{
		Label:      *label,
		KeyType:    kt,
		CommonName: *cn,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating CTK identity: %v\n", err)
		os.Exit(1)
	}

	csrPEM, err := keychain.CreateCTKIdentityCSR(identity, keychain.CreateCTKIdentityCSRInput{
		CommonName: *cn,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating CSR: %v\n", err)
		os.Exit(1)
	}

	hash, err := identity.PublicKeyHash()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading public key hash: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Public key hash: %s\n", hex.EncodeToString(hash))
	fmt.Fprintf(os.Stderr, "Label: %s\n", *label)

	if *outPath != "" {
		if err := os.WriteFile(*outPath, csrPEM, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "error writing CSR: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if _, err := os.Stdout.Write(csrPEM); err != nil {
		fmt.Fprintf(os.Stderr, "error writing CSR: %v\n", err)
		os.Exit(1)
	}
	if len(csrPEM) == 0 || csrPEM[len(csrPEM)-1] != '\n' {
		fmt.Println()
	}
}

func cmdImportCTKCertificate(args []string) {
	fs := flag.NewFlagSet("import-ctk-certificate", flag.ExitOnError)
	file := fs.String("f", "", "path to certificate PEM file (default: read stdin)")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: keychain import-ctk-certificate [-f path]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Imports a certificate issued for a CTK CSR into the keychain (sc_auth import-ctk-certificate).")
		fmt.Fprintln(os.Stderr, "With no -f or -f -, PEM is read from stdin.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	var pemData []byte
	var err error
	if *file == "" || *file == "-" {
		pemData, err = io.ReadAll(os.Stdin)
	} else {
		pemData, err = os.ReadFile(*file)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading certificate: %v\n", err)
		os.Exit(1)
	}

	if err := keychain.ImportCTKCertificate(pemData); err != nil {
		fmt.Fprintf(os.Stderr, "error importing certificate: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "Certificate imported.")
}
