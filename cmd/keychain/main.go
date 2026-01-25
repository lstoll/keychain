//go:build darwin

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"lds.li/keychain"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "list-identities":
		cmdListIdentities(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: keychain <command> [options]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  list-identities    List identities")
}

func cmdListIdentities(args []string) {
	fs := flag.NewFlagSet("list-identities", flag.ExitOnError)
	typeFilter := fs.String("type", "all", "identity type: all, sec, ctk")
	label := fs.String("label", "", "filter by label")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: keychain list-identities [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Lists identities from the keychain.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Types:")
		fmt.Fprintln(os.Stderr, "  all    Both SecIdentity and CTK identities (default)")
		fmt.Fprintln(os.Stderr, "  sec    SecIdentity only (certificate + private key)")
		fmt.Fprintln(os.Stderr, "  ctk    CTK identities only (Secure Enclave keys)")
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	query := keychain.IdentityQuery{
		Label: *label,
	}

	switch *typeFilter {
	case "all":
		query.Type = keychain.IdentityQueryTypeAll
	case "sec":
		query.Type = keychain.IdentityQueryTypeSecIdentity
	case "ctk":
		query.Type = keychain.IdentityQueryTypeCTK
	default:
		fmt.Fprintf(os.Stderr, "invalid type: %s (use all, sec, or ctk)\n", *typeFilter)
		os.Exit(1)
	}

	identities, err := keychain.ListIdentities(query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error listing identities: %v\n", err)
		os.Exit(1)
	}

	if len(identities) == 0 {
		fmt.Println("No identities found.")
		return
	}

	for _, id := range identities {
		label := id.Label()
		if label == "" {
			label = "(no label)"
		}

		fmt.Printf("Label: %s\n", label)
		fmt.Printf("  Type: %s\n", id.Type())

		if hash, err := id.PublicKeyHash(); err == nil && hash != nil {
			fmt.Printf("  Public Key Hash: %s\n", hex.EncodeToString(hash))
		}
		if keySize, err := id.KeySizeInBits(); err == nil && keySize != 0 {
			fmt.Printf("  Key Size: %d bits\n", keySize)
		}
		// TokenID is only meaningful for CTK identities
		if tokenID := id.TokenID(); tokenID != "" {
			fmt.Printf("  Token ID: %s\n", tokenID)
		}

		if cert, err := id.Certificate(); err == nil && cert != nil {
			fmt.Printf("  Certificate:\n")
			fmt.Printf("    Subject: %s\n", cert.Subject)
			fmt.Printf("    Issuer: %s\n", cert.Issuer)
			fmt.Printf("    Serial: %s\n", cert.SerialNumber)
			fmt.Printf("    Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
			fmt.Printf("    Not After: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
		}
		fmt.Println()
	}
}
