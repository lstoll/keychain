//go:build !darwin

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("keychain is not supported on this platform (only macOS)")
	os.Exit(1)
}
