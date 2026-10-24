// Command cachehelper is a test helper for the cross-binary Cache test.
package main

import (
	"fmt"
	"os"

	"lds.li/keychain"
)

// build is set via -ldflags=-X so that differently built binaries differ.
var build = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: cachehelper <service> put|get|clear [key] [value] (build %s)", build)
	}
	c, err := keychain.NewCache(keychain.CacheOptions{Service: args[0]})
	if err != nil {
		return err
	}
	switch args[1] {
	case "put":
		if len(args) != 4 {
			return fmt.Errorf("put needs key and value")
		}
		return c.Put(args[2], []byte(args[3]), "")
	case "get":
		if len(args) != 3 {
			return fmt.Errorf("get needs key")
		}
		v, ok, err := c.Get(args[2])
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println("miss")
			return nil
		}
		fmt.Printf("hit %s\n", v)
	case "clear":
		return c.Clear()
	default:
		return fmt.Errorf("unknown command %q", args[1])
	}
	return nil
}
