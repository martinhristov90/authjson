// hashpw prints the bcrypt hash of a password, the hash is what goes into the "password" field of the users file.
//
// The password is read from the standard input, so it does not end up in the shell history or the process list:
//
//	read -rs PW && printf '%s' "$PW" | go run ./cmd/hashpw
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/martinhristov90/authjson/internal/jsonauthhelper"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	cost := flag.Int("cost", 12, fmt.Sprintf("bcrypt cost, between %d and %d", bcrypt.MinCost, bcrypt.MaxCost))
	flag.Parse()

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to read the password:", err)
		os.Exit(1)
	}
	// Only the line ending added by the terminal or echo is removed, other whitespace is part of the password
	password := strings.TrimRight(string(raw), "\r\n")

	hash, err := jsonauthhelper.HashPassword(password, *cost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to hash the password:", err)
		os.Exit(1)
	}
	fmt.Println(hash)
}
