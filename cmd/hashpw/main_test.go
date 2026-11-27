package main

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// run executes the built binary with the given standard input, and returns the output and the exit code
func run(t *testing.T, bin, stdin string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exitCode = exitErr.ExitCode()
	} else {
		require.NoError(t, err)
	}
	return outBuf.String(), errBuf.String(), exitCode
}

func TestHashpw(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "hashpw")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	require.NoError(t, err, string(out))

	cost := "-cost=4"

	t.Run("prints a hash that matches the password", func(t *testing.T) {
		stdout, stderr, code := run(t, bin, "s3cret", cost)
		require.Equal(t, 0, code, stderr)
		require.Empty(t, stderr)
		hash := strings.TrimSpace(stdout)
		require.NoError(t, bcrypt.CompareHashAndPassword([]byte(hash), []byte("s3cret")))
	})

	t.Run("the line ending of the input is not part of the password", func(t *testing.T) {
		for _, input := range []string{"s3cret\n", "s3cret\r\n"} {
			stdout, stderr, code := run(t, bin, input, cost)
			require.Equal(t, 0, code, stderr)
			require.NoError(t, bcrypt.CompareHashAndPassword([]byte(strings.TrimSpace(stdout)), []byte("s3cret")))
		}
	})

	t.Run("other whitespace is part of the password", func(t *testing.T) {
		stdout, stderr, code := run(t, bin, " s3cret ", cost)
		require.Equal(t, 0, code, stderr)
		hash := []byte(strings.TrimSpace(stdout))
		require.NoError(t, bcrypt.CompareHashAndPassword(hash, []byte(" s3cret ")))
		require.Error(t, bcrypt.CompareHashAndPassword(hash, []byte("s3cret")))
	})

	t.Run("the cost flag is used", func(t *testing.T) {
		stdout, stderr, code := run(t, bin, "s3cret", "-cost=5")
		require.Equal(t, 0, code, stderr)
		got, err := bcrypt.Cost([]byte(strings.TrimSpace(stdout)))
		require.NoError(t, err)
		require.Equal(t, 5, got)
	})

	t.Run("an empty password fails", func(t *testing.T) {
		for _, input := range []string{"", "\n"} {
			stdout, stderr, code := run(t, bin, input, cost)
			require.Equal(t, 1, code)
			require.Empty(t, stdout)
			require.Contains(t, stderr, "password is empty")
		}
	})

	t.Run("a password over 72 bytes fails", func(t *testing.T) {
		stdout, stderr, code := run(t, bin, strings.Repeat("a", 73), cost)
		require.Equal(t, 1, code)
		require.Empty(t, stdout)
		require.Contains(t, stderr, "longer than 72 bytes")
	})

	t.Run("a cost above the maximum fails", func(t *testing.T) {
		stdout, stderr, code := run(t, bin, "s3cret", "-cost=32")
		require.Equal(t, 1, code)
		require.Empty(t, stdout)
		require.Contains(t, stderr, "failed to hash the password")
	})

	t.Run("the password is never printed on failure", func(t *testing.T) {
		pw := strings.Repeat("x", 80)
		stdout, stderr, _ := run(t, bin, pw, cost)
		require.NotContains(t, stdout+stderr, pw)
	})
}
