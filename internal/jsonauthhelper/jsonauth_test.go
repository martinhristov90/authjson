package jsonauthhelper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// bcrypt.MinCost keeps the tests fast, real users files should use a much higher cost
const testCost = bcrypt.MinCost

func mustHash(password string) string {
	hash, err := HashPassword(password, testCost)
	if err != nil {
		panic(err)
	}
	return hash
}

var (
	hashA = mustHash("pw-a")
	hashB = mustHash("pw-b")
)

// hashPlaceholder is replaced by a valid bcrypt hash in the JSON of the tests
const hashPlaceholder = "HASH"

func TestLoadUsersFromFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantLen int
		// wantErr lists substrings that must all be part of the error, empty means no error is expected
		wantErr []string
	}{
		{"valid", `[{"user_id":"a","password":"HASH","team_role":"r"}]`, 1, nil},
		{"valid with two users", `[{"user_id":"a","password":"HASH","team_role":"r"},{"user_id":"b","password":"HASH","team_role":"r"}]`, 2, nil},
		{"empty array", `[]`, 0, nil},
		{"truncated JSON", `[{"user_id":"a"`, 0, []string{"unexpected EOF"}},
		{"empty file", ``, 0, []string{"EOF"}},
		{"wrong shape", `{"user_id":"a"}`, 0, []string{"cannot unmarshal"}},
		{
			"duplicate user ID",
			`[{"user_id":"a","password":"HASH","team_role":"r"},{"user_id":"a","password":"HASH","team_role":"r"}]`,
			0, []string{`user "a" (#1): duplicate of user #0`},
		},
		{
			"user ID is case sensitive so these are not duplicates",
			`[{"user_id":"a","password":"HASH","team_role":"r"},{"user_id":"A","password":"HASH","team_role":"r"}]`,
			2, nil,
		},
		{"empty user ID", `[{"user_id":"","password":"HASH","team_role":"r"}]`, 0, []string{"user #0: user_id is empty"}},
		{"missing user ID", `[{"password":"HASH","team_role":"r"}]`, 0, []string{"user #0: user_id is empty"}},
		{"empty password", `[{"user_id":"a","password":"","team_role":"r"}]`, 0, []string{`user "a": password is empty`}},
		{"missing password", `[{"user_id":"a","team_role":"r"}]`, 0, []string{`user "a": password is empty`}},
		{"plaintext password", `[{"user_id":"a","password":"plaintext","team_role":"r"}]`, 0, []string{`user "a": password is not a bcrypt hash`}},
		{"placeholder instead of a hash", `[{"user_id":"a","password":"hashed_password_here","team_role":"r"}]`, 0, []string{`user "a": password is not a bcrypt hash`}},
		{"truncated hash", `[{"user_id":"a","password":"$2a$04$2GdbMEvE6ceyqJ2beTcZBOhLlzaPiFOQ","team_role":"r"}]`, 0, []string{`user "a": password is not a bcrypt hash`}},
		{"empty team role", `[{"user_id":"a","password":"HASH","team_role":""}]`, 0, []string{`user "a": team_role is empty`}},
		{"misspelled team role", `[{"user_id":"a","password":"HASH","team_roles":"r"}]`, 0, []string{`user "a": team_role is empty`}},
		{
			"all problems are reported at once",
			`[{"user_id":"a","password":"","team_role":"r"},{"user_id":"a","password":"plaintext","team_role":""},{"password":"HASH","team_role":"r"}]`,
			0,
			[]string{
				`user "a": password is empty`,
				`user "a" (#1): duplicate of user #0`,
				`user "a": password is not a bcrypt hash`,
				`user "a": team_role is empty`,
				"user #2: user_id is empty",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			content := strings.ReplaceAll(tt.content, hashPlaceholder, hashA)
			require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

			users, err := LoadUsersFromFile(path)
			if len(tt.wantErr) > 0 {
				require.Error(t, err)
				require.Nil(t, users)
				for _, want := range tt.wantErr {
					require.ErrorContains(t, err, want)
				}
				return
			}
			require.NoError(t, err)
			require.Len(t, users, tt.wantLen)
		})
	}

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadUsersFromFile(filepath.Join(t.TempDir(), "nope.json"))
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("a validation error is marked as such but never prints a password", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "users.json")
		content := `[{"user_id":"a","password":"s3cret-value","team_role":""}]`
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		_, err := LoadUsersFromFile(path)
		require.Error(t, err)
		require.ErrorContains(t, err, "invalid users file")
		require.ErrorContains(t, err, "password is not a bcrypt hash")
		require.NotContains(t, err.Error(), "s3cret-value")
	})

	t.Run("the example users file is valid once the placeholder is replaced", func(t *testing.T) {
		template, err := os.ReadFile("../../users.example.json")
		require.NoError(t, err)
		path := filepath.Join(t.TempDir(), "users.json")
		content := strings.ReplaceAll(string(template), "REPLACE_WITH_BCRYPT_HASH", hashA)
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		users, err := LoadUsersFromFile(path)
		require.NoError(t, err)
		require.NotEmpty(t, users)
	})
}

func TestHashPassword(t *testing.T) {
	t.Run("the hash matches the password and carries the cost", func(t *testing.T) {
		hash, err := HashPassword("pw", testCost)
		require.NoError(t, err)
		require.NoError(t, bcrypt.CompareHashAndPassword([]byte(hash), []byte("pw")))
		require.Error(t, bcrypt.CompareHashAndPassword([]byte(hash), []byte("other")))

		cost, err := bcrypt.Cost([]byte(hash))
		require.NoError(t, err)
		require.Equal(t, testCost, cost)
	})

	t.Run("the same password gets a different hash every time because of the salt", func(t *testing.T) {
		first, err := HashPassword("pw", testCost)
		require.NoError(t, err)
		second, err := HashPassword("pw", testCost)
		require.NoError(t, err)
		require.NotEqual(t, first, second)
	})

	t.Run("the longest password is accepted", func(t *testing.T) {
		_, err := HashPassword(strings.Repeat("a", MaxPasswordBytes), testCost)
		require.NoError(t, err)
	})

	t.Run("too long password is rejected", func(t *testing.T) {
		_, err := HashPassword(strings.Repeat("a", MaxPasswordBytes+1), testCost)
		require.Error(t, err)
	})

	t.Run("empty password is rejected", func(t *testing.T) {
		_, err := HashPassword("", testCost)
		require.Error(t, err)
	})

	t.Run("invalid cost is rejected", func(t *testing.T) {
		_, err := HashPassword("pw", bcrypt.MaxCost+1)
		require.Error(t, err)
	})
}

var testUsers = []User{
	{UserID: "user-a", Password: hashA, TeamRole: "backline"},
	{UserID: "user-b", Password: hashB, TeamRole: "core"},
	{UserID: "user-nopass", Password: "", TeamRole: "core"},
	{UserID: "user-badhash", Password: "not-a-bcrypt-hash", TeamRole: "core"},
}

func TestFindUser(t *testing.T) {
	tests := []struct {
		name     string
		userID   string
		users    []User
		wantRole string // empty means no user is expected
	}{
		{"existing user", "user-b", testUsers, "core"},
		{"first user", "user-a", testUsers, "backline"},
		{"unknown user", "user-x", testUsers, ""},
		{"empty user ID", "", testUsers, ""},
		{"empty user list", "user-a", []User{}, ""},
		{"nil user list", "user-a", nil, ""},
		{"user ID is case sensitive", "USER-A", testUsers, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindUser(tt.userID, tt.users)
			if tt.wantRole == "" {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, tt.userID, got.UserID)
			require.Equal(t, tt.wantRole, got.TeamRole)
		})
	}
}

func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name     string
		userID   string
		password string
		users    []User
		wantOK   bool
	}{
		{"correct credentials", "user-a", "pw-a", testUsers, true},
		{"second user with correct credentials", "user-b", "pw-b", testUsers, true},
		{"wrong password", "user-a", "wrong", testUsers, false},
		{"password of another user", "user-a", "pw-b", testUsers, false},
		{"password is case sensitive", "user-a", "PW-A", testUsers, false},
		{"password is only a prefix", "user-a", "pw-", testUsers, false},
		{"password has extra characters", "user-a", "pw-a-extra", testUsers, false},
		{"the hash itself is not accepted as the password", "user-a", hashA, testUsers, false},
		{"unknown user", "user-x", "pw-a", testUsers, false},
		{"empty user ID and password", "", "", testUsers, false},
		{"empty password", "user-a", "", testUsers, false},
		{"user with empty stored password and empty input", "user-nopass", "", testUsers, false},
		{"user with empty stored password and some input", "user-nopass", "anything", testUsers, false},
		{"user with a stored value that is not a hash", "user-badhash", "not-a-bcrypt-hash", testUsers, false},
		{"empty user list", "user-a", "pw-a", []User{}, false},
		{"nil user list", "user-a", "pw-a", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Authenticate(tt.userID, tt.password, tt.users)
			if !tt.wantOK {
				require.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			require.Equal(t, tt.userID, got.UserID)
		})
	}

	t.Run("a password of the maximal length works, a longer one is rejected and not truncated", func(t *testing.T) {
		longest := strings.Repeat("a", MaxPasswordBytes)
		users := []User{{UserID: "long", Password: mustHash(longest), TeamRole: "r"}}

		require.NotNil(t, Authenticate("long", longest, users))
		// bcrypt ignores the bytes beyond the limit, so without the check this would let the user in
		require.Nil(t, Authenticate("long", longest+"b", users))
	})
}
