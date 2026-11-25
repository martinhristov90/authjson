package jsonauthhelper

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadUsersFromFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantLen int
		// wantErr lists substrings that must all be part of the error, empty means no error is expected
		wantErr []string
	}{
		{"valid", `[{"user_id":"a","password":"p","team_role":"r"}]`, 1, nil},
		{"valid with two users", `[{"user_id":"a","password":"p","team_role":"r"},{"user_id":"b","password":"p","team_role":"r"}]`, 2, nil},
		{"empty array", `[]`, 0, nil},
		{"truncated JSON", `[{"user_id":"a"`, 0, []string{"unexpected EOF"}},
		{"empty file", ``, 0, []string{"EOF"}},
		{"wrong shape", `{"user_id":"a"}`, 0, []string{"cannot unmarshal"}},
		{
			"duplicate user ID",
			`[{"user_id":"a","password":"p","team_role":"r"},{"user_id":"a","password":"q","team_role":"r"}]`,
			0, []string{`user "a" (#1): duplicate of user #0`},
		},
		{
			"user ID is case sensitive so these are not duplicates",
			`[{"user_id":"a","password":"p","team_role":"r"},{"user_id":"A","password":"p","team_role":"r"}]`,
			2, nil,
		},
		{"empty user ID", `[{"user_id":"","password":"p","team_role":"r"}]`, 0, []string{"user #0: user_id is empty"}},
		{"missing user ID", `[{"password":"p","team_role":"r"}]`, 0, []string{"user #0: user_id is empty"}},
		{"empty password", `[{"user_id":"a","password":"","team_role":"r"}]`, 0, []string{`user "a": password is empty`}},
		{"missing password", `[{"user_id":"a","team_role":"r"}]`, 0, []string{`user "a": password is empty`}},
		{"empty team role", `[{"user_id":"a","password":"p","team_role":""}]`, 0, []string{`user "a": team_role is empty`}},
		{"misspelled team role", `[{"user_id":"a","password":"p","team_roles":"r"}]`, 0, []string{`user "a": team_role is empty`}},
		{
			"all problems are reported at once",
			`[{"user_id":"a","password":"","team_role":"r"},{"user_id":"a","password":"p","team_role":""},{"password":"p","team_role":"r"}]`,
			0,
			[]string{
				`user "a": password is empty`,
				`user "a" (#1): duplicate of user #0`,
				`user "a": team_role is empty`,
				"user #2: user_id is empty",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))

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
		require.NotContains(t, err.Error(), "s3cret-value")
	})

	t.Run("the integration test data is valid", func(t *testing.T) {
		users, err := LoadUsersFromFile("../../integration_test_data/users.json")
		require.NoError(t, err)
		require.NotEmpty(t, users)
	})
}

var testUsers = []User{
	{UserID: "user-a", Password: "pw-a", TeamRole: "backline"},
	{UserID: "user-b", Password: "pw-b", TeamRole: "core"},
	{UserID: "user-nopass", Password: "", TeamRole: "core"},
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
		{"unknown user", "user-x", "pw-a", testUsers, false},
		{"empty user ID and password", "", "", testUsers, false},
		{"empty password", "user-a", "", testUsers, false},
		{"user with empty stored password and empty input", "user-nopass", "", testUsers, false},
		{"user with empty stored password and some input", "user-nopass", "anything", testUsers, false},
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
}
