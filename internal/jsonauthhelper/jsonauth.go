package jsonauthhelper

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// User represents a user in the JSON file
type User struct {
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	Password   string `json:"password"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Nickname   string `json:"nickname"`
	TeamRole   string `json:"team_role"`
}

func validateUsers(users []User) error {
	var errs []error
	seen := make(map[string]int, len(users))
	for i, u := range users {

		if u.UserID == "" {
			errs = append(errs, fmt.Errorf("user #%d: user_id is empty", i))
			continue
		}
		if first, dup := seen[u.UserID]; dup {
			errs = append(errs, fmt.Errorf("user %q (#%d): duplicate of user #%d", u.UserID, i, first))
		} else {
			seen[u.UserID] = i
		}
		if u.Password == "" {
			errs = append(errs, fmt.Errorf("user %q: password is empty", u.UserID))
		}
		if u.TeamRole == "" {
			errs = append(errs, fmt.Errorf("user %q: team_role is empty", u.UserID))
		}
	}
	return errors.Join(errs...)
}

func LoadUsersFromFile(filePath string) ([]User, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users []User
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&users); err != nil {
		return nil, err
	}

	if err := validateUsers(users); err != nil {
		return nil, fmt.Errorf("invalid users file: %w", err)
	}

	return users, nil
}

// FindUser returns the user with the given ID, or nil if there is none
func FindUser(userID string, users []User) *User {
	var match *User
	for i := range users {
		if users[i].UserID == userID {
			match = &users[i]
		}
	}
	return match
}

func Authenticate(userID, password string, users []User) *User {
	match := FindUser(userID, users)

	if match == nil {
		return nil
	}

	// Password should not be empty
	if password == "" || match.Password == "" {
		return nil
	}

	if subtle.ConstantTimeCompare([]byte(password), []byte(match.Password)) != 1 {
		return nil
	}

	return match
}
