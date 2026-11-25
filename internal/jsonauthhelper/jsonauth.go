package jsonauthhelper

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

// MaxPasswordBytes is the longest password bcrypt takes into account, it ignores (or rejects) anything beyond that
const MaxPasswordBytes = 72

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

// HashPassword returns the bcrypt hash of the password, this is what has to be stored in the users file
func HashPassword(password string, cost int) (string, error) {
	if password == "" {
		return "", errors.New("password is empty")
	}
	if len(password) > MaxPasswordBytes {
		return "", fmt.Errorf("password is longer than %d bytes", MaxPasswordBytes)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
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
		} else if _, err := bcrypt.Cost([]byte(u.Password)); err != nil {
			// The value itself is not printed, if it is a plaintext password it must not end up in the logs
			errs = append(errs, fmt.Errorf("user %q: password is not a bcrypt hash", u.UserID))
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

// Authenticate returns the user only if the user exists and the password matches its bcrypt hash
func Authenticate(userID, password string, users []User) *User {
	// Independent of the user, hence it does not tell anything about which users exist
	if password == "" || len(password) > MaxPasswordBytes {
		return nil
	}

	match := FindUser(userID, users)
	if match == nil {
		// Compare against the hash of an existing user and throw the result away, so an unknown user costs as much time
		// as a wrong password and the response time does not reveal which user IDs exist
		if len(users) > 0 {
			_ = bcrypt.CompareHashAndPassword([]byte(users[0].Password), []byte(password))
		}
		return nil
	}

	if err := bcrypt.CompareHashAndPassword([]byte(match.Password), []byte(password)); err != nil {
		return nil
	}

	return match
}
