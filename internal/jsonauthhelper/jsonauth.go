package jsonauthhelper

import (
	"encoding/json"
	"os"
	"crypto/subtle"
	"fmt"
)

// User represents a user in the JSON file
type User struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	GivenName string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Nickname  string `json:"nickname"`
	TeamRole string `json:"team_role"`
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
	return users, nil
}

func CheckUserExistance(user_id string, users []User) bool {
	for _, user := range users {
		if user.UserID == user_id {
			return true
		}
	}
	return false
}

func CheckUserPassword(user_id string, password string, users []User) bool {
	for _, user := range users {
		// Check if the user ID matches and compare passwords in constant time
		// to prevent timing attacks
		if user.UserID == user_id && subtle.ConstantTimeCompare([]byte(password), []byte(user.Password)) != 1 {
			return false
		}
	}
	return true
}

func ReturnUserInfo(user_id string, users []User) (*User, error) {
	for _, user := range users {
		// Return the user info if the user ID matches
		if user.UserID == user_id {
			return &user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}