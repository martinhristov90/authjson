package authjson

import (
	"context"
	"reflect"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/martinhristov90/authjson/internal/jsonauthhelper"
)

const (
	configHelpSynopsis    = `Configure the JSON Auth plugin by specifying the path to the JSON file containing user credentials.`
	configHelpDescription = `
	The JSON Auth plugin requires a configuration step to specify the path to the JSON file that contains user credentials.
	This configuration is essential for the plugin to function correctly, as it relies on this file to authenticate users.
	`
	configPath = "config"
)

// Structure to hold the configuration data, for storing in Vault's storage backend. In the future, more configuration options can be added here as needed.
type jsonAuthConfig struct {
	UsersFilePath string `json:"users_file_path"`
}

func (b *backend) PathConfig() *framework.Path {
	return &framework.Path{ // Setting the path pattern to "config"
		Pattern: "config", // This is the path where the configuration will be read/written, it is simply named "config"
		Fields: map[string]*framework.FieldSchema{ // Defining the fields for this path
			"users_file_path": { // Defining the field for the users file path
				Type:        framework.TypeString, // The type of this field is string
				Description: "Path to the JSON file containing user credentials.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{ // Defining the operations for this path
			logical.UpdateOperation: &framework.PathOperation{
				Callback:    b.pathConfigWrite, // Callback function for handling write operations
				Description: "Writes path to the JSON file containing user credentials.",
				DisplayAttrs: &framework.DisplayAttributes{ // This is shown in path-help output
					Description: "Update the users file path.",
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback:    b.pathConfigRead,
				Description: "Reads path to the JSON file containing user credentials.",
				DisplayAttrs: &framework.DisplayAttributes{ // This is shown in path-help output
					Description: "Read the users file path.",
				},
			},
		},
		HelpSynopsis:    configHelpSynopsis,
		HelpDescription: configHelpDescription,
	}
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	usersFilePath := d.Get("users_file_path").(string) // Extracting the users_file_path from the request data
	if usersFilePath == "" {
		return logical.ErrorResponse("users_file_path is required"), logical.ErrInvalidRequest
	}

	// Checking if we actually can read the file, if not we error
	if _, err := jsonauthhelper.LoadUsersFromFile(usersFilePath); err != nil {
		return logical.ErrorResponse("cannot load users from %q: %v", usersFilePath, err), nil
	}

	// Creating the config struct to store the configuration entry in JSON format
	config := &jsonAuthConfig{
		UsersFilePath: usersFilePath,
	}

	// Creating a storage entry for the configuration data in JSON format
	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return logical.ErrorResponse("failed to create storage entry: %v", err), err
	}

	// Writing the configuration entry to storage backend
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return logical.ErrorResponse("failed write configuration to storage: %v", err), err
	}

	// Returning nil response and nil error on successful write
	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	// Retrieving the configuration entry from storage backend
	// Configpath is a constant defined earlier as "config"
	entry, err := req.Storage.Get(ctx, configPath)
	if err != nil {
		return logical.ErrorResponse("failed to read configuration from storage: %v", err), err
	}
	// If configuration is not found, return an error response
	if entry == nil {
		return logical.ErrorResponse("configuration not found"), logical.ErrInvalidRequest
	}

	// A structure that will hold the decoded configuration data
	var config jsonAuthConfig

	// Decoding the JSON configuration data from the storage entry and populating the config struct
	if err := entry.DecodeJSON(&config); err != nil {
		return logical.ErrorResponse("failed to decode configuration: %v", err), err
	}

	// Using the reflect package to get the name of tag in the jsonAuthConfig struct in case we change it later. It could simply be:
	//	"users_file_path" string
	cnf := reflect.TypeOf(config)
	field, _ := cnf.FieldByName("UsersFilePath")
	jsonTagConfig := field.Tag.Get("json")

	// Preparing the response with the configuration data to be returned to the caller
	resp := &logical.Response{
		Data: map[string]interface{}{
			// "users_file_path": config.UsersFilePath as simple as that
			jsonTagConfig: config.UsersFilePath,
		},
	}

	// Returning a logical response containing the configuration data
	return resp, nil

}
