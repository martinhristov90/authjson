## Simple Vault plugin that uses JSON file as its source of truth
-----

![Vault Logo](https://github.com/hashicorp/vault/raw/f22d202cde2018f9455dec755118a9b84586e082/Vault_PrimaryLogo_Black.png)

### What is it: 
This is a sample project that creates a Vault plugin using the official Hashicorp SDK, implementing JSON file based authentication plugin, similar to what `userpass` auth method provides, but the users are stored in a `json` file.

### Simple diagram:

![Diagram](https://lucid.app/publicSegments/view/65cdaa74-0ec4-4d87-adc1-f65024892f45/image.png)

### Prerequisites:
- Docker (for testing and developing)
- Golang installed locally (for development and building)
- Vault server (CE or Enterprise)

### Usage:
- Clone the repository: `git clone https://github.com/martinhristov90/authjson`.
- Change into its directory: `cd authjson`.
- Create a sample `users.json` file in the root directory of the plugin. The name is configurable via `users_file_path` parameter of the config path.
- Example `users.json`
- Run `./docker-test.sh` command for running a test deployment inside a Docker container, using the Vault's official image.
- Expected output (or similar based on `users.json`file):
    ```
    vault write auth/jsonauth/login password=hashed_password_here username=user-marti
    Key                     Value
    ---                     -----
    token                   h<SNIP>s.CAESIHlAN7sm<SNIP>3UzcwZnpqRFJLbmw
    token_accessor          KG6rv2miL3CZefwZIqUQswsF
    token_duration          1h
    token_renewable         true
    token_policies          ["admin" "default" "test" "test2"]
    identity_policies       []
    policies                ["admin" "default" "test" "test2"]
    token_meta_team_role    admin
    ```

### How to consume this Vault plugin:
- Compile the plugin via `GOOS=linux go build -o vault-auth-jsonauth cmd/jsonauth/main.go` (assuming Linux build)
- Start a Vault server
- Register the compiled binary to the Vault server via following command:
    ```
    vault write sys/plugins/catalog/auth/vault-auth-jsonauth \
    sha_256=$(shasum -a 256 vault-auth-jsonauth | cut -d' ' -f1) \
    command="vault-auth-jsonauth"
    ```
- Enable the plugin at the desired path via following command (usually `jsonauth`):
    ```
    vault auth enable \
    -path="jsonauth" \
    -plugin-name="vault-auth-jsonauth" \
    -plugin-version=0.2.0 \
    plugin
    ```
- Create the desired roles that are allowed to login. Role names should match the `team_role` (the role of the person within the team in the `users.json` file) field. For example:
    ```
    vault write auth/jsonauth/role/core policies=core_policy token_max_ttl=12h token_ttl=1h
    vault write auth/jsonauth/role/backline policies=backline_policy token_max_ttl=3h token_ttl=1h
    vault write auth/jsonauth/role/manager policies=manager_policy token_max_ttl=36h token_ttl=1h
    ```
- Attempt a login via:
    ```
    vault write auth/jsonauth/login password=hashed_password_here username=user-martin
    ```
- Output should be similar to the following:
    ```
    vault write auth/jsonauth/login password=hashed_password_here username=user-martin
    Key                     Value
    ---                     -----
    token                   h<SNIP>s.CAESICRJapqI<SNIP>nTXZwaHN0aTk1UHY
    token_accessor          X2LSpgMjVgla8TxyH4I6sPkh
    token_duration          1h
    token_renewable         true
    token_policies          ["backline_policy" "default"]
    identity_policies       []
    policies                ["backline_policy" "default"]
    token_meta_team_role    backline
    ```
-----
### TODO:
  - [ ] Hash the password of the users + salt
  - [ ] Implement `renew` operation based on user's role
  - [ ] Provide more options for building the plugin via the Makefile
  - [ ] Create more thorough testing
  - [ ] Implement the `-method` option for the Vault binary
### License:
  - [MIT](https://choosealicense.com/licenses/mit/)