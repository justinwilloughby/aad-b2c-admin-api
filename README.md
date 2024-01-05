# Azure AD B2C Admin API

API wrapper around the Microsoft Graph API to manage a B2C directory.

API is written in Go using the Gin library and Microsoft Graph SDK

Dockerfile included to build an image to run it. Multistage build to minimize image size. Go build and module caching to improve local docker build speeds.

Kubernetes yamls included to do a deployment locally with the Microsoft Graph API secrets injected from HashiCorp Vault via the Vault Agent Init Container method. Service included in deployment to expose the API externally on port 8081. Expects external local Vault instance with Kubernetes auth method configured, secrets created, policy create for the secrets.

Can include a local secrets/config.txt file to run the API locally with "go run main.go true" and the argument true lets the program know that it should load your secrets from the local filesystem.

## API Features

### User Administration

Create - POST /users

Read - GET /users/:id

Update - PATCH /users/:id

Delete - DELETE /users/:id

List - Get /users