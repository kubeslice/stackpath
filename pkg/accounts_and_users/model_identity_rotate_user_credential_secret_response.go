/*
 * Accounts and Users
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package accounts_and_users
// IdentityRotateUserCredentialSecretResponse A response from a request to generate a new API client secret for a user
type IdentityRotateUserCredentialSecretResponse struct {
	// The API credential's unique identifier
	Id string `json:"id,omitempty"`
	// The API credential's name
	Name string `json:"name,omitempty"`
	// The API credential's OAuth2 client ID
	ClientId string `json:"clientId,omitempty"`
	// The API credential's OAuth2 client secret  The client secret is returned only once and is not stored by StackPath. Please take care to save this response.
	ClientSecret string `json:"clientSecret,omitempty"`
}
