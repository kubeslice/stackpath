/*
 * Accounts and Users
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package accounts_and_users
// IdentityCreateUserCredentialResponse A response from a request to create new user API credentials
type IdentityCreateUserCredentialResponse struct {
	// The new API credential's unique identifier
	Id string `json:"id,omitempty"`
	// The new API credential's name
	Name string `json:"name,omitempty"`
	// The new API credential's OAuth2 client ID
	ClientId string `json:"clientId,omitempty"`
	// The new API credential's OAuth2 client secret  The client secret is returned only once and is not stored by StackPath. Please take care to save this response.
	ClientSecret string `json:"clientSecret,omitempty"`
}
