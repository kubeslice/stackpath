/*
 * Accounts and Users
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package accounts_and_users
// StackpathRpcLocalizedMessage struct for StackpathRpcLocalizedMessage
type StackpathRpcLocalizedMessage struct {
	Type string `json:"@type"`
	Locale string `json:"locale,omitempty"`
	Message string `json:"message,omitempty"`
}
