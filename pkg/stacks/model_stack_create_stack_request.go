/*
 * Stacks
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package stacks
// StackCreateStackRequest struct for StackCreateStackRequest
type StackCreateStackRequest struct {
	// The ID of the account to create the stack for
	AccountId string `json:"accountId,omitempty"`
	// The StackPath stack's friendly, text-based unique identifier  This can be used in place of a stack's ID in most situations to identify a stack. It can be no larger than 30 characters, each being a lowercase letter, number, or dash. It also cannot start with a dash, end with a dash, or have consecutive dashes.If this value is not present, it is derived from the name. This value cannot be updated.
	Slug string `json:"slug,omitempty"`
	// The stack's name
	Name string `json:"name,omitempty"`
}
