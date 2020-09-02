/*
 * Stacks
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package stacks
// StackStackStatus A stack's status
type StackStackStatus string

// List of stackStackStatus
const (
	PENDING StackStackStatus = "PENDING"
	ACTIVE StackStackStatus = "ACTIVE"
	DISABLED StackStackStatus = "DISABLED"
	SUSPENDED StackStackStatus = "SUSPENDED"
	BILLING_SUSPENDED StackStackStatus = "BILLING_SUSPENDED"
	CANCELLED StackStackStatus = "CANCELLED"
	DELETED StackStackStatus = "DELETED"
)
