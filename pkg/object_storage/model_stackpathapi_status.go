/*
 * Object Storage
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package object_storage
// StackpathapiStatus struct for StackpathapiStatus
type StackpathapiStatus struct {
	Code int32 `json:"code,omitempty"`
	Details []ApiStatusDetail `json:"details,omitempty"`
	Message string `json:"message,omitempty"`
}
