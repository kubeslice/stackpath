/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// StackpathRpcBadRequest struct for StackpathRpcBadRequest
type StackpathRpcBadRequest struct {
	Type string `json:"@type"`
	FieldViolations []StackpathRpcBadRequestFieldViolation `json:"fieldViolations,omitempty"`
}
