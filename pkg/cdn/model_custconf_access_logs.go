/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// CustconfAccessLogs Enable/Disable access logs
type CustconfAccessLogs struct {
	// This is used by the API to perform conflict checking
	Id string `json:"id,omitempty"`
	Enabled bool `json:"enabled,omitempty"`
}
