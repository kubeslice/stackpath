/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// CdnPurgeContentRequest struct for CdnPurgeContentRequest
type CdnPurgeContentRequest struct {
	// The items to purge from the CDN
	Items []PurgeContentRequestItem `json:"items,omitempty"`
}
