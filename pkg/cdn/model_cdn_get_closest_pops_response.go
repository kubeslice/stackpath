/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// CdnGetClosestPopsResponse The response from a request to scan a URL from the StackPath edge network
type CdnGetClosestPopsResponse struct {
	// Results of the scan
	Result []CdnPopScanReport `json:"result,omitempty"`
}
