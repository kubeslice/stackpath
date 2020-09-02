/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// CdnGetPopsResponse The response from a request to retrieve the StackPath's points of presence
type CdnGetPopsResponse struct {
	PageInfo PaginationPageInfo `json:"pageInfo,omitempty"`
	// The requested StackPath points of presence
	Results []CdnPop `json:"results,omitempty"`
}
