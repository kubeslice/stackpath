/*
 * DNS
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package dns
// ZoneGetZoneRecordsResponse A response from a request to retrieve a DNS zone's resource records
type ZoneGetZoneRecordsResponse struct {
	PageInfo PaginationPageInfo `json:"pageInfo,omitempty"`
	// The requested resource records
	Records []ZoneZoneRecord `json:"records,omitempty"`
}
