/*
 * DNS
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package dns
// ZoneBulkCreateOrUpdateZoneRecordsRequest struct for ZoneBulkCreateOrUpdateZoneRecordsRequest
type ZoneBulkCreateOrUpdateZoneRecordsRequest struct {
	// The records to create or update in the DNS zone
	Records []ZoneBulkCreateOrUpdateZoneRecordMessage `json:"records,omitempty"`
}
