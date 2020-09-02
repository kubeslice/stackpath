/*
 * DNS
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package dns
// ZoneUpdateZoneMessage struct for ZoneUpdateZoneMessage
type ZoneUpdateZoneMessage struct {
	// A key/value pair of user-defined labels for a DNS zone  Zone labels are not processed by StackPath and are solely used for users to organize their DNS zones.
	Labels map[string]string `json:"labels,omitempty"`
}
