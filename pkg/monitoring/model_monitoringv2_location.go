/*
 * Monitoring
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package monitoring
// Monitoringv2Location A location which performs monitoring checks.
type Monitoringv2Location struct {
	// A location's unique identifier
	Id string `json:"id,omitempty"`
	// A location's name
	Name string `json:"name,omitempty"`
	// A location's city
	City string `json:"city,omitempty"`
	// A location's city, expressed as an IATA airport code
	CityCode string `json:"cityCode,omitempty"`
	// A location's country
	Country string `json:"country,omitempty"`
	// A location's ISO-3166-1 alpha-2 country code
	CountryCode string `json:"countryCode,omitempty"`
	// A location's network provider
	Provider string `json:"provider,omitempty"`
	// The IP addresses of a location  The IP addresses where monitoring checks originate from.
	IpAddresses []string `json:"ipAddresses,omitempty"`
	// Whether or not a location supports IPv4 monitoring checks.
	HasIpv4 bool `json:"hasIpv4,omitempty"`
	// Whether or not a location supports IPv6 monitoring checks.
	HasIpv6 bool `json:"hasIpv6,omitempty"`
}
