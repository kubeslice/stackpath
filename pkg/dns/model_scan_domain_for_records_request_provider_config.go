/*
 * DNS
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package dns
// ScanDomainForRecordsRequestProviderConfig Provider-specific configuration needed to scan a domain
type ScanDomainForRecordsRequestProviderConfig struct {
	DnsProvider ZoneDnsProvider `json:"dnsProvider,omitempty"`
	// The username required to authenticate with the DNS provider
	AuthenticationUser string `json:"authenticationUser,omitempty"`
	// The API key or password required to authenticate with the DNS provider
	ApiKey string `json:"apiKey,omitempty"`
}
