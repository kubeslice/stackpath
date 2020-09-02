/*
 * Web Application Firewall
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package waf
// WafRequestDetailsNetwork A WAF request's network related aspects
type WafRequestDetailsNetwork struct {
	// The originating IP address
	ClientIp string `json:"clientIp,omitempty"`
	// The ISO 3166-1 alpha-2 code of the country where the request originated from
	Country string `json:"country,omitempty"`
	Organization NetworkOrganization `json:"organization,omitempty"`
}
