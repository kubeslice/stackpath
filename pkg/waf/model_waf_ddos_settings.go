/*
 * Web Application Firewall
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package waf
// WafDdosSettings A WAF site's DDOS protection settings  DDOS protection is activated if at least one of these conditions is met.
type WafDdosSettings struct {
	// The number of overall requests per ten seconds that can trigger DDOS protection
	GlobalThreshold string `json:"globalThreshold,omitempty"`
	// The number of requests per two seconds that can trigger DDOS protection
	BurstThreshold string `json:"burstThreshold,omitempty"`
	// The number of requests per 0.1 seconds that can trigger DDOS protection
	SubSecondBurstThreshold string `json:"subSecondBurstThreshold,omitempty"`
}
