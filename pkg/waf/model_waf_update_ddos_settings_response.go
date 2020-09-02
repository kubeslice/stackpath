/*
 * Web Application Firewall
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package waf
// WafUpdateDdosSettingsResponse A response from a request to update a WAF site's DDOS protection settings
type WafUpdateDdosSettingsResponse struct {
	DdosSettings WafDdosSettings `json:"ddosSettings,omitempty"`
}
