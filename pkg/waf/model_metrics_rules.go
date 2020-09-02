/*
 * Web Application Firewall
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package waf
// MetricsRules The \"top threats\" metric, the number of events encountered per rule
type MetricsRules struct {
	// The name of the rule
	RuleName string `json:"ruleName,omitempty"`
	// The number of requests the rule analyzed
	Count string `json:"count,omitempty"`
}
