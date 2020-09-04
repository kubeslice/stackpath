/*
 * Web Application Firewall
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package waf
// RuleActionResultType Results from a WAF event  - RESULT_TYPE_UNSPECIFIED: The event resulted in an unknown action  - BLOCKED: The event was blocked by the WAF  - ALLOWED: The event was allowed by the WAF  - MONITORED: The event was monitored by the WAF but no action was taken
type RuleActionResultType string

// List of RuleActionResultType
const (
	RULEACTIONRESULTTYPE_RESULT_TYPE_UNSPECIFIED RuleActionResultType = "RESULT_TYPE_UNSPECIFIED"
	RULEACTIONRESULTTYPE_BLOCKED RuleActionResultType = "BLOCKED"
	RULEACTIONRESULTTYPE_ALLOWED RuleActionResultType = "ALLOWED"
	RULEACTIONRESULTTYPE_MONITORED RuleActionResultType = "MONITORED"
)
