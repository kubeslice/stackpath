/*
 * Web Application Firewall
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package waf
// ConditionFileExtensionCondition Match the incoming file extension
type ConditionFileExtensionCondition struct {
	// The file extension, with or without a period character, to match against
	FileExtension string `json:"fileExtension,omitempty"`
}
