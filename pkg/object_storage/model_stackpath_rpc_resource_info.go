/*
 * Object Storage
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package object_storage
// StackpathRpcResourceInfo struct for StackpathRpcResourceInfo
type StackpathRpcResourceInfo struct {
	Type string `json:"@type"`
	ResourceType string `json:"resourceType,omitempty"`
	ResourceName string `json:"resourceName,omitempty"`
	Owner string `json:"owner,omitempty"`
	Description string `json:"description,omitempty"`
}
