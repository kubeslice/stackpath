/*
 * Edge Compute
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute
// ContainerStatusWaiting Properties related to containers that are starting up
type ContainerStatusWaiting struct {
	// The reason that a container is waiting to start
	Reason string `json:"reason,omitempty"`
	// A more detailed explanation of a container's waiting state
	Message string `json:"message,omitempty"`
}
