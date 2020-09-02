/*
 * Edge Compute
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute
import (
	"time"
)
// V1ImageCondition Further information about an image's status
type V1ImageCondition struct {
	// Type of the condition
	Type string `json:"type,omitempty"`
	Status V1ImageConditionStatus `json:"status,omitempty"`
	// The last time the condition was checked
	CheckedAt time.Time `json:"checkedAt,omitempty"`
	// The last time the condition transitioned status
	TransitionedAt time.Time `json:"transitionedAt,omitempty"`
	// A stable identifier for the reason the condition is in its current state
	Reason string `json:"reason,omitempty"`
	// A human readable message with details regarding the condition
	Message string `json:"message,omitempty"`
}
