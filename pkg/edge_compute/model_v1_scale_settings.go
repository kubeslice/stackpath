/*
 * Edge Compute
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute
// V1ScaleSettings struct for V1ScaleSettings
type V1ScaleSettings struct {
	// Metrics to observe for invoking scaling events.
	Metrics []V1MetricSpec `json:"metrics,omitempty"`
}
