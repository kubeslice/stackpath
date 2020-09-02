/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// GetMetricsResponseMetricSeries A series of analytics data suitable for a graph
type GetMetricsResponseMetricSeries struct {
	// The type of data in the analytics set
	Type string `json:"type,omitempty"`
	// A graphable key for the type of data in the analytics set
	Key string `json:"key,omitempty"`
	// Descriptions of the CDN metrics' samples
	Metrics []string `json:"metrics,omitempty"`
	// The CDN metrics' data points
	Samples []GetMetricsResponseMetricSample `json:"samples,omitempty"`
}
