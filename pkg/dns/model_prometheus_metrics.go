/*
 * DNS
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package dns
// PrometheusMetrics A collection of metrics
type PrometheusMetrics struct {
	Status PrometheusMetricsStatus `json:"status,omitempty"`
	Data MetricsData `json:"data,omitempty"`
	// The type of error encountered when querying for metrics
	ErrorType string `json:"errorType,omitempty"`
	// The error encountered when querying for metrics
	Error string `json:"error,omitempty"`
	// Warnings encountered when querying for metrics
	Warnings []string `json:"warnings,omitempty"`
}
