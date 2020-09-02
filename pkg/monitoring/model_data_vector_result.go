/*
 * Monitoring
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package monitoring
// DataVectorResult Time series containing a single sample for each time series, all sharing the same timestamp
type DataVectorResult struct {
	// The data points' labels
	Metric map[string]string `json:"metric,omitempty"`
	Value DataValue `json:"value,omitempty"`
}
