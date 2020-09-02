/*
 * Monitoring
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package monitoring
// V2CreateAlertConditionRequest struct for V2CreateAlertConditionRequest
type V2CreateAlertConditionRequest struct {
	Metric V2AlertConditionMetric `json:"metric,omitempty"`
	Comparator AlertConditionComparator `json:"comparator,omitempty"`
	// The value to check to determine if an alert should be generated.
	Value string `json:"value,omitempty"`
	// The amount of time to wait before sending an alert.  This is useful to prevent alerts due to a flapping service.
	AlarmDelay int32 `json:"alarmDelay,omitempty"`
	// How often an alert should be generated if an alert condition is still being met.
	AlarmEvery int32 `json:"alarmEvery,omitempty"`
	// A flag that determines if an alert should continue to trigger until it is resolved.
	AlarmUntilSilenced bool `json:"alarmUntilSilenced,omitempty"`
	// Whether an alert condition is enabled or not.
	Enabled bool `json:"enabled,omitempty"`
	// The minimum number of locations that the alert condition must be triggered for before an alert is generated.  This should always be less than or equal to the number of locations a monitor has.
	MinimumLocations int32 `json:"minimumLocations,omitempty"`
}
