/*
 * DNS
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package dns

import (
	"encoding/json"
)

// PrometheusMetricsStatus A metrics query's resulting status
type PrometheusMetricsStatus string

// List of prometheusMetricsStatus
const (
	PROMETHEUSMETRICSSTATUS_SUCCESS PrometheusMetricsStatus = "SUCCESS"
	PROMETHEUSMETRICSSTATUS_ERROR PrometheusMetricsStatus = "ERROR"
)

// Ptr returns reference to prometheusMetricsStatus value
func (v PrometheusMetricsStatus) Ptr() *PrometheusMetricsStatus {
	return &v
}


type NullablePrometheusMetricsStatus struct {
	value *PrometheusMetricsStatus
	isSet bool
}

func (v NullablePrometheusMetricsStatus) Get() *PrometheusMetricsStatus {
	return v.value
}

func (v *NullablePrometheusMetricsStatus) Set(val *PrometheusMetricsStatus) {
	v.value = val
	v.isSet = true
}

func (v NullablePrometheusMetricsStatus) IsSet() bool {
	return v.isSet
}

func (v *NullablePrometheusMetricsStatus) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullablePrometheusMetricsStatus(val *PrometheusMetricsStatus) *NullablePrometheusMetricsStatus {
	return &NullablePrometheusMetricsStatus{value: val, isSet: true}
}

func (v NullablePrometheusMetricsStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullablePrometheusMetricsStatus) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
