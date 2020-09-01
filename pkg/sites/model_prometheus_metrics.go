/*
 * Sites
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sites

import (
	"encoding/json"
)

// PrometheusMetrics A collection of metrics
type PrometheusMetrics struct {
	Status *PrometheusMetricsStatus `json:"status,omitempty"`
	Data *MetricsData `json:"data,omitempty"`
	// The type of error encountered when querying for metrics
	ErrorType *string `json:"errorType,omitempty"`
	// The error encountered when querying for metrics
	Error *string `json:"error,omitempty"`
	// Warnings encountered when querying for metrics
	Warnings *[]string `json:"warnings,omitempty"`
}

// NewPrometheusMetrics instantiates a new PrometheusMetrics object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewPrometheusMetrics() *PrometheusMetrics {
	this := PrometheusMetrics{}
	var status PrometheusMetricsStatus = "SUCCESS"
	this.Status = &status
	return &this
}

// NewPrometheusMetricsWithDefaults instantiates a new PrometheusMetrics object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPrometheusMetricsWithDefaults() *PrometheusMetrics {
	this := PrometheusMetrics{}
	var status PrometheusMetricsStatus = "SUCCESS"
	this.Status = &status
	return &this
}

// GetStatus returns the Status field value if set, zero value otherwise.
func (o *PrometheusMetrics) GetStatus() PrometheusMetricsStatus {
	if o == nil || o.Status == nil {
		var ret PrometheusMetricsStatus
		return ret
	}
	return *o.Status
}

// GetStatusOk returns a tuple with the Status field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PrometheusMetrics) GetStatusOk() (*PrometheusMetricsStatus, bool) {
	if o == nil || o.Status == nil {
		return nil, false
	}
	return o.Status, true
}

// HasStatus returns a boolean if a field has been set.
func (o *PrometheusMetrics) HasStatus() bool {
	if o != nil && o.Status != nil {
		return true
	}

	return false
}

// SetStatus gets a reference to the given PrometheusMetricsStatus and assigns it to the Status field.
func (o *PrometheusMetrics) SetStatus(v PrometheusMetricsStatus) {
	o.Status = &v
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *PrometheusMetrics) GetData() MetricsData {
	if o == nil || o.Data == nil {
		var ret MetricsData
		return ret
	}
	return *o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PrometheusMetrics) GetDataOk() (*MetricsData, bool) {
	if o == nil || o.Data == nil {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *PrometheusMetrics) HasData() bool {
	if o != nil && o.Data != nil {
		return true
	}

	return false
}

// SetData gets a reference to the given MetricsData and assigns it to the Data field.
func (o *PrometheusMetrics) SetData(v MetricsData) {
	o.Data = &v
}

// GetErrorType returns the ErrorType field value if set, zero value otherwise.
func (o *PrometheusMetrics) GetErrorType() string {
	if o == nil || o.ErrorType == nil {
		var ret string
		return ret
	}
	return *o.ErrorType
}

// GetErrorTypeOk returns a tuple with the ErrorType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PrometheusMetrics) GetErrorTypeOk() (*string, bool) {
	if o == nil || o.ErrorType == nil {
		return nil, false
	}
	return o.ErrorType, true
}

// HasErrorType returns a boolean if a field has been set.
func (o *PrometheusMetrics) HasErrorType() bool {
	if o != nil && o.ErrorType != nil {
		return true
	}

	return false
}

// SetErrorType gets a reference to the given string and assigns it to the ErrorType field.
func (o *PrometheusMetrics) SetErrorType(v string) {
	o.ErrorType = &v
}

// GetError returns the Error field value if set, zero value otherwise.
func (o *PrometheusMetrics) GetError() string {
	if o == nil || o.Error == nil {
		var ret string
		return ret
	}
	return *o.Error
}

// GetErrorOk returns a tuple with the Error field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PrometheusMetrics) GetErrorOk() (*string, bool) {
	if o == nil || o.Error == nil {
		return nil, false
	}
	return o.Error, true
}

// HasError returns a boolean if a field has been set.
func (o *PrometheusMetrics) HasError() bool {
	if o != nil && o.Error != nil {
		return true
	}

	return false
}

// SetError gets a reference to the given string and assigns it to the Error field.
func (o *PrometheusMetrics) SetError(v string) {
	o.Error = &v
}

// GetWarnings returns the Warnings field value if set, zero value otherwise.
func (o *PrometheusMetrics) GetWarnings() []string {
	if o == nil || o.Warnings == nil {
		var ret []string
		return ret
	}
	return *o.Warnings
}

// GetWarningsOk returns a tuple with the Warnings field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *PrometheusMetrics) GetWarningsOk() (*[]string, bool) {
	if o == nil || o.Warnings == nil {
		return nil, false
	}
	return o.Warnings, true
}

// HasWarnings returns a boolean if a field has been set.
func (o *PrometheusMetrics) HasWarnings() bool {
	if o != nil && o.Warnings != nil {
		return true
	}

	return false
}

// SetWarnings gets a reference to the given []string and assigns it to the Warnings field.
func (o *PrometheusMetrics) SetWarnings(v []string) {
	o.Warnings = &v
}

func (o PrometheusMetrics) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Status != nil {
		toSerialize["status"] = o.Status
	}
	if o.Data != nil {
		toSerialize["data"] = o.Data
	}
	if o.ErrorType != nil {
		toSerialize["errorType"] = o.ErrorType
	}
	if o.Error != nil {
		toSerialize["error"] = o.Error
	}
	if o.Warnings != nil {
		toSerialize["warnings"] = o.Warnings
	}
	return json.Marshal(toSerialize)
}

type NullablePrometheusMetrics struct {
	value *PrometheusMetrics
	isSet bool
}

func (v NullablePrometheusMetrics) Get() *PrometheusMetrics {
	return v.value
}

func (v *NullablePrometheusMetrics) Set(val *PrometheusMetrics) {
	v.value = val
	v.isSet = true
}

func (v NullablePrometheusMetrics) IsSet() bool {
	return v.isSet
}

func (v *NullablePrometheusMetrics) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullablePrometheusMetrics(val *PrometheusMetrics) *NullablePrometheusMetrics {
	return &NullablePrometheusMetrics{value: val, isSet: true}
}

func (v NullablePrometheusMetrics) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullablePrometheusMetrics) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
