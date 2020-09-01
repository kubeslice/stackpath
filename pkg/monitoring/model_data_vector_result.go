/*
 * Monitoring
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package monitoring

import (
	"encoding/json"
)

// DataVectorResult Time series containing a single sample for each time series, all sharing the same timestamp
type DataVectorResult struct {
	// The data points' labels
	Metric *map[string]string `json:"metric,omitempty"`
	Value *DataValue `json:"value,omitempty"`
}

// NewDataVectorResult instantiates a new DataVectorResult object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDataVectorResult() *DataVectorResult {
	this := DataVectorResult{}
	return &this
}

// NewDataVectorResultWithDefaults instantiates a new DataVectorResult object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDataVectorResultWithDefaults() *DataVectorResult {
	this := DataVectorResult{}
	return &this
}

// GetMetric returns the Metric field value if set, zero value otherwise.
func (o *DataVectorResult) GetMetric() map[string]string {
	if o == nil || o.Metric == nil {
		var ret map[string]string
		return ret
	}
	return *o.Metric
}

// GetMetricOk returns a tuple with the Metric field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DataVectorResult) GetMetricOk() (*map[string]string, bool) {
	if o == nil || o.Metric == nil {
		return nil, false
	}
	return o.Metric, true
}

// HasMetric returns a boolean if a field has been set.
func (o *DataVectorResult) HasMetric() bool {
	if o != nil && o.Metric != nil {
		return true
	}

	return false
}

// SetMetric gets a reference to the given map[string]string and assigns it to the Metric field.
func (o *DataVectorResult) SetMetric(v map[string]string) {
	o.Metric = &v
}

// GetValue returns the Value field value if set, zero value otherwise.
func (o *DataVectorResult) GetValue() DataValue {
	if o == nil || o.Value == nil {
		var ret DataValue
		return ret
	}
	return *o.Value
}

// GetValueOk returns a tuple with the Value field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DataVectorResult) GetValueOk() (*DataValue, bool) {
	if o == nil || o.Value == nil {
		return nil, false
	}
	return o.Value, true
}

// HasValue returns a boolean if a field has been set.
func (o *DataVectorResult) HasValue() bool {
	if o != nil && o.Value != nil {
		return true
	}

	return false
}

// SetValue gets a reference to the given DataValue and assigns it to the Value field.
func (o *DataVectorResult) SetValue(v DataValue) {
	o.Value = &v
}

func (o DataVectorResult) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Metric != nil {
		toSerialize["metric"] = o.Metric
	}
	if o.Value != nil {
		toSerialize["value"] = o.Value
	}
	return json.Marshal(toSerialize)
}

type NullableDataVectorResult struct {
	value *DataVectorResult
	isSet bool
}

func (v NullableDataVectorResult) Get() *DataVectorResult {
	return v.value
}

func (v *NullableDataVectorResult) Set(val *DataVectorResult) {
	v.value = val
	v.isSet = true
}

func (v NullableDataVectorResult) IsSet() bool {
	return v.isSet
}

func (v *NullableDataVectorResult) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDataVectorResult(val *DataVectorResult) *NullableDataVectorResult {
	return &NullableDataVectorResult{value: val, isSet: true}
}

func (v NullableDataVectorResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDataVectorResult) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
