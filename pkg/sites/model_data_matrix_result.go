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

// DataMatrixResult Time series containing a range of data points over time for each time series
type DataMatrixResult struct {
	// The data points' labels
	Metric *map[string]string `json:"metric,omitempty"`
	// Time series data point values
	Values *[]MetricsDataValue `json:"values,omitempty"`
}

// NewDataMatrixResult instantiates a new DataMatrixResult object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDataMatrixResult() *DataMatrixResult {
	this := DataMatrixResult{}
	return &this
}

// NewDataMatrixResultWithDefaults instantiates a new DataMatrixResult object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDataMatrixResultWithDefaults() *DataMatrixResult {
	this := DataMatrixResult{}
	return &this
}

// GetMetric returns the Metric field value if set, zero value otherwise.
func (o *DataMatrixResult) GetMetric() map[string]string {
	if o == nil || o.Metric == nil {
		var ret map[string]string
		return ret
	}
	return *o.Metric
}

// GetMetricOk returns a tuple with the Metric field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DataMatrixResult) GetMetricOk() (*map[string]string, bool) {
	if o == nil || o.Metric == nil {
		return nil, false
	}
	return o.Metric, true
}

// HasMetric returns a boolean if a field has been set.
func (o *DataMatrixResult) HasMetric() bool {
	if o != nil && o.Metric != nil {
		return true
	}

	return false
}

// SetMetric gets a reference to the given map[string]string and assigns it to the Metric field.
func (o *DataMatrixResult) SetMetric(v map[string]string) {
	o.Metric = &v
}

// GetValues returns the Values field value if set, zero value otherwise.
func (o *DataMatrixResult) GetValues() []MetricsDataValue {
	if o == nil || o.Values == nil {
		var ret []MetricsDataValue
		return ret
	}
	return *o.Values
}

// GetValuesOk returns a tuple with the Values field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DataMatrixResult) GetValuesOk() (*[]MetricsDataValue, bool) {
	if o == nil || o.Values == nil {
		return nil, false
	}
	return o.Values, true
}

// HasValues returns a boolean if a field has been set.
func (o *DataMatrixResult) HasValues() bool {
	if o != nil && o.Values != nil {
		return true
	}

	return false
}

// SetValues gets a reference to the given []MetricsDataValue and assigns it to the Values field.
func (o *DataMatrixResult) SetValues(v []MetricsDataValue) {
	o.Values = &v
}

func (o DataMatrixResult) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Metric != nil {
		toSerialize["metric"] = o.Metric
	}
	if o.Values != nil {
		toSerialize["values"] = o.Values
	}
	return json.Marshal(toSerialize)
}

type NullableDataMatrixResult struct {
	value *DataMatrixResult
	isSet bool
}

func (v NullableDataMatrixResult) Get() *DataMatrixResult {
	return v.value
}

func (v *NullableDataMatrixResult) Set(val *DataMatrixResult) {
	v.value = val
	v.isSet = true
}

func (v NullableDataMatrixResult) IsSet() bool {
	return v.isSet
}

func (v *NullableDataMatrixResult) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDataMatrixResult(val *DataMatrixResult) *NullableDataMatrixResult {
	return &NullableDataMatrixResult{value: val, isSet: true}
}

func (v NullableDataMatrixResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDataMatrixResult) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
