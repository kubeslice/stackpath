/*
 * Edge Compute
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge-compute

import (
	"encoding/json"
)

// DataValue An individual metric data point
type DataValue struct {
	// The time that a data point was recorded
	UnixTime *string `json:"unixTime,omitempty"`
	// A data point's value
	Value *string `json:"value,omitempty"`
}

// NewDataValue instantiates a new DataValue object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDataValue() *DataValue {
	this := DataValue{}
	return &this
}

// NewDataValueWithDefaults instantiates a new DataValue object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDataValueWithDefaults() *DataValue {
	this := DataValue{}
	return &this
}

// GetUnixTime returns the UnixTime field value if set, zero value otherwise.
func (o *DataValue) GetUnixTime() string {
	if o == nil || o.UnixTime == nil {
		var ret string
		return ret
	}
	return *o.UnixTime
}

// GetUnixTimeOk returns a tuple with the UnixTime field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DataValue) GetUnixTimeOk() (*string, bool) {
	if o == nil || o.UnixTime == nil {
		return nil, false
	}
	return o.UnixTime, true
}

// HasUnixTime returns a boolean if a field has been set.
func (o *DataValue) HasUnixTime() bool {
	if o != nil && o.UnixTime != nil {
		return true
	}

	return false
}

// SetUnixTime gets a reference to the given string and assigns it to the UnixTime field.
func (o *DataValue) SetUnixTime(v string) {
	o.UnixTime = &v
}

// GetValue returns the Value field value if set, zero value otherwise.
func (o *DataValue) GetValue() string {
	if o == nil || o.Value == nil {
		var ret string
		return ret
	}
	return *o.Value
}

// GetValueOk returns a tuple with the Value field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DataValue) GetValueOk() (*string, bool) {
	if o == nil || o.Value == nil {
		return nil, false
	}
	return o.Value, true
}

// HasValue returns a boolean if a field has been set.
func (o *DataValue) HasValue() bool {
	if o != nil && o.Value != nil {
		return true
	}

	return false
}

// SetValue gets a reference to the given string and assigns it to the Value field.
func (o *DataValue) SetValue(v string) {
	o.Value = &v
}

func (o DataValue) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.UnixTime != nil {
		toSerialize["unixTime"] = o.UnixTime
	}
	if o.Value != nil {
		toSerialize["value"] = o.Value
	}
	return json.Marshal(toSerialize)
}

type NullableDataValue struct {
	value *DataValue
	isSet bool
}

func (v NullableDataValue) Get() *DataValue {
	return v.value
}

func (v *NullableDataValue) Set(val *DataValue) {
	v.value = val
	v.isSet = true
}

func (v NullableDataValue) IsSet() bool {
	return v.isSet
}

func (v *NullableDataValue) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDataValue(val *DataValue) *NullableDataValue {
	return &NullableDataValue{value: val, isSet: true}
}

func (v NullableDataValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDataValue) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
