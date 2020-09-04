/*
 * Edge Compute
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute

import (
	"encoding/json"
)

// StackpathRpcQuotaFailureAllOf struct for StackpathRpcQuotaFailureAllOf
type StackpathRpcQuotaFailureAllOf struct {
	Violations *[]StackpathRpcQuotaFailureViolation `json:"violations,omitempty"`
}

// NewStackpathRpcQuotaFailureAllOf instantiates a new StackpathRpcQuotaFailureAllOf object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcQuotaFailureAllOf() *StackpathRpcQuotaFailureAllOf {
	this := StackpathRpcQuotaFailureAllOf{}
	return &this
}

// NewStackpathRpcQuotaFailureAllOfWithDefaults instantiates a new StackpathRpcQuotaFailureAllOf object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcQuotaFailureAllOfWithDefaults() *StackpathRpcQuotaFailureAllOf {
	this := StackpathRpcQuotaFailureAllOf{}
	return &this
}

// GetViolations returns the Violations field value if set, zero value otherwise.
func (o *StackpathRpcQuotaFailureAllOf) GetViolations() []StackpathRpcQuotaFailureViolation {
	if o == nil || o.Violations == nil {
		var ret []StackpathRpcQuotaFailureViolation
		return ret
	}
	return *o.Violations
}

// GetViolationsOk returns a tuple with the Violations field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcQuotaFailureAllOf) GetViolationsOk() (*[]StackpathRpcQuotaFailureViolation, bool) {
	if o == nil || o.Violations == nil {
		return nil, false
	}
	return o.Violations, true
}

// HasViolations returns a boolean if a field has been set.
func (o *StackpathRpcQuotaFailureAllOf) HasViolations() bool {
	if o != nil && o.Violations != nil {
		return true
	}

	return false
}

// SetViolations gets a reference to the given []StackpathRpcQuotaFailureViolation and assigns it to the Violations field.
func (o *StackpathRpcQuotaFailureAllOf) SetViolations(v []StackpathRpcQuotaFailureViolation) {
	o.Violations = &v
}

func (o StackpathRpcQuotaFailureAllOf) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Violations != nil {
		toSerialize["violations"] = o.Violations
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathRpcQuotaFailureAllOf struct {
	value *StackpathRpcQuotaFailureAllOf
	isSet bool
}

func (v NullableStackpathRpcQuotaFailureAllOf) Get() *StackpathRpcQuotaFailureAllOf {
	return v.value
}

func (v *NullableStackpathRpcQuotaFailureAllOf) Set(val *StackpathRpcQuotaFailureAllOf) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcQuotaFailureAllOf) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcQuotaFailureAllOf) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcQuotaFailureAllOf(val *StackpathRpcQuotaFailureAllOf) *NullableStackpathRpcQuotaFailureAllOf {
	return &NullableStackpathRpcQuotaFailureAllOf{value: val, isSet: true}
}

func (v NullableStackpathRpcQuotaFailureAllOf) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcQuotaFailureAllOf) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
