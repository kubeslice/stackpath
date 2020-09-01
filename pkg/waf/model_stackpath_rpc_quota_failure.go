/*
 * Web Application Firewall
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package waf

import (
	"encoding/json"
)

// StackpathRpcQuotaFailure struct for StackpathRpcQuotaFailure
type StackpathRpcQuotaFailure struct {
	ApiStatusDetail
	Violations *[]StackpathRpcQuotaFailureViolation `json:"violations,omitempty"`
}

// NewStackpathRpcQuotaFailure instantiates a new StackpathRpcQuotaFailure object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcQuotaFailure() *StackpathRpcQuotaFailure {
	this := StackpathRpcQuotaFailure{}
	return &this
}

// NewStackpathRpcQuotaFailureWithDefaults instantiates a new StackpathRpcQuotaFailure object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcQuotaFailureWithDefaults() *StackpathRpcQuotaFailure {
	this := StackpathRpcQuotaFailure{}
	return &this
}

// GetViolations returns the Violations field value if set, zero value otherwise.
func (o *StackpathRpcQuotaFailure) GetViolations() []StackpathRpcQuotaFailureViolation {
	if o == nil || o.Violations == nil {
		var ret []StackpathRpcQuotaFailureViolation
		return ret
	}
	return *o.Violations
}

// GetViolationsOk returns a tuple with the Violations field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcQuotaFailure) GetViolationsOk() (*[]StackpathRpcQuotaFailureViolation, bool) {
	if o == nil || o.Violations == nil {
		return nil, false
	}
	return o.Violations, true
}

// HasViolations returns a boolean if a field has been set.
func (o *StackpathRpcQuotaFailure) HasViolations() bool {
	if o != nil && o.Violations != nil {
		return true
	}

	return false
}

// SetViolations gets a reference to the given []StackpathRpcQuotaFailureViolation and assigns it to the Violations field.
func (o *StackpathRpcQuotaFailure) SetViolations(v []StackpathRpcQuotaFailureViolation) {
	o.Violations = &v
}

func (o StackpathRpcQuotaFailure) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	serializedApiStatusDetail, errApiStatusDetail := json.Marshal(o.ApiStatusDetail)
	if errApiStatusDetail != nil {
		return []byte{}, errApiStatusDetail
	}
	errApiStatusDetail = json.Unmarshal([]byte(serializedApiStatusDetail), &toSerialize)
	if errApiStatusDetail != nil {
		return []byte{}, errApiStatusDetail
	}
	if o.Violations != nil {
		toSerialize["violations"] = o.Violations
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathRpcQuotaFailure struct {
	value *StackpathRpcQuotaFailure
	isSet bool
}

func (v NullableStackpathRpcQuotaFailure) Get() *StackpathRpcQuotaFailure {
	return v.value
}

func (v *NullableStackpathRpcQuotaFailure) Set(val *StackpathRpcQuotaFailure) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcQuotaFailure) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcQuotaFailure) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcQuotaFailure(val *StackpathRpcQuotaFailure) *NullableStackpathRpcQuotaFailure {
	return &NullableStackpathRpcQuotaFailure{value: val, isSet: true}
}

func (v NullableStackpathRpcQuotaFailure) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcQuotaFailure) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
