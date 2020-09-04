/*
 * Accounts and Users
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package accounts_and_users

import (
	"encoding/json"
)

// StackpathRpcPreconditionFailureAllOf struct for StackpathRpcPreconditionFailureAllOf
type StackpathRpcPreconditionFailureAllOf struct {
	Violations *[]StackpathRpcPreconditionFailureViolation `json:"violations,omitempty"`
}

// NewStackpathRpcPreconditionFailureAllOf instantiates a new StackpathRpcPreconditionFailureAllOf object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcPreconditionFailureAllOf() *StackpathRpcPreconditionFailureAllOf {
	this := StackpathRpcPreconditionFailureAllOf{}
	return &this
}

// NewStackpathRpcPreconditionFailureAllOfWithDefaults instantiates a new StackpathRpcPreconditionFailureAllOf object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcPreconditionFailureAllOfWithDefaults() *StackpathRpcPreconditionFailureAllOf {
	this := StackpathRpcPreconditionFailureAllOf{}
	return &this
}

// GetViolations returns the Violations field value if set, zero value otherwise.
func (o *StackpathRpcPreconditionFailureAllOf) GetViolations() []StackpathRpcPreconditionFailureViolation {
	if o == nil || o.Violations == nil {
		var ret []StackpathRpcPreconditionFailureViolation
		return ret
	}
	return *o.Violations
}

// GetViolationsOk returns a tuple with the Violations field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcPreconditionFailureAllOf) GetViolationsOk() (*[]StackpathRpcPreconditionFailureViolation, bool) {
	if o == nil || o.Violations == nil {
		return nil, false
	}
	return o.Violations, true
}

// HasViolations returns a boolean if a field has been set.
func (o *StackpathRpcPreconditionFailureAllOf) HasViolations() bool {
	if o != nil && o.Violations != nil {
		return true
	}

	return false
}

// SetViolations gets a reference to the given []StackpathRpcPreconditionFailureViolation and assigns it to the Violations field.
func (o *StackpathRpcPreconditionFailureAllOf) SetViolations(v []StackpathRpcPreconditionFailureViolation) {
	o.Violations = &v
}

func (o StackpathRpcPreconditionFailureAllOf) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Violations != nil {
		toSerialize["violations"] = o.Violations
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathRpcPreconditionFailureAllOf struct {
	value *StackpathRpcPreconditionFailureAllOf
	isSet bool
}

func (v NullableStackpathRpcPreconditionFailureAllOf) Get() *StackpathRpcPreconditionFailureAllOf {
	return v.value
}

func (v *NullableStackpathRpcPreconditionFailureAllOf) Set(val *StackpathRpcPreconditionFailureAllOf) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcPreconditionFailureAllOf) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcPreconditionFailureAllOf) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcPreconditionFailureAllOf(val *StackpathRpcPreconditionFailureAllOf) *NullableStackpathRpcPreconditionFailureAllOf {
	return &NullableStackpathRpcPreconditionFailureAllOf{value: val, isSet: true}
}

func (v NullableStackpathRpcPreconditionFailureAllOf) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcPreconditionFailureAllOf) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
