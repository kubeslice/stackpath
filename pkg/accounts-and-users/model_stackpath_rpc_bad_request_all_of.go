/*
 * Accounts and Users
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package accounts-and-users

import (
	"encoding/json"
)

// StackpathRpcBadRequestAllOf struct for StackpathRpcBadRequestAllOf
type StackpathRpcBadRequestAllOf struct {
	FieldViolations *[]StackpathRpcBadRequestFieldViolation `json:"fieldViolations,omitempty"`
}

// NewStackpathRpcBadRequestAllOf instantiates a new StackpathRpcBadRequestAllOf object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcBadRequestAllOf() *StackpathRpcBadRequestAllOf {
	this := StackpathRpcBadRequestAllOf{}
	return &this
}

// NewStackpathRpcBadRequestAllOfWithDefaults instantiates a new StackpathRpcBadRequestAllOf object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcBadRequestAllOfWithDefaults() *StackpathRpcBadRequestAllOf {
	this := StackpathRpcBadRequestAllOf{}
	return &this
}

// GetFieldViolations returns the FieldViolations field value if set, zero value otherwise.
func (o *StackpathRpcBadRequestAllOf) GetFieldViolations() []StackpathRpcBadRequestFieldViolation {
	if o == nil || o.FieldViolations == nil {
		var ret []StackpathRpcBadRequestFieldViolation
		return ret
	}
	return *o.FieldViolations
}

// GetFieldViolationsOk returns a tuple with the FieldViolations field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcBadRequestAllOf) GetFieldViolationsOk() (*[]StackpathRpcBadRequestFieldViolation, bool) {
	if o == nil || o.FieldViolations == nil {
		return nil, false
	}
	return o.FieldViolations, true
}

// HasFieldViolations returns a boolean if a field has been set.
func (o *StackpathRpcBadRequestAllOf) HasFieldViolations() bool {
	if o != nil && o.FieldViolations != nil {
		return true
	}

	return false
}

// SetFieldViolations gets a reference to the given []StackpathRpcBadRequestFieldViolation and assigns it to the FieldViolations field.
func (o *StackpathRpcBadRequestAllOf) SetFieldViolations(v []StackpathRpcBadRequestFieldViolation) {
	o.FieldViolations = &v
}

func (o StackpathRpcBadRequestAllOf) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.FieldViolations != nil {
		toSerialize["fieldViolations"] = o.FieldViolations
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathRpcBadRequestAllOf struct {
	value *StackpathRpcBadRequestAllOf
	isSet bool
}

func (v NullableStackpathRpcBadRequestAllOf) Get() *StackpathRpcBadRequestAllOf {
	return v.value
}

func (v *NullableStackpathRpcBadRequestAllOf) Set(val *StackpathRpcBadRequestAllOf) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcBadRequestAllOf) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcBadRequestAllOf) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcBadRequestAllOf(val *StackpathRpcBadRequestAllOf) *NullableStackpathRpcBadRequestAllOf {
	return &NullableStackpathRpcBadRequestAllOf{value: val, isSet: true}
}

func (v NullableStackpathRpcBadRequestAllOf) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcBadRequestAllOf) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
