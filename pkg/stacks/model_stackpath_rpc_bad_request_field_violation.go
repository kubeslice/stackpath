/*
 * Stacks
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package stacks

import (
	"encoding/json"
)

// StackpathRpcBadRequestFieldViolation struct for StackpathRpcBadRequestFieldViolation
type StackpathRpcBadRequestFieldViolation struct {
	Field *string `json:"field,omitempty"`
	Description *string `json:"description,omitempty"`
}

// NewStackpathRpcBadRequestFieldViolation instantiates a new StackpathRpcBadRequestFieldViolation object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcBadRequestFieldViolation() *StackpathRpcBadRequestFieldViolation {
	this := StackpathRpcBadRequestFieldViolation{}
	return &this
}

// NewStackpathRpcBadRequestFieldViolationWithDefaults instantiates a new StackpathRpcBadRequestFieldViolation object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcBadRequestFieldViolationWithDefaults() *StackpathRpcBadRequestFieldViolation {
	this := StackpathRpcBadRequestFieldViolation{}
	return &this
}

// GetField returns the Field field value if set, zero value otherwise.
func (o *StackpathRpcBadRequestFieldViolation) GetField() string {
	if o == nil || o.Field == nil {
		var ret string
		return ret
	}
	return *o.Field
}

// GetFieldOk returns a tuple with the Field field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcBadRequestFieldViolation) GetFieldOk() (*string, bool) {
	if o == nil || o.Field == nil {
		return nil, false
	}
	return o.Field, true
}

// HasField returns a boolean if a field has been set.
func (o *StackpathRpcBadRequestFieldViolation) HasField() bool {
	if o != nil && o.Field != nil {
		return true
	}

	return false
}

// SetField gets a reference to the given string and assigns it to the Field field.
func (o *StackpathRpcBadRequestFieldViolation) SetField(v string) {
	o.Field = &v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *StackpathRpcBadRequestFieldViolation) GetDescription() string {
	if o == nil || o.Description == nil {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcBadRequestFieldViolation) GetDescriptionOk() (*string, bool) {
	if o == nil || o.Description == nil {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *StackpathRpcBadRequestFieldViolation) HasDescription() bool {
	if o != nil && o.Description != nil {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *StackpathRpcBadRequestFieldViolation) SetDescription(v string) {
	o.Description = &v
}

func (o StackpathRpcBadRequestFieldViolation) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Field != nil {
		toSerialize["field"] = o.Field
	}
	if o.Description != nil {
		toSerialize["description"] = o.Description
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathRpcBadRequestFieldViolation struct {
	value *StackpathRpcBadRequestFieldViolation
	isSet bool
}

func (v NullableStackpathRpcBadRequestFieldViolation) Get() *StackpathRpcBadRequestFieldViolation {
	return v.value
}

func (v *NullableStackpathRpcBadRequestFieldViolation) Set(val *StackpathRpcBadRequestFieldViolation) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcBadRequestFieldViolation) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcBadRequestFieldViolation) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcBadRequestFieldViolation(val *StackpathRpcBadRequestFieldViolation) *NullableStackpathRpcBadRequestFieldViolation {
	return &NullableStackpathRpcBadRequestFieldViolation{value: val, isSet: true}
}

func (v NullableStackpathRpcBadRequestFieldViolation) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcBadRequestFieldViolation) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
