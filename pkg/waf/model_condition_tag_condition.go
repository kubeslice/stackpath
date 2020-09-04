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

// ConditionTagCondition Match aspects of an incoming request
type ConditionTagCondition struct {
	// A facet of the incoming request to match against
	Tags *[]string `json:"tags,omitempty"`
}

// NewConditionTagCondition instantiates a new ConditionTagCondition object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewConditionTagCondition() *ConditionTagCondition {
	this := ConditionTagCondition{}
	return &this
}

// NewConditionTagConditionWithDefaults instantiates a new ConditionTagCondition object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewConditionTagConditionWithDefaults() *ConditionTagCondition {
	this := ConditionTagCondition{}
	return &this
}

// GetTags returns the Tags field value if set, zero value otherwise.
func (o *ConditionTagCondition) GetTags() []string {
	if o == nil || o.Tags == nil {
		var ret []string
		return ret
	}
	return *o.Tags
}

// GetTagsOk returns a tuple with the Tags field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ConditionTagCondition) GetTagsOk() (*[]string, bool) {
	if o == nil || o.Tags == nil {
		return nil, false
	}
	return o.Tags, true
}

// HasTags returns a boolean if a field has been set.
func (o *ConditionTagCondition) HasTags() bool {
	if o != nil && o.Tags != nil {
		return true
	}

	return false
}

// SetTags gets a reference to the given []string and assigns it to the Tags field.
func (o *ConditionTagCondition) SetTags(v []string) {
	o.Tags = &v
}

func (o ConditionTagCondition) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Tags != nil {
		toSerialize["tags"] = o.Tags
	}
	return json.Marshal(toSerialize)
}

type NullableConditionTagCondition struct {
	value *ConditionTagCondition
	isSet bool
}

func (v NullableConditionTagCondition) Get() *ConditionTagCondition {
	return v.value
}

func (v *NullableConditionTagCondition) Set(val *ConditionTagCondition) {
	v.value = val
	v.isSet = true
}

func (v NullableConditionTagCondition) IsSet() bool {
	return v.isSet
}

func (v *NullableConditionTagCondition) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableConditionTagCondition(val *ConditionTagCondition) *NullableConditionTagCondition {
	return &NullableConditionTagCondition{value: val, isSet: true}
}

func (v NullableConditionTagCondition) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableConditionTagCondition) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
