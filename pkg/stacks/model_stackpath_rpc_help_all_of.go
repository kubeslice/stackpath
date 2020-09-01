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

// StackpathRpcHelpAllOf struct for StackpathRpcHelpAllOf
type StackpathRpcHelpAllOf struct {
	Links *[]StackpathRpcHelpLink `json:"links,omitempty"`
}

// NewStackpathRpcHelpAllOf instantiates a new StackpathRpcHelpAllOf object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcHelpAllOf() *StackpathRpcHelpAllOf {
	this := StackpathRpcHelpAllOf{}
	return &this
}

// NewStackpathRpcHelpAllOfWithDefaults instantiates a new StackpathRpcHelpAllOf object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcHelpAllOfWithDefaults() *StackpathRpcHelpAllOf {
	this := StackpathRpcHelpAllOf{}
	return &this
}

// GetLinks returns the Links field value if set, zero value otherwise.
func (o *StackpathRpcHelpAllOf) GetLinks() []StackpathRpcHelpLink {
	if o == nil || o.Links == nil {
		var ret []StackpathRpcHelpLink
		return ret
	}
	return *o.Links
}

// GetLinksOk returns a tuple with the Links field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcHelpAllOf) GetLinksOk() (*[]StackpathRpcHelpLink, bool) {
	if o == nil || o.Links == nil {
		return nil, false
	}
	return o.Links, true
}

// HasLinks returns a boolean if a field has been set.
func (o *StackpathRpcHelpAllOf) HasLinks() bool {
	if o != nil && o.Links != nil {
		return true
	}

	return false
}

// SetLinks gets a reference to the given []StackpathRpcHelpLink and assigns it to the Links field.
func (o *StackpathRpcHelpAllOf) SetLinks(v []StackpathRpcHelpLink) {
	o.Links = &v
}

func (o StackpathRpcHelpAllOf) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Links != nil {
		toSerialize["links"] = o.Links
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathRpcHelpAllOf struct {
	value *StackpathRpcHelpAllOf
	isSet bool
}

func (v NullableStackpathRpcHelpAllOf) Get() *StackpathRpcHelpAllOf {
	return v.value
}

func (v *NullableStackpathRpcHelpAllOf) Set(val *StackpathRpcHelpAllOf) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcHelpAllOf) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcHelpAllOf) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcHelpAllOf(val *StackpathRpcHelpAllOf) *NullableStackpathRpcHelpAllOf {
	return &NullableStackpathRpcHelpAllOf{value: val, isSet: true}
}

func (v NullableStackpathRpcHelpAllOf) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcHelpAllOf) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
