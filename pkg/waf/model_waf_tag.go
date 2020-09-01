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

// WafTag Aspects of an incoming HTTP request  StackPath provides shortcuts for the rules used in WAF policies for the creation of more complex WAF rules.
type WafTag struct {
	// A tag's name
	Name *string `json:"name,omitempty"`
	// A tag's human readable description
	Description *string `json:"description,omitempty"`
}

// NewWafTag instantiates a new WafTag object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewWafTag() *WafTag {
	this := WafTag{}
	return &this
}

// NewWafTagWithDefaults instantiates a new WafTag object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewWafTagWithDefaults() *WafTag {
	this := WafTag{}
	return &this
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *WafTag) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WafTag) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *WafTag) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *WafTag) SetName(v string) {
	o.Name = &v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *WafTag) GetDescription() string {
	if o == nil || o.Description == nil {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WafTag) GetDescriptionOk() (*string, bool) {
	if o == nil || o.Description == nil {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *WafTag) HasDescription() bool {
	if o != nil && o.Description != nil {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *WafTag) SetDescription(v string) {
	o.Description = &v
}

func (o WafTag) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Name != nil {
		toSerialize["name"] = o.Name
	}
	if o.Description != nil {
		toSerialize["description"] = o.Description
	}
	return json.Marshal(toSerialize)
}

type NullableWafTag struct {
	value *WafTag
	isSet bool
}

func (v NullableWafTag) Get() *WafTag {
	return v.value
}

func (v *NullableWafTag) Set(val *WafTag) {
	v.value = val
	v.isSet = true
}

func (v NullableWafTag) IsSet() bool {
	return v.isSet
}

func (v *NullableWafTag) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableWafTag(val *WafTag) *NullableWafTag {
	return &NullableWafTag{value: val, isSet: true}
}

func (v NullableWafTag) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableWafTag) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
