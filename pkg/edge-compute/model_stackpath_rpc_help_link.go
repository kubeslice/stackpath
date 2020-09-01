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

// StackpathRpcHelpLink struct for StackpathRpcHelpLink
type StackpathRpcHelpLink struct {
	Description *string `json:"description,omitempty"`
	Url *string `json:"url,omitempty"`
}

// NewStackpathRpcHelpLink instantiates a new StackpathRpcHelpLink object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcHelpLink() *StackpathRpcHelpLink {
	this := StackpathRpcHelpLink{}
	return &this
}

// NewStackpathRpcHelpLinkWithDefaults instantiates a new StackpathRpcHelpLink object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcHelpLinkWithDefaults() *StackpathRpcHelpLink {
	this := StackpathRpcHelpLink{}
	return &this
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *StackpathRpcHelpLink) GetDescription() string {
	if o == nil || o.Description == nil {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcHelpLink) GetDescriptionOk() (*string, bool) {
	if o == nil || o.Description == nil {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *StackpathRpcHelpLink) HasDescription() bool {
	if o != nil && o.Description != nil {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *StackpathRpcHelpLink) SetDescription(v string) {
	o.Description = &v
}

// GetUrl returns the Url field value if set, zero value otherwise.
func (o *StackpathRpcHelpLink) GetUrl() string {
	if o == nil || o.Url == nil {
		var ret string
		return ret
	}
	return *o.Url
}

// GetUrlOk returns a tuple with the Url field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcHelpLink) GetUrlOk() (*string, bool) {
	if o == nil || o.Url == nil {
		return nil, false
	}
	return o.Url, true
}

// HasUrl returns a boolean if a field has been set.
func (o *StackpathRpcHelpLink) HasUrl() bool {
	if o != nil && o.Url != nil {
		return true
	}

	return false
}

// SetUrl gets a reference to the given string and assigns it to the Url field.
func (o *StackpathRpcHelpLink) SetUrl(v string) {
	o.Url = &v
}

func (o StackpathRpcHelpLink) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Description != nil {
		toSerialize["description"] = o.Description
	}
	if o.Url != nil {
		toSerialize["url"] = o.Url
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathRpcHelpLink struct {
	value *StackpathRpcHelpLink
	isSet bool
}

func (v NullableStackpathRpcHelpLink) Get() *StackpathRpcHelpLink {
	return v.value
}

func (v *NullableStackpathRpcHelpLink) Set(val *StackpathRpcHelpLink) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcHelpLink) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcHelpLink) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcHelpLink(val *StackpathRpcHelpLink) *NullableStackpathRpcHelpLink {
	return &NullableStackpathRpcHelpLink{value: val, isSet: true}
}

func (v NullableStackpathRpcHelpLink) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcHelpLink) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
