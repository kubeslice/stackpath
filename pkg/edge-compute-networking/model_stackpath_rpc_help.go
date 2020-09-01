/*
 * Edge Compute Networking
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge-compute-networking

import (
	"encoding/json"
)

// StackpathRpcHelp struct for StackpathRpcHelp
type StackpathRpcHelp struct {
	ApiStatusDetail
	Links *[]StackpathRpcHelpLink `json:"links,omitempty"`
}

// NewStackpathRpcHelp instantiates a new StackpathRpcHelp object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcHelp() *StackpathRpcHelp {
	this := StackpathRpcHelp{}
	return &this
}

// NewStackpathRpcHelpWithDefaults instantiates a new StackpathRpcHelp object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcHelpWithDefaults() *StackpathRpcHelp {
	this := StackpathRpcHelp{}
	return &this
}

// GetLinks returns the Links field value if set, zero value otherwise.
func (o *StackpathRpcHelp) GetLinks() []StackpathRpcHelpLink {
	if o == nil || o.Links == nil {
		var ret []StackpathRpcHelpLink
		return ret
	}
	return *o.Links
}

// GetLinksOk returns a tuple with the Links field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcHelp) GetLinksOk() (*[]StackpathRpcHelpLink, bool) {
	if o == nil || o.Links == nil {
		return nil, false
	}
	return o.Links, true
}

// HasLinks returns a boolean if a field has been set.
func (o *StackpathRpcHelp) HasLinks() bool {
	if o != nil && o.Links != nil {
		return true
	}

	return false
}

// SetLinks gets a reference to the given []StackpathRpcHelpLink and assigns it to the Links field.
func (o *StackpathRpcHelp) SetLinks(v []StackpathRpcHelpLink) {
	o.Links = &v
}

func (o StackpathRpcHelp) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	serializedApiStatusDetail, errApiStatusDetail := json.Marshal(o.ApiStatusDetail)
	if errApiStatusDetail != nil {
		return []byte{}, errApiStatusDetail
	}
	errApiStatusDetail = json.Unmarshal([]byte(serializedApiStatusDetail), &toSerialize)
	if errApiStatusDetail != nil {
		return []byte{}, errApiStatusDetail
	}
	if o.Links != nil {
		toSerialize["links"] = o.Links
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathRpcHelp struct {
	value *StackpathRpcHelp
	isSet bool
}

func (v NullableStackpathRpcHelp) Get() *StackpathRpcHelp {
	return v.value
}

func (v *NullableStackpathRpcHelp) Set(val *StackpathRpcHelp) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcHelp) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcHelp) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcHelp(val *StackpathRpcHelp) *NullableStackpathRpcHelp {
	return &NullableStackpathRpcHelp{value: val, isSet: true}
}

func (v NullableStackpathRpcHelp) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcHelp) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
