/*
 * Edge Compute Networking
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute_networking

import (
	"encoding/json"
)

// ApiStatusDetail struct for ApiStatusDetail
type ApiStatusDetail struct {
	Type string `json:"@type"`
}

// NewApiStatusDetail instantiates a new ApiStatusDetail object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewApiStatusDetail(type_ string, ) *ApiStatusDetail {
	this := ApiStatusDetail{}
	this.Type = type_
	return &this
}

// NewApiStatusDetailWithDefaults instantiates a new ApiStatusDetail object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewApiStatusDetailWithDefaults() *ApiStatusDetail {
	this := ApiStatusDetail{}
	return &this
}

// GetType returns the Type field value
func (o *ApiStatusDetail) GetType() string {
	if o == nil  {
		var ret string
		return ret
	}

	return o.Type
}

// GetTypeOk returns a tuple with the Type field value
// and a boolean to check if the value has been set.
func (o *ApiStatusDetail) GetTypeOk() (*string, bool) {
	if o == nil  {
		return nil, false
	}
	return &o.Type, true
}

// SetType sets field value
func (o *ApiStatusDetail) SetType(v string) {
	o.Type = v
}

func (o ApiStatusDetail) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if true {
		toSerialize["@type"] = o.Type
	}
	return json.Marshal(toSerialize)
}

type NullableApiStatusDetail struct {
	value *ApiStatusDetail
	isSet bool
}

func (v NullableApiStatusDetail) Get() *ApiStatusDetail {
	return v.value
}

func (v *NullableApiStatusDetail) Set(val *ApiStatusDetail) {
	v.value = val
	v.isSet = true
}

func (v NullableApiStatusDetail) IsSet() bool {
	return v.isSet
}

func (v *NullableApiStatusDetail) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableApiStatusDetail(val *ApiStatusDetail) *NullableApiStatusDetail {
	return &NullableApiStatusDetail{value: val, isSet: true}
}

func (v NullableApiStatusDetail) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableApiStatusDetail) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
