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

// StackpathRpcLocalizedMessageAllOf struct for StackpathRpcLocalizedMessageAllOf
type StackpathRpcLocalizedMessageAllOf struct {
	Locale *string `json:"locale,omitempty"`
	Message *string `json:"message,omitempty"`
}

// NewStackpathRpcLocalizedMessageAllOf instantiates a new StackpathRpcLocalizedMessageAllOf object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcLocalizedMessageAllOf() *StackpathRpcLocalizedMessageAllOf {
	this := StackpathRpcLocalizedMessageAllOf{}
	return &this
}

// NewStackpathRpcLocalizedMessageAllOfWithDefaults instantiates a new StackpathRpcLocalizedMessageAllOf object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcLocalizedMessageAllOfWithDefaults() *StackpathRpcLocalizedMessageAllOf {
	this := StackpathRpcLocalizedMessageAllOf{}
	return &this
}

// GetLocale returns the Locale field value if set, zero value otherwise.
func (o *StackpathRpcLocalizedMessageAllOf) GetLocale() string {
	if o == nil || o.Locale == nil {
		var ret string
		return ret
	}
	return *o.Locale
}

// GetLocaleOk returns a tuple with the Locale field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcLocalizedMessageAllOf) GetLocaleOk() (*string, bool) {
	if o == nil || o.Locale == nil {
		return nil, false
	}
	return o.Locale, true
}

// HasLocale returns a boolean if a field has been set.
func (o *StackpathRpcLocalizedMessageAllOf) HasLocale() bool {
	if o != nil && o.Locale != nil {
		return true
	}

	return false
}

// SetLocale gets a reference to the given string and assigns it to the Locale field.
func (o *StackpathRpcLocalizedMessageAllOf) SetLocale(v string) {
	o.Locale = &v
}

// GetMessage returns the Message field value if set, zero value otherwise.
func (o *StackpathRpcLocalizedMessageAllOf) GetMessage() string {
	if o == nil || o.Message == nil {
		var ret string
		return ret
	}
	return *o.Message
}

// GetMessageOk returns a tuple with the Message field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcLocalizedMessageAllOf) GetMessageOk() (*string, bool) {
	if o == nil || o.Message == nil {
		return nil, false
	}
	return o.Message, true
}

// HasMessage returns a boolean if a field has been set.
func (o *StackpathRpcLocalizedMessageAllOf) HasMessage() bool {
	if o != nil && o.Message != nil {
		return true
	}

	return false
}

// SetMessage gets a reference to the given string and assigns it to the Message field.
func (o *StackpathRpcLocalizedMessageAllOf) SetMessage(v string) {
	o.Message = &v
}

func (o StackpathRpcLocalizedMessageAllOf) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Locale != nil {
		toSerialize["locale"] = o.Locale
	}
	if o.Message != nil {
		toSerialize["message"] = o.Message
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathRpcLocalizedMessageAllOf struct {
	value *StackpathRpcLocalizedMessageAllOf
	isSet bool
}

func (v NullableStackpathRpcLocalizedMessageAllOf) Get() *StackpathRpcLocalizedMessageAllOf {
	return v.value
}

func (v *NullableStackpathRpcLocalizedMessageAllOf) Set(val *StackpathRpcLocalizedMessageAllOf) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcLocalizedMessageAllOf) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcLocalizedMessageAllOf) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcLocalizedMessageAllOf(val *StackpathRpcLocalizedMessageAllOf) *NullableStackpathRpcLocalizedMessageAllOf {
	return &NullableStackpathRpcLocalizedMessageAllOf{value: val, isSet: true}
}

func (v NullableStackpathRpcLocalizedMessageAllOf) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcLocalizedMessageAllOf) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
