/*
 * Object Storage
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package object_storage

import (
	"encoding/json"
)

// StackpathRpcLocalizedMessage struct for StackpathRpcLocalizedMessage
type StackpathRpcLocalizedMessage struct {
	ApiStatusDetail
	Locale *string `json:"locale,omitempty"`
	Message *string `json:"message,omitempty"`
}

// NewStackpathRpcLocalizedMessage instantiates a new StackpathRpcLocalizedMessage object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcLocalizedMessage() *StackpathRpcLocalizedMessage {
	this := StackpathRpcLocalizedMessage{}
	return &this
}

// NewStackpathRpcLocalizedMessageWithDefaults instantiates a new StackpathRpcLocalizedMessage object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcLocalizedMessageWithDefaults() *StackpathRpcLocalizedMessage {
	this := StackpathRpcLocalizedMessage{}
	return &this
}

// GetLocale returns the Locale field value if set, zero value otherwise.
func (o *StackpathRpcLocalizedMessage) GetLocale() string {
	if o == nil || o.Locale == nil {
		var ret string
		return ret
	}
	return *o.Locale
}

// GetLocaleOk returns a tuple with the Locale field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcLocalizedMessage) GetLocaleOk() (*string, bool) {
	if o == nil || o.Locale == nil {
		return nil, false
	}
	return o.Locale, true
}

// HasLocale returns a boolean if a field has been set.
func (o *StackpathRpcLocalizedMessage) HasLocale() bool {
	if o != nil && o.Locale != nil {
		return true
	}

	return false
}

// SetLocale gets a reference to the given string and assigns it to the Locale field.
func (o *StackpathRpcLocalizedMessage) SetLocale(v string) {
	o.Locale = &v
}

// GetMessage returns the Message field value if set, zero value otherwise.
func (o *StackpathRpcLocalizedMessage) GetMessage() string {
	if o == nil || o.Message == nil {
		var ret string
		return ret
	}
	return *o.Message
}

// GetMessageOk returns a tuple with the Message field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcLocalizedMessage) GetMessageOk() (*string, bool) {
	if o == nil || o.Message == nil {
		return nil, false
	}
	return o.Message, true
}

// HasMessage returns a boolean if a field has been set.
func (o *StackpathRpcLocalizedMessage) HasMessage() bool {
	if o != nil && o.Message != nil {
		return true
	}

	return false
}

// SetMessage gets a reference to the given string and assigns it to the Message field.
func (o *StackpathRpcLocalizedMessage) SetMessage(v string) {
	o.Message = &v
}

func (o StackpathRpcLocalizedMessage) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	serializedApiStatusDetail, errApiStatusDetail := json.Marshal(o.ApiStatusDetail)
	if errApiStatusDetail != nil {
		return []byte{}, errApiStatusDetail
	}
	errApiStatusDetail = json.Unmarshal([]byte(serializedApiStatusDetail), &toSerialize)
	if errApiStatusDetail != nil {
		return []byte{}, errApiStatusDetail
	}
	if o.Locale != nil {
		toSerialize["locale"] = o.Locale
	}
	if o.Message != nil {
		toSerialize["message"] = o.Message
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathRpcLocalizedMessage struct {
	value *StackpathRpcLocalizedMessage
	isSet bool
}

func (v NullableStackpathRpcLocalizedMessage) Get() *StackpathRpcLocalizedMessage {
	return v.value
}

func (v *NullableStackpathRpcLocalizedMessage) Set(val *StackpathRpcLocalizedMessage) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcLocalizedMessage) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcLocalizedMessage) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcLocalizedMessage(val *StackpathRpcLocalizedMessage) *NullableStackpathRpcLocalizedMessage {
	return &NullableStackpathRpcLocalizedMessage{value: val, isSet: true}
}

func (v NullableStackpathRpcLocalizedMessage) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcLocalizedMessage) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
