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

// StackpathapiStatus struct for StackpathapiStatus
type StackpathapiStatus struct {
	Code *int32 `json:"code,omitempty"`
	Details *[]ApiStatusDetail `json:"details,omitempty"`
	Message *string `json:"message,omitempty"`
}

// NewStackpathapiStatus instantiates a new StackpathapiStatus object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathapiStatus() *StackpathapiStatus {
	this := StackpathapiStatus{}
	return &this
}

// NewStackpathapiStatusWithDefaults instantiates a new StackpathapiStatus object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathapiStatusWithDefaults() *StackpathapiStatus {
	this := StackpathapiStatus{}
	return &this
}

// GetCode returns the Code field value if set, zero value otherwise.
func (o *StackpathapiStatus) GetCode() int32 {
	if o == nil || o.Code == nil {
		var ret int32
		return ret
	}
	return *o.Code
}

// GetCodeOk returns a tuple with the Code field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathapiStatus) GetCodeOk() (*int32, bool) {
	if o == nil || o.Code == nil {
		return nil, false
	}
	return o.Code, true
}

// HasCode returns a boolean if a field has been set.
func (o *StackpathapiStatus) HasCode() bool {
	if o != nil && o.Code != nil {
		return true
	}

	return false
}

// SetCode gets a reference to the given int32 and assigns it to the Code field.
func (o *StackpathapiStatus) SetCode(v int32) {
	o.Code = &v
}

// GetDetails returns the Details field value if set, zero value otherwise.
func (o *StackpathapiStatus) GetDetails() []ApiStatusDetail {
	if o == nil || o.Details == nil {
		var ret []ApiStatusDetail
		return ret
	}
	return *o.Details
}

// GetDetailsOk returns a tuple with the Details field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathapiStatus) GetDetailsOk() (*[]ApiStatusDetail, bool) {
	if o == nil || o.Details == nil {
		return nil, false
	}
	return o.Details, true
}

// HasDetails returns a boolean if a field has been set.
func (o *StackpathapiStatus) HasDetails() bool {
	if o != nil && o.Details != nil {
		return true
	}

	return false
}

// SetDetails gets a reference to the given []ApiStatusDetail and assigns it to the Details field.
func (o *StackpathapiStatus) SetDetails(v []ApiStatusDetail) {
	o.Details = &v
}

// GetMessage returns the Message field value if set, zero value otherwise.
func (o *StackpathapiStatus) GetMessage() string {
	if o == nil || o.Message == nil {
		var ret string
		return ret
	}
	return *o.Message
}

// GetMessageOk returns a tuple with the Message field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathapiStatus) GetMessageOk() (*string, bool) {
	if o == nil || o.Message == nil {
		return nil, false
	}
	return o.Message, true
}

// HasMessage returns a boolean if a field has been set.
func (o *StackpathapiStatus) HasMessage() bool {
	if o != nil && o.Message != nil {
		return true
	}

	return false
}

// SetMessage gets a reference to the given string and assigns it to the Message field.
func (o *StackpathapiStatus) SetMessage(v string) {
	o.Message = &v
}

func (o StackpathapiStatus) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Code != nil {
		toSerialize["code"] = o.Code
	}
	if o.Details != nil {
		toSerialize["details"] = o.Details
	}
	if o.Message != nil {
		toSerialize["message"] = o.Message
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathapiStatus struct {
	value *StackpathapiStatus
	isSet bool
}

func (v NullableStackpathapiStatus) Get() *StackpathapiStatus {
	return v.value
}

func (v *NullableStackpathapiStatus) Set(val *StackpathapiStatus) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathapiStatus) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathapiStatus) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathapiStatus(val *StackpathapiStatus) *NullableStackpathapiStatus {
	return &NullableStackpathapiStatus{value: val, isSet: true}
}

func (v NullableStackpathapiStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathapiStatus) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
