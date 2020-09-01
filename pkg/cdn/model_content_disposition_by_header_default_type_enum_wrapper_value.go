/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn

import (
	"encoding/json"
)

// ContentDispositionByHeaderDefaultTypeEnumWrapperValue the model 'ContentDispositionByHeaderDefaultTypeEnumWrapperValue'
type ContentDispositionByHeaderDefaultTypeEnumWrapperValue string

// List of ContentDispositionByHeaderDefaultTypeEnumWrapperValue
const (
	UNKNOWN ContentDispositionByHeaderDefaultTypeEnumWrapperValue = "UNKNOWN"
	ATTACHMENT ContentDispositionByHeaderDefaultTypeEnumWrapperValue = "attachment"
	INLINE ContentDispositionByHeaderDefaultTypeEnumWrapperValue = "inline"
)

// Ptr returns reference to ContentDispositionByHeaderDefaultTypeEnumWrapperValue value
func (v ContentDispositionByHeaderDefaultTypeEnumWrapperValue) Ptr() *ContentDispositionByHeaderDefaultTypeEnumWrapperValue {
	return &v
}


type NullableContentDispositionByHeaderDefaultTypeEnumWrapperValue struct {
	value *ContentDispositionByHeaderDefaultTypeEnumWrapperValue
	isSet bool
}

func (v NullableContentDispositionByHeaderDefaultTypeEnumWrapperValue) Get() *ContentDispositionByHeaderDefaultTypeEnumWrapperValue {
	return v.value
}

func (v *NullableContentDispositionByHeaderDefaultTypeEnumWrapperValue) Set(val *ContentDispositionByHeaderDefaultTypeEnumWrapperValue) {
	v.value = val
	v.isSet = true
}

func (v NullableContentDispositionByHeaderDefaultTypeEnumWrapperValue) IsSet() bool {
	return v.isSet
}

func (v *NullableContentDispositionByHeaderDefaultTypeEnumWrapperValue) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableContentDispositionByHeaderDefaultTypeEnumWrapperValue(val *ContentDispositionByHeaderDefaultTypeEnumWrapperValue) *NullableContentDispositionByHeaderDefaultTypeEnumWrapperValue {
	return &NullableContentDispositionByHeaderDefaultTypeEnumWrapperValue{value: val, isSet: true}
}

func (v NullableContentDispositionByHeaderDefaultTypeEnumWrapperValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableContentDispositionByHeaderDefaultTypeEnumWrapperValue) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
