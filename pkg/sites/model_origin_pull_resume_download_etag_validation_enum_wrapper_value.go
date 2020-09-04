/*
 * Sites
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sites

import (
	"encoding/json"
)

// OriginPullResumeDownloadEtagValidationEnumWrapperValue the model 'OriginPullResumeDownloadEtagValidationEnumWrapperValue'
type OriginPullResumeDownloadEtagValidationEnumWrapperValue string

// List of OriginPullResumeDownloadEtagValidationEnumWrapperValue
const (
	ORIGINPULLRESUMEDOWNLOADETAGVALIDATIONENUMWRAPPERVALUE_UNKNOWN OriginPullResumeDownloadEtagValidationEnumWrapperValue = "UNKNOWN"
	ORIGINPULLRESUMEDOWNLOADETAGVALIDATIONENUMWRAPPERVALUE_DO_NOT_USE OriginPullResumeDownloadEtagValidationEnumWrapperValue = "DO_NOT_USE"
	ORIGINPULLRESUMEDOWNLOADETAGVALIDATIONENUMWRAPPERVALUE_OPTIONAL OriginPullResumeDownloadEtagValidationEnumWrapperValue = "OPTIONAL"
	ORIGINPULLRESUMEDOWNLOADETAGVALIDATIONENUMWRAPPERVALUE_REQUIRED OriginPullResumeDownloadEtagValidationEnumWrapperValue = "REQUIRED"
)

// Ptr returns reference to OriginPullResumeDownloadEtagValidationEnumWrapperValue value
func (v OriginPullResumeDownloadEtagValidationEnumWrapperValue) Ptr() *OriginPullResumeDownloadEtagValidationEnumWrapperValue {
	return &v
}


type NullableOriginPullResumeDownloadEtagValidationEnumWrapperValue struct {
	value *OriginPullResumeDownloadEtagValidationEnumWrapperValue
	isSet bool
}

func (v NullableOriginPullResumeDownloadEtagValidationEnumWrapperValue) Get() *OriginPullResumeDownloadEtagValidationEnumWrapperValue {
	return v.value
}

func (v *NullableOriginPullResumeDownloadEtagValidationEnumWrapperValue) Set(val *OriginPullResumeDownloadEtagValidationEnumWrapperValue) {
	v.value = val
	v.isSet = true
}

func (v NullableOriginPullResumeDownloadEtagValidationEnumWrapperValue) IsSet() bool {
	return v.isSet
}

func (v *NullableOriginPullResumeDownloadEtagValidationEnumWrapperValue) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableOriginPullResumeDownloadEtagValidationEnumWrapperValue(val *OriginPullResumeDownloadEtagValidationEnumWrapperValue) *NullableOriginPullResumeDownloadEtagValidationEnumWrapperValue {
	return &NullableOriginPullResumeDownloadEtagValidationEnumWrapperValue{value: val, isSet: true}
}

func (v NullableOriginPullResumeDownloadEtagValidationEnumWrapperValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableOriginPullResumeDownloadEtagValidationEnumWrapperValue) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
