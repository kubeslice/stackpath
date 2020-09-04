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

// OriginPullPolicyNoCacheBehaviorEnumWrapperValue the model 'OriginPullPolicyNoCacheBehaviorEnumWrapperValue'
type OriginPullPolicyNoCacheBehaviorEnumWrapperValue string

// List of OriginPullPolicyNoCacheBehaviorEnumWrapperValue
const (
	ORIGINPULLPOLICYNOCACHEBEHAVIORENUMWRAPPERVALUE_UNKNOWN OriginPullPolicyNoCacheBehaviorEnumWrapperValue = "UNKNOWN"
	ORIGINPULLPOLICYNOCACHEBEHAVIORENUMWRAPPERVALUE_LEGACY OriginPullPolicyNoCacheBehaviorEnumWrapperValue = "legacy"
	ORIGINPULLPOLICYNOCACHEBEHAVIORENUMWRAPPERVALUE_SPEC OriginPullPolicyNoCacheBehaviorEnumWrapperValue = "spec"
)

// Ptr returns reference to OriginPullPolicyNoCacheBehaviorEnumWrapperValue value
func (v OriginPullPolicyNoCacheBehaviorEnumWrapperValue) Ptr() *OriginPullPolicyNoCacheBehaviorEnumWrapperValue {
	return &v
}


type NullableOriginPullPolicyNoCacheBehaviorEnumWrapperValue struct {
	value *OriginPullPolicyNoCacheBehaviorEnumWrapperValue
	isSet bool
}

func (v NullableOriginPullPolicyNoCacheBehaviorEnumWrapperValue) Get() *OriginPullPolicyNoCacheBehaviorEnumWrapperValue {
	return v.value
}

func (v *NullableOriginPullPolicyNoCacheBehaviorEnumWrapperValue) Set(val *OriginPullPolicyNoCacheBehaviorEnumWrapperValue) {
	v.value = val
	v.isSet = true
}

func (v NullableOriginPullPolicyNoCacheBehaviorEnumWrapperValue) IsSet() bool {
	return v.isSet
}

func (v *NullableOriginPullPolicyNoCacheBehaviorEnumWrapperValue) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableOriginPullPolicyNoCacheBehaviorEnumWrapperValue(val *OriginPullPolicyNoCacheBehaviorEnumWrapperValue) *NullableOriginPullPolicyNoCacheBehaviorEnumWrapperValue {
	return &NullableOriginPullPolicyNoCacheBehaviorEnumWrapperValue{value: val, isSet: true}
}

func (v NullableOriginPullPolicyNoCacheBehaviorEnumWrapperValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableOriginPullPolicyNoCacheBehaviorEnumWrapperValue) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
