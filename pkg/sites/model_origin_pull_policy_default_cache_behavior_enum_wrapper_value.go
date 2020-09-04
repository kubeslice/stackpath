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

// OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue the model 'OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue'
type OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue string

// List of OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue
const (
	ORIGINPULLPOLICYDEFAULTCACHEBEHAVIORENUMWRAPPERVALUE_UNKNOWN OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue = "UNKNOWN"
	ORIGINPULLPOLICYDEFAULTCACHEBEHAVIORENUMWRAPPERVALUE_BYPASS OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue = "bypass"
	ORIGINPULLPOLICYDEFAULTCACHEBEHAVIORENUMWRAPPERVALUE_TTL OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue = "ttl"
)

// Ptr returns reference to OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue value
func (v OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue) Ptr() *OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue {
	return &v
}


type NullableOriginPullPolicyDefaultCacheBehaviorEnumWrapperValue struct {
	value *OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue
	isSet bool
}

func (v NullableOriginPullPolicyDefaultCacheBehaviorEnumWrapperValue) Get() *OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue {
	return v.value
}

func (v *NullableOriginPullPolicyDefaultCacheBehaviorEnumWrapperValue) Set(val *OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue) {
	v.value = val
	v.isSet = true
}

func (v NullableOriginPullPolicyDefaultCacheBehaviorEnumWrapperValue) IsSet() bool {
	return v.isSet
}

func (v *NullableOriginPullPolicyDefaultCacheBehaviorEnumWrapperValue) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableOriginPullPolicyDefaultCacheBehaviorEnumWrapperValue(val *OriginPullPolicyDefaultCacheBehaviorEnumWrapperValue) *NullableOriginPullPolicyDefaultCacheBehaviorEnumWrapperValue {
	return &NullableOriginPullPolicyDefaultCacheBehaviorEnumWrapperValue{value: val, isSet: true}
}

func (v NullableOriginPullPolicyDefaultCacheBehaviorEnumWrapperValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableOriginPullPolicyDefaultCacheBehaviorEnumWrapperValue) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
