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

// OriginPullPolicyExpirePolicyEnumWrapperValue the model 'OriginPullPolicyExpirePolicyEnumWrapperValue'
type OriginPullPolicyExpirePolicyEnumWrapperValue string

// List of OriginPullPolicyExpirePolicyEnumWrapperValue
const (
	UNKNOWN OriginPullPolicyExpirePolicyEnumWrapperValue = "UNKNOWN"
	CACHE_CONTROL OriginPullPolicyExpirePolicyEnumWrapperValue = "CACHE_CONTROL"
	INGEST OriginPullPolicyExpirePolicyEnumWrapperValue = "INGEST"
	LAST_MODIFY OriginPullPolicyExpirePolicyEnumWrapperValue = "LAST_MODIFY"
	NEVER_EXPIRE OriginPullPolicyExpirePolicyEnumWrapperValue = "NEVER_EXPIRE"
	DO_NOT_CACHE OriginPullPolicyExpirePolicyEnumWrapperValue = "DO_NOT_CACHE"
)

// Ptr returns reference to OriginPullPolicyExpirePolicyEnumWrapperValue value
func (v OriginPullPolicyExpirePolicyEnumWrapperValue) Ptr() *OriginPullPolicyExpirePolicyEnumWrapperValue {
	return &v
}


type NullableOriginPullPolicyExpirePolicyEnumWrapperValue struct {
	value *OriginPullPolicyExpirePolicyEnumWrapperValue
	isSet bool
}

func (v NullableOriginPullPolicyExpirePolicyEnumWrapperValue) Get() *OriginPullPolicyExpirePolicyEnumWrapperValue {
	return v.value
}

func (v *NullableOriginPullPolicyExpirePolicyEnumWrapperValue) Set(val *OriginPullPolicyExpirePolicyEnumWrapperValue) {
	v.value = val
	v.isSet = true
}

func (v NullableOriginPullPolicyExpirePolicyEnumWrapperValue) IsSet() bool {
	return v.isSet
}

func (v *NullableOriginPullPolicyExpirePolicyEnumWrapperValue) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableOriginPullPolicyExpirePolicyEnumWrapperValue(val *OriginPullPolicyExpirePolicyEnumWrapperValue) *NullableOriginPullPolicyExpirePolicyEnumWrapperValue {
	return &NullableOriginPullPolicyExpirePolicyEnumWrapperValue{value: val, isSet: true}
}

func (v NullableOriginPullPolicyExpirePolicyEnumWrapperValue) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableOriginPullPolicyExpirePolicyEnumWrapperValue) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
