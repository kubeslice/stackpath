/*
 * Web Application Firewall
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package waf

import (
	"encoding/json"
)

// OwnerTypeConditionOwnerType Potential owner type values to match against
type OwnerTypeConditionOwnerType string

// List of OwnerTypeConditionOwnerType
const (
	OWNERTYPECONDITIONOWNERTYPE_COMMERCIAL OwnerTypeConditionOwnerType = "COMMERCIAL"
	OWNERTYPECONDITIONOWNERTYPE_EDUCATIONAL OwnerTypeConditionOwnerType = "EDUCATIONAL"
	OWNERTYPECONDITIONOWNERTYPE_GOVERNMENT OwnerTypeConditionOwnerType = "GOVERNMENT"
	OWNERTYPECONDITIONOWNERTYPE_HOSTING_SERVICES OwnerTypeConditionOwnerType = "HOSTING_SERVICES"
	OWNERTYPECONDITIONOWNERTYPE_ISP OwnerTypeConditionOwnerType = "ISP"
	OWNERTYPECONDITIONOWNERTYPE_MOBILE_NETWORK OwnerTypeConditionOwnerType = "MOBILE_NETWORK"
	OWNERTYPECONDITIONOWNERTYPE_NETWORK OwnerTypeConditionOwnerType = "NETWORK"
	OWNERTYPECONDITIONOWNERTYPE_RESERVED OwnerTypeConditionOwnerType = "RESERVED"
)

// Ptr returns reference to OwnerTypeConditionOwnerType value
func (v OwnerTypeConditionOwnerType) Ptr() *OwnerTypeConditionOwnerType {
	return &v
}


type NullableOwnerTypeConditionOwnerType struct {
	value *OwnerTypeConditionOwnerType
	isSet bool
}

func (v NullableOwnerTypeConditionOwnerType) Get() *OwnerTypeConditionOwnerType {
	return v.value
}

func (v *NullableOwnerTypeConditionOwnerType) Set(val *OwnerTypeConditionOwnerType) {
	v.value = val
	v.isSet = true
}

func (v NullableOwnerTypeConditionOwnerType) IsSet() bool {
	return v.isSet
}

func (v *NullableOwnerTypeConditionOwnerType) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableOwnerTypeConditionOwnerType(val *OwnerTypeConditionOwnerType) *NullableOwnerTypeConditionOwnerType {
	return &NullableOwnerTypeConditionOwnerType{value: val, isSet: true}
}

func (v NullableOwnerTypeConditionOwnerType) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableOwnerTypeConditionOwnerType) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
