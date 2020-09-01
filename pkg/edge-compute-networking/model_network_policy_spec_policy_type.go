/*
 * Edge Compute Networking
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge-compute-networking

import (
	"encoding/json"
)

// NetworkPolicySpecPolicyType the model 'NetworkPolicySpecPolicyType'
type NetworkPolicySpecPolicyType string

// List of NetworkPolicySpecPolicyType
const (
	POLICY_TYPE_NOT_SPECIFIED NetworkPolicySpecPolicyType = "POLICY_TYPE_NOT_SPECIFIED"
	INGRESS NetworkPolicySpecPolicyType = "INGRESS"
	EGRESS NetworkPolicySpecPolicyType = "EGRESS"
)

// Ptr returns reference to NetworkPolicySpecPolicyType value
func (v NetworkPolicySpecPolicyType) Ptr() *NetworkPolicySpecPolicyType {
	return &v
}


type NullableNetworkPolicySpecPolicyType struct {
	value *NetworkPolicySpecPolicyType
	isSet bool
}

func (v NullableNetworkPolicySpecPolicyType) Get() *NetworkPolicySpecPolicyType {
	return v.value
}

func (v *NullableNetworkPolicySpecPolicyType) Set(val *NetworkPolicySpecPolicyType) {
	v.value = val
	v.isSet = true
}

func (v NullableNetworkPolicySpecPolicyType) IsSet() bool {
	return v.isSet
}

func (v *NullableNetworkPolicySpecPolicyType) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableNetworkPolicySpecPolicyType(val *NetworkPolicySpecPolicyType) *NullableNetworkPolicySpecPolicyType {
	return &NullableNetworkPolicySpecPolicyType{value: val, isSet: true}
}

func (v NullableNetworkPolicySpecPolicyType) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableNetworkPolicySpecPolicyType) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
