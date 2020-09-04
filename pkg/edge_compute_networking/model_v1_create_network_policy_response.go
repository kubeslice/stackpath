/*
 * Edge Compute Networking
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute_networking

import (
	"encoding/json"
)

// V1CreateNetworkPolicyResponse A response from a request to add a network policy to a stack
type V1CreateNetworkPolicyResponse struct {
	NetworkPolicy *V1NetworkPolicy `json:"networkPolicy,omitempty"`
}

// NewV1CreateNetworkPolicyResponse instantiates a new V1CreateNetworkPolicyResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewV1CreateNetworkPolicyResponse() *V1CreateNetworkPolicyResponse {
	this := V1CreateNetworkPolicyResponse{}
	return &this
}

// NewV1CreateNetworkPolicyResponseWithDefaults instantiates a new V1CreateNetworkPolicyResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewV1CreateNetworkPolicyResponseWithDefaults() *V1CreateNetworkPolicyResponse {
	this := V1CreateNetworkPolicyResponse{}
	return &this
}

// GetNetworkPolicy returns the NetworkPolicy field value if set, zero value otherwise.
func (o *V1CreateNetworkPolicyResponse) GetNetworkPolicy() V1NetworkPolicy {
	if o == nil || o.NetworkPolicy == nil {
		var ret V1NetworkPolicy
		return ret
	}
	return *o.NetworkPolicy
}

// GetNetworkPolicyOk returns a tuple with the NetworkPolicy field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1CreateNetworkPolicyResponse) GetNetworkPolicyOk() (*V1NetworkPolicy, bool) {
	if o == nil || o.NetworkPolicy == nil {
		return nil, false
	}
	return o.NetworkPolicy, true
}

// HasNetworkPolicy returns a boolean if a field has been set.
func (o *V1CreateNetworkPolicyResponse) HasNetworkPolicy() bool {
	if o != nil && o.NetworkPolicy != nil {
		return true
	}

	return false
}

// SetNetworkPolicy gets a reference to the given V1NetworkPolicy and assigns it to the NetworkPolicy field.
func (o *V1CreateNetworkPolicyResponse) SetNetworkPolicy(v V1NetworkPolicy) {
	o.NetworkPolicy = &v
}

func (o V1CreateNetworkPolicyResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.NetworkPolicy != nil {
		toSerialize["networkPolicy"] = o.NetworkPolicy
	}
	return json.Marshal(toSerialize)
}

type NullableV1CreateNetworkPolicyResponse struct {
	value *V1CreateNetworkPolicyResponse
	isSet bool
}

func (v NullableV1CreateNetworkPolicyResponse) Get() *V1CreateNetworkPolicyResponse {
	return v.value
}

func (v *NullableV1CreateNetworkPolicyResponse) Set(val *V1CreateNetworkPolicyResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableV1CreateNetworkPolicyResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableV1CreateNetworkPolicyResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableV1CreateNetworkPolicyResponse(val *V1CreateNetworkPolicyResponse) *NullableV1CreateNetworkPolicyResponse {
	return &NullableV1CreateNetworkPolicyResponse{value: val, isSet: true}
}

func (v NullableV1CreateNetworkPolicyResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableV1CreateNetworkPolicyResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
