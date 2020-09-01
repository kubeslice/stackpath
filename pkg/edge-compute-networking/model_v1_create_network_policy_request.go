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

// V1CreateNetworkPolicyRequest struct for V1CreateNetworkPolicyRequest
type V1CreateNetworkPolicyRequest struct {
	NetworkPolicy *V1NetworkPolicy `json:"networkPolicy,omitempty"`
}

// NewV1CreateNetworkPolicyRequest instantiates a new V1CreateNetworkPolicyRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewV1CreateNetworkPolicyRequest() *V1CreateNetworkPolicyRequest {
	this := V1CreateNetworkPolicyRequest{}
	return &this
}

// NewV1CreateNetworkPolicyRequestWithDefaults instantiates a new V1CreateNetworkPolicyRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewV1CreateNetworkPolicyRequestWithDefaults() *V1CreateNetworkPolicyRequest {
	this := V1CreateNetworkPolicyRequest{}
	return &this
}

// GetNetworkPolicy returns the NetworkPolicy field value if set, zero value otherwise.
func (o *V1CreateNetworkPolicyRequest) GetNetworkPolicy() V1NetworkPolicy {
	if o == nil || o.NetworkPolicy == nil {
		var ret V1NetworkPolicy
		return ret
	}
	return *o.NetworkPolicy
}

// GetNetworkPolicyOk returns a tuple with the NetworkPolicy field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1CreateNetworkPolicyRequest) GetNetworkPolicyOk() (*V1NetworkPolicy, bool) {
	if o == nil || o.NetworkPolicy == nil {
		return nil, false
	}
	return o.NetworkPolicy, true
}

// HasNetworkPolicy returns a boolean if a field has been set.
func (o *V1CreateNetworkPolicyRequest) HasNetworkPolicy() bool {
	if o != nil && o.NetworkPolicy != nil {
		return true
	}

	return false
}

// SetNetworkPolicy gets a reference to the given V1NetworkPolicy and assigns it to the NetworkPolicy field.
func (o *V1CreateNetworkPolicyRequest) SetNetworkPolicy(v V1NetworkPolicy) {
	o.NetworkPolicy = &v
}

func (o V1CreateNetworkPolicyRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.NetworkPolicy != nil {
		toSerialize["networkPolicy"] = o.NetworkPolicy
	}
	return json.Marshal(toSerialize)
}

type NullableV1CreateNetworkPolicyRequest struct {
	value *V1CreateNetworkPolicyRequest
	isSet bool
}

func (v NullableV1CreateNetworkPolicyRequest) Get() *V1CreateNetworkPolicyRequest {
	return v.value
}

func (v *NullableV1CreateNetworkPolicyRequest) Set(val *V1CreateNetworkPolicyRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableV1CreateNetworkPolicyRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableV1CreateNetworkPolicyRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableV1CreateNetworkPolicyRequest(val *V1CreateNetworkPolicyRequest) *NullableV1CreateNetworkPolicyRequest {
	return &NullableV1CreateNetworkPolicyRequest{value: val, isSet: true}
}

func (v NullableV1CreateNetworkPolicyRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableV1CreateNetworkPolicyRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
