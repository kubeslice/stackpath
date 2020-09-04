/*
 * Edge Compute
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute

import (
	"encoding/json"
)

// V1InstancePort A named port for an instance of a workload
type V1InstancePort struct {
	// The network port
	Port *int32 `json:"port,omitempty"`
	// The network protocol for the port  Values are either \"TCP\" or \"UDP\". Defaults to \"TCP\".
	Protocol *string `json:"protocol,omitempty"`
	// Allow the internet to connect to the port  When true, this port will be given an implicit network policy of priority 65534 permitting 0.0.0.0/0 access to the port. This can be overridden by creating network policies of a higher priority to block the port.
	EnableImplicitNetworkPolicy *bool `json:"enableImplicitNetworkPolicy,omitempty"`
}

// NewV1InstancePort instantiates a new V1InstancePort object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewV1InstancePort() *V1InstancePort {
	this := V1InstancePort{}
	return &this
}

// NewV1InstancePortWithDefaults instantiates a new V1InstancePort object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewV1InstancePortWithDefaults() *V1InstancePort {
	this := V1InstancePort{}
	return &this
}

// GetPort returns the Port field value if set, zero value otherwise.
func (o *V1InstancePort) GetPort() int32 {
	if o == nil || o.Port == nil {
		var ret int32
		return ret
	}
	return *o.Port
}

// GetPortOk returns a tuple with the Port field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1InstancePort) GetPortOk() (*int32, bool) {
	if o == nil || o.Port == nil {
		return nil, false
	}
	return o.Port, true
}

// HasPort returns a boolean if a field has been set.
func (o *V1InstancePort) HasPort() bool {
	if o != nil && o.Port != nil {
		return true
	}

	return false
}

// SetPort gets a reference to the given int32 and assigns it to the Port field.
func (o *V1InstancePort) SetPort(v int32) {
	o.Port = &v
}

// GetProtocol returns the Protocol field value if set, zero value otherwise.
func (o *V1InstancePort) GetProtocol() string {
	if o == nil || o.Protocol == nil {
		var ret string
		return ret
	}
	return *o.Protocol
}

// GetProtocolOk returns a tuple with the Protocol field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1InstancePort) GetProtocolOk() (*string, bool) {
	if o == nil || o.Protocol == nil {
		return nil, false
	}
	return o.Protocol, true
}

// HasProtocol returns a boolean if a field has been set.
func (o *V1InstancePort) HasProtocol() bool {
	if o != nil && o.Protocol != nil {
		return true
	}

	return false
}

// SetProtocol gets a reference to the given string and assigns it to the Protocol field.
func (o *V1InstancePort) SetProtocol(v string) {
	o.Protocol = &v
}

// GetEnableImplicitNetworkPolicy returns the EnableImplicitNetworkPolicy field value if set, zero value otherwise.
func (o *V1InstancePort) GetEnableImplicitNetworkPolicy() bool {
	if o == nil || o.EnableImplicitNetworkPolicy == nil {
		var ret bool
		return ret
	}
	return *o.EnableImplicitNetworkPolicy
}

// GetEnableImplicitNetworkPolicyOk returns a tuple with the EnableImplicitNetworkPolicy field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1InstancePort) GetEnableImplicitNetworkPolicyOk() (*bool, bool) {
	if o == nil || o.EnableImplicitNetworkPolicy == nil {
		return nil, false
	}
	return o.EnableImplicitNetworkPolicy, true
}

// HasEnableImplicitNetworkPolicy returns a boolean if a field has been set.
func (o *V1InstancePort) HasEnableImplicitNetworkPolicy() bool {
	if o != nil && o.EnableImplicitNetworkPolicy != nil {
		return true
	}

	return false
}

// SetEnableImplicitNetworkPolicy gets a reference to the given bool and assigns it to the EnableImplicitNetworkPolicy field.
func (o *V1InstancePort) SetEnableImplicitNetworkPolicy(v bool) {
	o.EnableImplicitNetworkPolicy = &v
}

func (o V1InstancePort) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Port != nil {
		toSerialize["port"] = o.Port
	}
	if o.Protocol != nil {
		toSerialize["protocol"] = o.Protocol
	}
	if o.EnableImplicitNetworkPolicy != nil {
		toSerialize["enableImplicitNetworkPolicy"] = o.EnableImplicitNetworkPolicy
	}
	return json.Marshal(toSerialize)
}

type NullableV1InstancePort struct {
	value *V1InstancePort
	isSet bool
}

func (v NullableV1InstancePort) Get() *V1InstancePort {
	return v.value
}

func (v *NullableV1InstancePort) Set(val *V1InstancePort) {
	v.value = val
	v.isSet = true
}

func (v NullableV1InstancePort) IsSet() bool {
	return v.isSet
}

func (v *NullableV1InstancePort) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableV1InstancePort(val *V1InstancePort) *NullableV1InstancePort {
	return &NullableV1InstancePort{value: val, isSet: true}
}

func (v NullableV1InstancePort) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableV1InstancePort) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
