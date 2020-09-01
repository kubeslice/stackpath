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

// NetworkOrganization The organization that owns the WAF request's originating IP address according to a WHOIS lookup
type NetworkOrganization struct {
	// The name of organization
	Name *string `json:"name,omitempty"`
	// The IP bock of the organization
	Subnet *string `json:"subnet,omitempty"`
}

// NewNetworkOrganization instantiates a new NetworkOrganization object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewNetworkOrganization() *NetworkOrganization {
	this := NetworkOrganization{}
	return &this
}

// NewNetworkOrganizationWithDefaults instantiates a new NetworkOrganization object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewNetworkOrganizationWithDefaults() *NetworkOrganization {
	this := NetworkOrganization{}
	return &this
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *NetworkOrganization) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *NetworkOrganization) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *NetworkOrganization) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *NetworkOrganization) SetName(v string) {
	o.Name = &v
}

// GetSubnet returns the Subnet field value if set, zero value otherwise.
func (o *NetworkOrganization) GetSubnet() string {
	if o == nil || o.Subnet == nil {
		var ret string
		return ret
	}
	return *o.Subnet
}

// GetSubnetOk returns a tuple with the Subnet field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *NetworkOrganization) GetSubnetOk() (*string, bool) {
	if o == nil || o.Subnet == nil {
		return nil, false
	}
	return o.Subnet, true
}

// HasSubnet returns a boolean if a field has been set.
func (o *NetworkOrganization) HasSubnet() bool {
	if o != nil && o.Subnet != nil {
		return true
	}

	return false
}

// SetSubnet gets a reference to the given string and assigns it to the Subnet field.
func (o *NetworkOrganization) SetSubnet(v string) {
	o.Subnet = &v
}

func (o NetworkOrganization) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Name != nil {
		toSerialize["name"] = o.Name
	}
	if o.Subnet != nil {
		toSerialize["subnet"] = o.Subnet
	}
	return json.Marshal(toSerialize)
}

type NullableNetworkOrganization struct {
	value *NetworkOrganization
	isSet bool
}

func (v NullableNetworkOrganization) Get() *NetworkOrganization {
	return v.value
}

func (v *NullableNetworkOrganization) Set(val *NetworkOrganization) {
	v.value = val
	v.isSet = true
}

func (v NullableNetworkOrganization) IsSet() bool {
	return v.isSet
}

func (v *NullableNetworkOrganization) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableNetworkOrganization(val *NetworkOrganization) *NullableNetworkOrganization {
	return &NullableNetworkOrganization{value: val, isSet: true}
}

func (v NullableNetworkOrganization) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableNetworkOrganization) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
