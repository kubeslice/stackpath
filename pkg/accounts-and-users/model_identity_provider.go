/*
 * Accounts and Users
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package accounts-and-users

import (
	"encoding/json"
)

// IdentityProvider An identity provider  Identity providers handle user authentication to the StackPath customer portal. They can be third party like Google or Facebook, or StackPath can provide identity resources for users.
type IdentityProvider struct {
	// An identity provider's unique identidier
	Id *string `json:"id,omitempty"`
	// An identity provider's name
	Name *string `json:"name,omitempty"`
}

// NewIdentityProvider instantiates a new IdentityProvider object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewIdentityProvider() *IdentityProvider {
	this := IdentityProvider{}
	return &this
}

// NewIdentityProviderWithDefaults instantiates a new IdentityProvider object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewIdentityProviderWithDefaults() *IdentityProvider {
	this := IdentityProvider{}
	return &this
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *IdentityProvider) GetId() string {
	if o == nil || o.Id == nil {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *IdentityProvider) GetIdOk() (*string, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *IdentityProvider) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *IdentityProvider) SetId(v string) {
	o.Id = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *IdentityProvider) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *IdentityProvider) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *IdentityProvider) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *IdentityProvider) SetName(v string) {
	o.Name = &v
}

func (o IdentityProvider) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Id != nil {
		toSerialize["id"] = o.Id
	}
	if o.Name != nil {
		toSerialize["name"] = o.Name
	}
	return json.Marshal(toSerialize)
}

type NullableIdentityProvider struct {
	value *IdentityProvider
	isSet bool
}

func (v NullableIdentityProvider) Get() *IdentityProvider {
	return v.value
}

func (v *NullableIdentityProvider) Set(val *IdentityProvider) {
	v.value = val
	v.isSet = true
}

func (v NullableIdentityProvider) IsSet() bool {
	return v.isSet
}

func (v *NullableIdentityProvider) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableIdentityProvider(val *IdentityProvider) *NullableIdentityProvider {
	return &NullableIdentityProvider{value: val, isSet: true}
}

func (v NullableIdentityProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableIdentityProvider) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
