/*
 * Accounts and Users
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package accounts_and_users

import (
	"encoding/json"
)

// IdentityCreateUserResponse A response from a request to create a new StackPath user
type IdentityCreateUserResponse struct {
	User *IdentityUser `json:"user,omitempty"`
}

// NewIdentityCreateUserResponse instantiates a new IdentityCreateUserResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewIdentityCreateUserResponse() *IdentityCreateUserResponse {
	this := IdentityCreateUserResponse{}
	return &this
}

// NewIdentityCreateUserResponseWithDefaults instantiates a new IdentityCreateUserResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewIdentityCreateUserResponseWithDefaults() *IdentityCreateUserResponse {
	this := IdentityCreateUserResponse{}
	return &this
}

// GetUser returns the User field value if set, zero value otherwise.
func (o *IdentityCreateUserResponse) GetUser() IdentityUser {
	if o == nil || o.User == nil {
		var ret IdentityUser
		return ret
	}
	return *o.User
}

// GetUserOk returns a tuple with the User field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *IdentityCreateUserResponse) GetUserOk() (*IdentityUser, bool) {
	if o == nil || o.User == nil {
		return nil, false
	}
	return o.User, true
}

// HasUser returns a boolean if a field has been set.
func (o *IdentityCreateUserResponse) HasUser() bool {
	if o != nil && o.User != nil {
		return true
	}

	return false
}

// SetUser gets a reference to the given IdentityUser and assigns it to the User field.
func (o *IdentityCreateUserResponse) SetUser(v IdentityUser) {
	o.User = &v
}

func (o IdentityCreateUserResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.User != nil {
		toSerialize["user"] = o.User
	}
	return json.Marshal(toSerialize)
}

type NullableIdentityCreateUserResponse struct {
	value *IdentityCreateUserResponse
	isSet bool
}

func (v NullableIdentityCreateUserResponse) Get() *IdentityCreateUserResponse {
	return v.value
}

func (v *NullableIdentityCreateUserResponse) Set(val *IdentityCreateUserResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableIdentityCreateUserResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableIdentityCreateUserResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableIdentityCreateUserResponse(val *IdentityCreateUserResponse) *NullableIdentityCreateUserResponse {
	return &NullableIdentityCreateUserResponse{value: val, isSet: true}
}

func (v NullableIdentityCreateUserResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableIdentityCreateUserResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
