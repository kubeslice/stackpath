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

// IdentityGetUserResponse A response from a request to retrieve a StackPath user account
type IdentityGetUserResponse struct {
	User *IdentityUser `json:"user,omitempty"`
}

// NewIdentityGetUserResponse instantiates a new IdentityGetUserResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewIdentityGetUserResponse() *IdentityGetUserResponse {
	this := IdentityGetUserResponse{}
	return &this
}

// NewIdentityGetUserResponseWithDefaults instantiates a new IdentityGetUserResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewIdentityGetUserResponseWithDefaults() *IdentityGetUserResponse {
	this := IdentityGetUserResponse{}
	return &this
}

// GetUser returns the User field value if set, zero value otherwise.
func (o *IdentityGetUserResponse) GetUser() IdentityUser {
	if o == nil || o.User == nil {
		var ret IdentityUser
		return ret
	}
	return *o.User
}

// GetUserOk returns a tuple with the User field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *IdentityGetUserResponse) GetUserOk() (*IdentityUser, bool) {
	if o == nil || o.User == nil {
		return nil, false
	}
	return o.User, true
}

// HasUser returns a boolean if a field has been set.
func (o *IdentityGetUserResponse) HasUser() bool {
	if o != nil && o.User != nil {
		return true
	}

	return false
}

// SetUser gets a reference to the given IdentityUser and assigns it to the User field.
func (o *IdentityGetUserResponse) SetUser(v IdentityUser) {
	o.User = &v
}

func (o IdentityGetUserResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.User != nil {
		toSerialize["user"] = o.User
	}
	return json.Marshal(toSerialize)
}

type NullableIdentityGetUserResponse struct {
	value *IdentityGetUserResponse
	isSet bool
}

func (v NullableIdentityGetUserResponse) Get() *IdentityGetUserResponse {
	return v.value
}

func (v *NullableIdentityGetUserResponse) Set(val *IdentityGetUserResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableIdentityGetUserResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableIdentityGetUserResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableIdentityGetUserResponse(val *IdentityGetUserResponse) *NullableIdentityGetUserResponse {
	return &NullableIdentityGetUserResponse{value: val, isSet: true}
}

func (v NullableIdentityGetUserResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableIdentityGetUserResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
