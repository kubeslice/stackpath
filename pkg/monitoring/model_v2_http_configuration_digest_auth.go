/*
 * Monitoring
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package monitoring

import (
	"encoding/json"
)

// V2HttpConfigurationDigestAuth HTTP digest authentication configuration
type V2HttpConfigurationDigestAuth struct {
	// The username used for digest authentication by a monitor.
	Username *string `json:"username,omitempty"`
	// The password used for digest authentication by a monitor.
	Password *string `json:"password,omitempty"`
}

// NewV2HttpConfigurationDigestAuth instantiates a new V2HttpConfigurationDigestAuth object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewV2HttpConfigurationDigestAuth() *V2HttpConfigurationDigestAuth {
	this := V2HttpConfigurationDigestAuth{}
	return &this
}

// NewV2HttpConfigurationDigestAuthWithDefaults instantiates a new V2HttpConfigurationDigestAuth object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewV2HttpConfigurationDigestAuthWithDefaults() *V2HttpConfigurationDigestAuth {
	this := V2HttpConfigurationDigestAuth{}
	return &this
}

// GetUsername returns the Username field value if set, zero value otherwise.
func (o *V2HttpConfigurationDigestAuth) GetUsername() string {
	if o == nil || o.Username == nil {
		var ret string
		return ret
	}
	return *o.Username
}

// GetUsernameOk returns a tuple with the Username field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V2HttpConfigurationDigestAuth) GetUsernameOk() (*string, bool) {
	if o == nil || o.Username == nil {
		return nil, false
	}
	return o.Username, true
}

// HasUsername returns a boolean if a field has been set.
func (o *V2HttpConfigurationDigestAuth) HasUsername() bool {
	if o != nil && o.Username != nil {
		return true
	}

	return false
}

// SetUsername gets a reference to the given string and assigns it to the Username field.
func (o *V2HttpConfigurationDigestAuth) SetUsername(v string) {
	o.Username = &v
}

// GetPassword returns the Password field value if set, zero value otherwise.
func (o *V2HttpConfigurationDigestAuth) GetPassword() string {
	if o == nil || o.Password == nil {
		var ret string
		return ret
	}
	return *o.Password
}

// GetPasswordOk returns a tuple with the Password field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V2HttpConfigurationDigestAuth) GetPasswordOk() (*string, bool) {
	if o == nil || o.Password == nil {
		return nil, false
	}
	return o.Password, true
}

// HasPassword returns a boolean if a field has been set.
func (o *V2HttpConfigurationDigestAuth) HasPassword() bool {
	if o != nil && o.Password != nil {
		return true
	}

	return false
}

// SetPassword gets a reference to the given string and assigns it to the Password field.
func (o *V2HttpConfigurationDigestAuth) SetPassword(v string) {
	o.Password = &v
}

func (o V2HttpConfigurationDigestAuth) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Username != nil {
		toSerialize["username"] = o.Username
	}
	if o.Password != nil {
		toSerialize["password"] = o.Password
	}
	return json.Marshal(toSerialize)
}

type NullableV2HttpConfigurationDigestAuth struct {
	value *V2HttpConfigurationDigestAuth
	isSet bool
}

func (v NullableV2HttpConfigurationDigestAuth) Get() *V2HttpConfigurationDigestAuth {
	return v.value
}

func (v *NullableV2HttpConfigurationDigestAuth) Set(val *V2HttpConfigurationDigestAuth) {
	v.value = val
	v.isSet = true
}

func (v NullableV2HttpConfigurationDigestAuth) IsSet() bool {
	return v.isSet
}

func (v *NullableV2HttpConfigurationDigestAuth) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableV2HttpConfigurationDigestAuth(val *V2HttpConfigurationDigestAuth) *NullableV2HttpConfigurationDigestAuth {
	return &NullableV2HttpConfigurationDigestAuth{value: val, isSet: true}
}

func (v NullableV2HttpConfigurationDigestAuth) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableV2HttpConfigurationDigestAuth) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
