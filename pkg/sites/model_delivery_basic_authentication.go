/*
 * Sites
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sites

import (
	"encoding/json"
)

// DeliveryBasicAuthentication Basic HTTP authentication
type DeliveryBasicAuthentication struct {
	// The username to be used when authenticating with the origin.
	Username *string `json:"username,omitempty"`
	// The password to be used when authenticating with the origin.
	Password *string `json:"password,omitempty"`
}

// NewDeliveryBasicAuthentication instantiates a new DeliveryBasicAuthentication object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDeliveryBasicAuthentication() *DeliveryBasicAuthentication {
	this := DeliveryBasicAuthentication{}
	return &this
}

// NewDeliveryBasicAuthenticationWithDefaults instantiates a new DeliveryBasicAuthentication object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDeliveryBasicAuthenticationWithDefaults() *DeliveryBasicAuthentication {
	this := DeliveryBasicAuthentication{}
	return &this
}

// GetUsername returns the Username field value if set, zero value otherwise.
func (o *DeliveryBasicAuthentication) GetUsername() string {
	if o == nil || o.Username == nil {
		var ret string
		return ret
	}
	return *o.Username
}

// GetUsernameOk returns a tuple with the Username field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DeliveryBasicAuthentication) GetUsernameOk() (*string, bool) {
	if o == nil || o.Username == nil {
		return nil, false
	}
	return o.Username, true
}

// HasUsername returns a boolean if a field has been set.
func (o *DeliveryBasicAuthentication) HasUsername() bool {
	if o != nil && o.Username != nil {
		return true
	}

	return false
}

// SetUsername gets a reference to the given string and assigns it to the Username field.
func (o *DeliveryBasicAuthentication) SetUsername(v string) {
	o.Username = &v
}

// GetPassword returns the Password field value if set, zero value otherwise.
func (o *DeliveryBasicAuthentication) GetPassword() string {
	if o == nil || o.Password == nil {
		var ret string
		return ret
	}
	return *o.Password
}

// GetPasswordOk returns a tuple with the Password field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DeliveryBasicAuthentication) GetPasswordOk() (*string, bool) {
	if o == nil || o.Password == nil {
		return nil, false
	}
	return o.Password, true
}

// HasPassword returns a boolean if a field has been set.
func (o *DeliveryBasicAuthentication) HasPassword() bool {
	if o != nil && o.Password != nil {
		return true
	}

	return false
}

// SetPassword gets a reference to the given string and assigns it to the Password field.
func (o *DeliveryBasicAuthentication) SetPassword(v string) {
	o.Password = &v
}

func (o DeliveryBasicAuthentication) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Username != nil {
		toSerialize["username"] = o.Username
	}
	if o.Password != nil {
		toSerialize["password"] = o.Password
	}
	return json.Marshal(toSerialize)
}

type NullableDeliveryBasicAuthentication struct {
	value *DeliveryBasicAuthentication
	isSet bool
}

func (v NullableDeliveryBasicAuthentication) Get() *DeliveryBasicAuthentication {
	return v.value
}

func (v *NullableDeliveryBasicAuthentication) Set(val *DeliveryBasicAuthentication) {
	v.value = val
	v.isSet = true
}

func (v NullableDeliveryBasicAuthentication) IsSet() bool {
	return v.isSet
}

func (v *NullableDeliveryBasicAuthentication) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDeliveryBasicAuthentication(val *DeliveryBasicAuthentication) *NullableDeliveryBasicAuthentication {
	return &NullableDeliveryBasicAuthentication{value: val, isSet: true}
}

func (v NullableDeliveryBasicAuthentication) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDeliveryBasicAuthentication) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
