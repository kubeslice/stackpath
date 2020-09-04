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

// IdentityGetAccessTokenRequest struct for IdentityGetAccessTokenRequest
type IdentityGetAccessTokenRequest struct {
	// The OAuth2 grant type  Currently, only the \"client_credentials\" grant type is supported.
	GrantType *string `json:"grant_type,omitempty"`
	// The client ID from your API credential
	ClientId *string `json:"client_id,omitempty"`
	// The client secret from your API credential  For security reasons, client secrets are not stored in StackPath's internal systems after they are generated. Please record your API client secret after generating it.
	ClientSecret *string `json:"client_secret,omitempty"`
}

// NewIdentityGetAccessTokenRequest instantiates a new IdentityGetAccessTokenRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewIdentityGetAccessTokenRequest() *IdentityGetAccessTokenRequest {
	this := IdentityGetAccessTokenRequest{}
	var grantType string = "client_credentials"
	this.GrantType = &grantType
	return &this
}

// NewIdentityGetAccessTokenRequestWithDefaults instantiates a new IdentityGetAccessTokenRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewIdentityGetAccessTokenRequestWithDefaults() *IdentityGetAccessTokenRequest {
	this := IdentityGetAccessTokenRequest{}
	var grantType string = "client_credentials"
	this.GrantType = &grantType
	return &this
}

// GetGrantType returns the GrantType field value if set, zero value otherwise.
func (o *IdentityGetAccessTokenRequest) GetGrantType() string {
	if o == nil || o.GrantType == nil {
		var ret string
		return ret
	}
	return *o.GrantType
}

// GetGrantTypeOk returns a tuple with the GrantType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *IdentityGetAccessTokenRequest) GetGrantTypeOk() (*string, bool) {
	if o == nil || o.GrantType == nil {
		return nil, false
	}
	return o.GrantType, true
}

// HasGrantType returns a boolean if a field has been set.
func (o *IdentityGetAccessTokenRequest) HasGrantType() bool {
	if o != nil && o.GrantType != nil {
		return true
	}

	return false
}

// SetGrantType gets a reference to the given string and assigns it to the GrantType field.
func (o *IdentityGetAccessTokenRequest) SetGrantType(v string) {
	o.GrantType = &v
}

// GetClientId returns the ClientId field value if set, zero value otherwise.
func (o *IdentityGetAccessTokenRequest) GetClientId() string {
	if o == nil || o.ClientId == nil {
		var ret string
		return ret
	}
	return *o.ClientId
}

// GetClientIdOk returns a tuple with the ClientId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *IdentityGetAccessTokenRequest) GetClientIdOk() (*string, bool) {
	if o == nil || o.ClientId == nil {
		return nil, false
	}
	return o.ClientId, true
}

// HasClientId returns a boolean if a field has been set.
func (o *IdentityGetAccessTokenRequest) HasClientId() bool {
	if o != nil && o.ClientId != nil {
		return true
	}

	return false
}

// SetClientId gets a reference to the given string and assigns it to the ClientId field.
func (o *IdentityGetAccessTokenRequest) SetClientId(v string) {
	o.ClientId = &v
}

// GetClientSecret returns the ClientSecret field value if set, zero value otherwise.
func (o *IdentityGetAccessTokenRequest) GetClientSecret() string {
	if o == nil || o.ClientSecret == nil {
		var ret string
		return ret
	}
	return *o.ClientSecret
}

// GetClientSecretOk returns a tuple with the ClientSecret field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *IdentityGetAccessTokenRequest) GetClientSecretOk() (*string, bool) {
	if o == nil || o.ClientSecret == nil {
		return nil, false
	}
	return o.ClientSecret, true
}

// HasClientSecret returns a boolean if a field has been set.
func (o *IdentityGetAccessTokenRequest) HasClientSecret() bool {
	if o != nil && o.ClientSecret != nil {
		return true
	}

	return false
}

// SetClientSecret gets a reference to the given string and assigns it to the ClientSecret field.
func (o *IdentityGetAccessTokenRequest) SetClientSecret(v string) {
	o.ClientSecret = &v
}

func (o IdentityGetAccessTokenRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.GrantType != nil {
		toSerialize["grant_type"] = o.GrantType
	}
	if o.ClientId != nil {
		toSerialize["client_id"] = o.ClientId
	}
	if o.ClientSecret != nil {
		toSerialize["client_secret"] = o.ClientSecret
	}
	return json.Marshal(toSerialize)
}

type NullableIdentityGetAccessTokenRequest struct {
	value *IdentityGetAccessTokenRequest
	isSet bool
}

func (v NullableIdentityGetAccessTokenRequest) Get() *IdentityGetAccessTokenRequest {
	return v.value
}

func (v *NullableIdentityGetAccessTokenRequest) Set(val *IdentityGetAccessTokenRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableIdentityGetAccessTokenRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableIdentityGetAccessTokenRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableIdentityGetAccessTokenRequest(val *IdentityGetAccessTokenRequest) *NullableIdentityGetAccessTokenRequest {
	return &NullableIdentityGetAccessTokenRequest{value: val, isSet: true}
}

func (v NullableIdentityGetAccessTokenRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableIdentityGetAccessTokenRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
