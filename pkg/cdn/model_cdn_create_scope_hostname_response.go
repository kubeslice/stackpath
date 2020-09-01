/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn

import (
	"encoding/json"
)

// CdnCreateScopeHostnameResponse The response from a request to add a hostname to a CDN site scope
type CdnCreateScopeHostnameResponse struct {
	Hostname *CdnHostname `json:"hostname,omitempty"`
}

// NewCdnCreateScopeHostnameResponse instantiates a new CdnCreateScopeHostnameResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCdnCreateScopeHostnameResponse() *CdnCreateScopeHostnameResponse {
	this := CdnCreateScopeHostnameResponse{}
	return &this
}

// NewCdnCreateScopeHostnameResponseWithDefaults instantiates a new CdnCreateScopeHostnameResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCdnCreateScopeHostnameResponseWithDefaults() *CdnCreateScopeHostnameResponse {
	this := CdnCreateScopeHostnameResponse{}
	return &this
}

// GetHostname returns the Hostname field value if set, zero value otherwise.
func (o *CdnCreateScopeHostnameResponse) GetHostname() CdnHostname {
	if o == nil || o.Hostname == nil {
		var ret CdnHostname
		return ret
	}
	return *o.Hostname
}

// GetHostnameOk returns a tuple with the Hostname field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CdnCreateScopeHostnameResponse) GetHostnameOk() (*CdnHostname, bool) {
	if o == nil || o.Hostname == nil {
		return nil, false
	}
	return o.Hostname, true
}

// HasHostname returns a boolean if a field has been set.
func (o *CdnCreateScopeHostnameResponse) HasHostname() bool {
	if o != nil && o.Hostname != nil {
		return true
	}

	return false
}

// SetHostname gets a reference to the given CdnHostname and assigns it to the Hostname field.
func (o *CdnCreateScopeHostnameResponse) SetHostname(v CdnHostname) {
	o.Hostname = &v
}

func (o CdnCreateScopeHostnameResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Hostname != nil {
		toSerialize["hostname"] = o.Hostname
	}
	return json.Marshal(toSerialize)
}

type NullableCdnCreateScopeHostnameResponse struct {
	value *CdnCreateScopeHostnameResponse
	isSet bool
}

func (v NullableCdnCreateScopeHostnameResponse) Get() *CdnCreateScopeHostnameResponse {
	return v.value
}

func (v *NullableCdnCreateScopeHostnameResponse) Set(val *CdnCreateScopeHostnameResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableCdnCreateScopeHostnameResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableCdnCreateScopeHostnameResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCdnCreateScopeHostnameResponse(val *CdnCreateScopeHostnameResponse) *NullableCdnCreateScopeHostnameResponse {
	return &NullableCdnCreateScopeHostnameResponse{value: val, isSet: true}
}

func (v NullableCdnCreateScopeHostnameResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCdnCreateScopeHostnameResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
