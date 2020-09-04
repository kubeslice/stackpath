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

// CdnGetScopeConfigurationResponse The response from a request to retrieve a CDN site scope's configuration
type CdnGetScopeConfigurationResponse struct {
	Configuration *CustconfConfiguration `json:"configuration,omitempty"`
}

// NewCdnGetScopeConfigurationResponse instantiates a new CdnGetScopeConfigurationResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCdnGetScopeConfigurationResponse() *CdnGetScopeConfigurationResponse {
	this := CdnGetScopeConfigurationResponse{}
	return &this
}

// NewCdnGetScopeConfigurationResponseWithDefaults instantiates a new CdnGetScopeConfigurationResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCdnGetScopeConfigurationResponseWithDefaults() *CdnGetScopeConfigurationResponse {
	this := CdnGetScopeConfigurationResponse{}
	return &this
}

// GetConfiguration returns the Configuration field value if set, zero value otherwise.
func (o *CdnGetScopeConfigurationResponse) GetConfiguration() CustconfConfiguration {
	if o == nil || o.Configuration == nil {
		var ret CustconfConfiguration
		return ret
	}
	return *o.Configuration
}

// GetConfigurationOk returns a tuple with the Configuration field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CdnGetScopeConfigurationResponse) GetConfigurationOk() (*CustconfConfiguration, bool) {
	if o == nil || o.Configuration == nil {
		return nil, false
	}
	return o.Configuration, true
}

// HasConfiguration returns a boolean if a field has been set.
func (o *CdnGetScopeConfigurationResponse) HasConfiguration() bool {
	if o != nil && o.Configuration != nil {
		return true
	}

	return false
}

// SetConfiguration gets a reference to the given CustconfConfiguration and assigns it to the Configuration field.
func (o *CdnGetScopeConfigurationResponse) SetConfiguration(v CustconfConfiguration) {
	o.Configuration = &v
}

func (o CdnGetScopeConfigurationResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Configuration != nil {
		toSerialize["configuration"] = o.Configuration
	}
	return json.Marshal(toSerialize)
}

type NullableCdnGetScopeConfigurationResponse struct {
	value *CdnGetScopeConfigurationResponse
	isSet bool
}

func (v NullableCdnGetScopeConfigurationResponse) Get() *CdnGetScopeConfigurationResponse {
	return v.value
}

func (v *NullableCdnGetScopeConfigurationResponse) Set(val *CdnGetScopeConfigurationResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableCdnGetScopeConfigurationResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableCdnGetScopeConfigurationResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCdnGetScopeConfigurationResponse(val *CdnGetScopeConfigurationResponse) *NullableCdnGetScopeConfigurationResponse {
	return &NullableCdnGetScopeConfigurationResponse{value: val, isSet: true}
}

func (v NullableCdnGetScopeConfigurationResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCdnGetScopeConfigurationResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
