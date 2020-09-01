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

// CdnCreateScopeRuleResponse The response from a request to create a new EdgeRule
type CdnCreateScopeRuleResponse struct {
	Rule *CdnScopeRule `json:"rule,omitempty"`
	Configuration *CustconfConfiguration `json:"configuration,omitempty"`
}

// NewCdnCreateScopeRuleResponse instantiates a new CdnCreateScopeRuleResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCdnCreateScopeRuleResponse() *CdnCreateScopeRuleResponse {
	this := CdnCreateScopeRuleResponse{}
	return &this
}

// NewCdnCreateScopeRuleResponseWithDefaults instantiates a new CdnCreateScopeRuleResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCdnCreateScopeRuleResponseWithDefaults() *CdnCreateScopeRuleResponse {
	this := CdnCreateScopeRuleResponse{}
	return &this
}

// GetRule returns the Rule field value if set, zero value otherwise.
func (o *CdnCreateScopeRuleResponse) GetRule() CdnScopeRule {
	if o == nil || o.Rule == nil {
		var ret CdnScopeRule
		return ret
	}
	return *o.Rule
}

// GetRuleOk returns a tuple with the Rule field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CdnCreateScopeRuleResponse) GetRuleOk() (*CdnScopeRule, bool) {
	if o == nil || o.Rule == nil {
		return nil, false
	}
	return o.Rule, true
}

// HasRule returns a boolean if a field has been set.
func (o *CdnCreateScopeRuleResponse) HasRule() bool {
	if o != nil && o.Rule != nil {
		return true
	}

	return false
}

// SetRule gets a reference to the given CdnScopeRule and assigns it to the Rule field.
func (o *CdnCreateScopeRuleResponse) SetRule(v CdnScopeRule) {
	o.Rule = &v
}

// GetConfiguration returns the Configuration field value if set, zero value otherwise.
func (o *CdnCreateScopeRuleResponse) GetConfiguration() CustconfConfiguration {
	if o == nil || o.Configuration == nil {
		var ret CustconfConfiguration
		return ret
	}
	return *o.Configuration
}

// GetConfigurationOk returns a tuple with the Configuration field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CdnCreateScopeRuleResponse) GetConfigurationOk() (*CustconfConfiguration, bool) {
	if o == nil || o.Configuration == nil {
		return nil, false
	}
	return o.Configuration, true
}

// HasConfiguration returns a boolean if a field has been set.
func (o *CdnCreateScopeRuleResponse) HasConfiguration() bool {
	if o != nil && o.Configuration != nil {
		return true
	}

	return false
}

// SetConfiguration gets a reference to the given CustconfConfiguration and assigns it to the Configuration field.
func (o *CdnCreateScopeRuleResponse) SetConfiguration(v CustconfConfiguration) {
	o.Configuration = &v
}

func (o CdnCreateScopeRuleResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Rule != nil {
		toSerialize["rule"] = o.Rule
	}
	if o.Configuration != nil {
		toSerialize["configuration"] = o.Configuration
	}
	return json.Marshal(toSerialize)
}

type NullableCdnCreateScopeRuleResponse struct {
	value *CdnCreateScopeRuleResponse
	isSet bool
}

func (v NullableCdnCreateScopeRuleResponse) Get() *CdnCreateScopeRuleResponse {
	return v.value
}

func (v *NullableCdnCreateScopeRuleResponse) Set(val *CdnCreateScopeRuleResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableCdnCreateScopeRuleResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableCdnCreateScopeRuleResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCdnCreateScopeRuleResponse(val *CdnCreateScopeRuleResponse) *NullableCdnCreateScopeRuleResponse {
	return &NullableCdnCreateScopeRuleResponse{value: val, isSet: true}
}

func (v NullableCdnCreateScopeRuleResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCdnCreateScopeRuleResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
