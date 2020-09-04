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

// StatisticsMetrics A collection of common event metrics for a single WAF action
type StatisticsMetrics struct {
	// The \"top threats\" metric, the number of events encountered per rule
	Rules *[]MetricsRules `json:"rules,omitempty"`
	// The number of events per country of origin
	Countries *[]MetricsCountries `json:"countries,omitempty"`
	// The number of events per requesting organization, as determined by WHOIS lookup on the requesting IP
	Organizations *[]MetricsOrganizations `json:"organizations,omitempty"`
	// The number of events per action taken by the WAF
	Actions *[]MetricsActions `json:"actions,omitempty"`
}

// NewStatisticsMetrics instantiates a new StatisticsMetrics object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStatisticsMetrics() *StatisticsMetrics {
	this := StatisticsMetrics{}
	return &this
}

// NewStatisticsMetricsWithDefaults instantiates a new StatisticsMetrics object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStatisticsMetricsWithDefaults() *StatisticsMetrics {
	this := StatisticsMetrics{}
	return &this
}

// GetRules returns the Rules field value if set, zero value otherwise.
func (o *StatisticsMetrics) GetRules() []MetricsRules {
	if o == nil || o.Rules == nil {
		var ret []MetricsRules
		return ret
	}
	return *o.Rules
}

// GetRulesOk returns a tuple with the Rules field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StatisticsMetrics) GetRulesOk() (*[]MetricsRules, bool) {
	if o == nil || o.Rules == nil {
		return nil, false
	}
	return o.Rules, true
}

// HasRules returns a boolean if a field has been set.
func (o *StatisticsMetrics) HasRules() bool {
	if o != nil && o.Rules != nil {
		return true
	}

	return false
}

// SetRules gets a reference to the given []MetricsRules and assigns it to the Rules field.
func (o *StatisticsMetrics) SetRules(v []MetricsRules) {
	o.Rules = &v
}

// GetCountries returns the Countries field value if set, zero value otherwise.
func (o *StatisticsMetrics) GetCountries() []MetricsCountries {
	if o == nil || o.Countries == nil {
		var ret []MetricsCountries
		return ret
	}
	return *o.Countries
}

// GetCountriesOk returns a tuple with the Countries field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StatisticsMetrics) GetCountriesOk() (*[]MetricsCountries, bool) {
	if o == nil || o.Countries == nil {
		return nil, false
	}
	return o.Countries, true
}

// HasCountries returns a boolean if a field has been set.
func (o *StatisticsMetrics) HasCountries() bool {
	if o != nil && o.Countries != nil {
		return true
	}

	return false
}

// SetCountries gets a reference to the given []MetricsCountries and assigns it to the Countries field.
func (o *StatisticsMetrics) SetCountries(v []MetricsCountries) {
	o.Countries = &v
}

// GetOrganizations returns the Organizations field value if set, zero value otherwise.
func (o *StatisticsMetrics) GetOrganizations() []MetricsOrganizations {
	if o == nil || o.Organizations == nil {
		var ret []MetricsOrganizations
		return ret
	}
	return *o.Organizations
}

// GetOrganizationsOk returns a tuple with the Organizations field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StatisticsMetrics) GetOrganizationsOk() (*[]MetricsOrganizations, bool) {
	if o == nil || o.Organizations == nil {
		return nil, false
	}
	return o.Organizations, true
}

// HasOrganizations returns a boolean if a field has been set.
func (o *StatisticsMetrics) HasOrganizations() bool {
	if o != nil && o.Organizations != nil {
		return true
	}

	return false
}

// SetOrganizations gets a reference to the given []MetricsOrganizations and assigns it to the Organizations field.
func (o *StatisticsMetrics) SetOrganizations(v []MetricsOrganizations) {
	o.Organizations = &v
}

// GetActions returns the Actions field value if set, zero value otherwise.
func (o *StatisticsMetrics) GetActions() []MetricsActions {
	if o == nil || o.Actions == nil {
		var ret []MetricsActions
		return ret
	}
	return *o.Actions
}

// GetActionsOk returns a tuple with the Actions field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StatisticsMetrics) GetActionsOk() (*[]MetricsActions, bool) {
	if o == nil || o.Actions == nil {
		return nil, false
	}
	return o.Actions, true
}

// HasActions returns a boolean if a field has been set.
func (o *StatisticsMetrics) HasActions() bool {
	if o != nil && o.Actions != nil {
		return true
	}

	return false
}

// SetActions gets a reference to the given []MetricsActions and assigns it to the Actions field.
func (o *StatisticsMetrics) SetActions(v []MetricsActions) {
	o.Actions = &v
}

func (o StatisticsMetrics) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Rules != nil {
		toSerialize["rules"] = o.Rules
	}
	if o.Countries != nil {
		toSerialize["countries"] = o.Countries
	}
	if o.Organizations != nil {
		toSerialize["organizations"] = o.Organizations
	}
	if o.Actions != nil {
		toSerialize["actions"] = o.Actions
	}
	return json.Marshal(toSerialize)
}

type NullableStatisticsMetrics struct {
	value *StatisticsMetrics
	isSet bool
}

func (v NullableStatisticsMetrics) Get() *StatisticsMetrics {
	return v.value
}

func (v *NullableStatisticsMetrics) Set(val *StatisticsMetrics) {
	v.value = val
	v.isSet = true
}

func (v NullableStatisticsMetrics) IsSet() bool {
	return v.isSet
}

func (v *NullableStatisticsMetrics) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStatisticsMetrics(val *StatisticsMetrics) *NullableStatisticsMetrics {
	return &NullableStatisticsMetrics{value: val, isSet: true}
}

func (v NullableStatisticsMetrics) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStatisticsMetrics) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
