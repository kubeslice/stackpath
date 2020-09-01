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

// MetricsActions The number of events per action taken by the WAF
type MetricsActions struct {
	Action *WafRuleAction `json:"action,omitempty"`
	// The number of requests that resulted in that action
	Count *string `json:"count,omitempty"`
}

// NewMetricsActions instantiates a new MetricsActions object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewMetricsActions() *MetricsActions {
	this := MetricsActions{}
	var action WafRuleAction = "BLOCK"
	this.Action = &action
	return &this
}

// NewMetricsActionsWithDefaults instantiates a new MetricsActions object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewMetricsActionsWithDefaults() *MetricsActions {
	this := MetricsActions{}
	var action WafRuleAction = "BLOCK"
	this.Action = &action
	return &this
}

// GetAction returns the Action field value if set, zero value otherwise.
func (o *MetricsActions) GetAction() WafRuleAction {
	if o == nil || o.Action == nil {
		var ret WafRuleAction
		return ret
	}
	return *o.Action
}

// GetActionOk returns a tuple with the Action field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *MetricsActions) GetActionOk() (*WafRuleAction, bool) {
	if o == nil || o.Action == nil {
		return nil, false
	}
	return o.Action, true
}

// HasAction returns a boolean if a field has been set.
func (o *MetricsActions) HasAction() bool {
	if o != nil && o.Action != nil {
		return true
	}

	return false
}

// SetAction gets a reference to the given WafRuleAction and assigns it to the Action field.
func (o *MetricsActions) SetAction(v WafRuleAction) {
	o.Action = &v
}

// GetCount returns the Count field value if set, zero value otherwise.
func (o *MetricsActions) GetCount() string {
	if o == nil || o.Count == nil {
		var ret string
		return ret
	}
	return *o.Count
}

// GetCountOk returns a tuple with the Count field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *MetricsActions) GetCountOk() (*string, bool) {
	if o == nil || o.Count == nil {
		return nil, false
	}
	return o.Count, true
}

// HasCount returns a boolean if a field has been set.
func (o *MetricsActions) HasCount() bool {
	if o != nil && o.Count != nil {
		return true
	}

	return false
}

// SetCount gets a reference to the given string and assigns it to the Count field.
func (o *MetricsActions) SetCount(v string) {
	o.Count = &v
}

func (o MetricsActions) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Action != nil {
		toSerialize["action"] = o.Action
	}
	if o.Count != nil {
		toSerialize["count"] = o.Count
	}
	return json.Marshal(toSerialize)
}

type NullableMetricsActions struct {
	value *MetricsActions
	isSet bool
}

func (v NullableMetricsActions) Get() *MetricsActions {
	return v.value
}

func (v *NullableMetricsActions) Set(val *MetricsActions) {
	v.value = val
	v.isSet = true
}

func (v NullableMetricsActions) IsSet() bool {
	return v.isSet
}

func (v *NullableMetricsActions) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableMetricsActions(val *MetricsActions) *NullableMetricsActions {
	return &NullableMetricsActions{value: val, isSet: true}
}

func (v NullableMetricsActions) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableMetricsActions) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
