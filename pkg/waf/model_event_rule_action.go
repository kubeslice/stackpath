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

// EventRuleAction Aspects of the rule that triggered a WAF event
type EventRuleAction struct {
	// The name of the rule that triggered the event action
	RuleName *string `json:"ruleName,omitempty"`
	// The unique ID of the rule that triggered the event action
	RuleId *string `json:"ruleId,omitempty"`
	ActionTaken *WafRuleAction `json:"actionTaken,omitempty"`
	// Whether the requesting client was blocked or not
	Blocked *bool `json:"blocked,omitempty"`
	// The name of the internal WAF engine powering the rule
	Engine *string `json:"engine,omitempty"`
	RequestType *EventWafRequestType `json:"requestType,omitempty"`
	Result *RuleActionResultType `json:"result,omitempty"`
}

// NewEventRuleAction instantiates a new EventRuleAction object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewEventRuleAction() *EventRuleAction {
	this := EventRuleAction{}
	var actionTaken WafRuleAction = "BLOCK"
	this.ActionTaken = &actionTaken
	var requestType EventWafRequestType = "CHALLENGE"
	this.RequestType = &requestType
	var result RuleActionResultType = "RESULT_TYPE_UNSPECIFIED"
	this.Result = &result
	return &this
}

// NewEventRuleActionWithDefaults instantiates a new EventRuleAction object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewEventRuleActionWithDefaults() *EventRuleAction {
	this := EventRuleAction{}
	var actionTaken WafRuleAction = "BLOCK"
	this.ActionTaken = &actionTaken
	var requestType EventWafRequestType = "CHALLENGE"
	this.RequestType = &requestType
	var result RuleActionResultType = "RESULT_TYPE_UNSPECIFIED"
	this.Result = &result
	return &this
}

// GetRuleName returns the RuleName field value if set, zero value otherwise.
func (o *EventRuleAction) GetRuleName() string {
	if o == nil || o.RuleName == nil {
		var ret string
		return ret
	}
	return *o.RuleName
}

// GetRuleNameOk returns a tuple with the RuleName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EventRuleAction) GetRuleNameOk() (*string, bool) {
	if o == nil || o.RuleName == nil {
		return nil, false
	}
	return o.RuleName, true
}

// HasRuleName returns a boolean if a field has been set.
func (o *EventRuleAction) HasRuleName() bool {
	if o != nil && o.RuleName != nil {
		return true
	}

	return false
}

// SetRuleName gets a reference to the given string and assigns it to the RuleName field.
func (o *EventRuleAction) SetRuleName(v string) {
	o.RuleName = &v
}

// GetRuleId returns the RuleId field value if set, zero value otherwise.
func (o *EventRuleAction) GetRuleId() string {
	if o == nil || o.RuleId == nil {
		var ret string
		return ret
	}
	return *o.RuleId
}

// GetRuleIdOk returns a tuple with the RuleId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EventRuleAction) GetRuleIdOk() (*string, bool) {
	if o == nil || o.RuleId == nil {
		return nil, false
	}
	return o.RuleId, true
}

// HasRuleId returns a boolean if a field has been set.
func (o *EventRuleAction) HasRuleId() bool {
	if o != nil && o.RuleId != nil {
		return true
	}

	return false
}

// SetRuleId gets a reference to the given string and assigns it to the RuleId field.
func (o *EventRuleAction) SetRuleId(v string) {
	o.RuleId = &v
}

// GetActionTaken returns the ActionTaken field value if set, zero value otherwise.
func (o *EventRuleAction) GetActionTaken() WafRuleAction {
	if o == nil || o.ActionTaken == nil {
		var ret WafRuleAction
		return ret
	}
	return *o.ActionTaken
}

// GetActionTakenOk returns a tuple with the ActionTaken field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EventRuleAction) GetActionTakenOk() (*WafRuleAction, bool) {
	if o == nil || o.ActionTaken == nil {
		return nil, false
	}
	return o.ActionTaken, true
}

// HasActionTaken returns a boolean if a field has been set.
func (o *EventRuleAction) HasActionTaken() bool {
	if o != nil && o.ActionTaken != nil {
		return true
	}

	return false
}

// SetActionTaken gets a reference to the given WafRuleAction and assigns it to the ActionTaken field.
func (o *EventRuleAction) SetActionTaken(v WafRuleAction) {
	o.ActionTaken = &v
}

// GetBlocked returns the Blocked field value if set, zero value otherwise.
func (o *EventRuleAction) GetBlocked() bool {
	if o == nil || o.Blocked == nil {
		var ret bool
		return ret
	}
	return *o.Blocked
}

// GetBlockedOk returns a tuple with the Blocked field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EventRuleAction) GetBlockedOk() (*bool, bool) {
	if o == nil || o.Blocked == nil {
		return nil, false
	}
	return o.Blocked, true
}

// HasBlocked returns a boolean if a field has been set.
func (o *EventRuleAction) HasBlocked() bool {
	if o != nil && o.Blocked != nil {
		return true
	}

	return false
}

// SetBlocked gets a reference to the given bool and assigns it to the Blocked field.
func (o *EventRuleAction) SetBlocked(v bool) {
	o.Blocked = &v
}

// GetEngine returns the Engine field value if set, zero value otherwise.
func (o *EventRuleAction) GetEngine() string {
	if o == nil || o.Engine == nil {
		var ret string
		return ret
	}
	return *o.Engine
}

// GetEngineOk returns a tuple with the Engine field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EventRuleAction) GetEngineOk() (*string, bool) {
	if o == nil || o.Engine == nil {
		return nil, false
	}
	return o.Engine, true
}

// HasEngine returns a boolean if a field has been set.
func (o *EventRuleAction) HasEngine() bool {
	if o != nil && o.Engine != nil {
		return true
	}

	return false
}

// SetEngine gets a reference to the given string and assigns it to the Engine field.
func (o *EventRuleAction) SetEngine(v string) {
	o.Engine = &v
}

// GetRequestType returns the RequestType field value if set, zero value otherwise.
func (o *EventRuleAction) GetRequestType() EventWafRequestType {
	if o == nil || o.RequestType == nil {
		var ret EventWafRequestType
		return ret
	}
	return *o.RequestType
}

// GetRequestTypeOk returns a tuple with the RequestType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EventRuleAction) GetRequestTypeOk() (*EventWafRequestType, bool) {
	if o == nil || o.RequestType == nil {
		return nil, false
	}
	return o.RequestType, true
}

// HasRequestType returns a boolean if a field has been set.
func (o *EventRuleAction) HasRequestType() bool {
	if o != nil && o.RequestType != nil {
		return true
	}

	return false
}

// SetRequestType gets a reference to the given EventWafRequestType and assigns it to the RequestType field.
func (o *EventRuleAction) SetRequestType(v EventWafRequestType) {
	o.RequestType = &v
}

// GetResult returns the Result field value if set, zero value otherwise.
func (o *EventRuleAction) GetResult() RuleActionResultType {
	if o == nil || o.Result == nil {
		var ret RuleActionResultType
		return ret
	}
	return *o.Result
}

// GetResultOk returns a tuple with the Result field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *EventRuleAction) GetResultOk() (*RuleActionResultType, bool) {
	if o == nil || o.Result == nil {
		return nil, false
	}
	return o.Result, true
}

// HasResult returns a boolean if a field has been set.
func (o *EventRuleAction) HasResult() bool {
	if o != nil && o.Result != nil {
		return true
	}

	return false
}

// SetResult gets a reference to the given RuleActionResultType and assigns it to the Result field.
func (o *EventRuleAction) SetResult(v RuleActionResultType) {
	o.Result = &v
}

func (o EventRuleAction) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.RuleName != nil {
		toSerialize["ruleName"] = o.RuleName
	}
	if o.RuleId != nil {
		toSerialize["ruleId"] = o.RuleId
	}
	if o.ActionTaken != nil {
		toSerialize["actionTaken"] = o.ActionTaken
	}
	if o.Blocked != nil {
		toSerialize["blocked"] = o.Blocked
	}
	if o.Engine != nil {
		toSerialize["engine"] = o.Engine
	}
	if o.RequestType != nil {
		toSerialize["requestType"] = o.RequestType
	}
	if o.Result != nil {
		toSerialize["result"] = o.Result
	}
	return json.Marshal(toSerialize)
}

type NullableEventRuleAction struct {
	value *EventRuleAction
	isSet bool
}

func (v NullableEventRuleAction) Get() *EventRuleAction {
	return v.value
}

func (v *NullableEventRuleAction) Set(val *EventRuleAction) {
	v.value = val
	v.isSet = true
}

func (v NullableEventRuleAction) IsSet() bool {
	return v.isSet
}

func (v *NullableEventRuleAction) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableEventRuleAction(val *EventRuleAction) *NullableEventRuleAction {
	return &NullableEventRuleAction{value: val, isSet: true}
}

func (v NullableEventRuleAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableEventRuleAction) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
