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

// WafPolicyAction The potential actions that the WAF will take when a policy is triggered
type WafPolicyAction string

// List of wafPolicyAction
const (
	WAFPOLICYACTION_BLOCK WafPolicyAction = "BLOCK"
	WAFPOLICYACTION_ALLOW WafPolicyAction = "ALLOW"
	WAFPOLICYACTION_CAPTCHA WafPolicyAction = "CAPTCHA"
	WAFPOLICYACTION_HANDSHAKE WafPolicyAction = "HANDSHAKE"
	WAFPOLICYACTION_MONITOR WafPolicyAction = "MONITOR"
)

// Ptr returns reference to wafPolicyAction value
func (v WafPolicyAction) Ptr() *WafPolicyAction {
	return &v
}


type NullableWafPolicyAction struct {
	value *WafPolicyAction
	isSet bool
}

func (v NullableWafPolicyAction) Get() *WafPolicyAction {
	return v.value
}

func (v *NullableWafPolicyAction) Set(val *WafPolicyAction) {
	v.value = val
	v.isSet = true
}

func (v NullableWafPolicyAction) IsSet() bool {
	return v.isSet
}

func (v *NullableWafPolicyAction) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableWafPolicyAction(val *WafPolicyAction) *NullableWafPolicyAction {
	return &NullableWafPolicyAction{value: val, isSet: true}
}

func (v NullableWafPolicyAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableWafPolicyAction) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
