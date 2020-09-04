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

// WafCreateSiteRequestType A WAF site's type  A site's type determines how StackPath delivers content to incoming HTTP requests.   - WAF: The site is either a standalone WAF site or a WAF site with attached CDN service  - API: The site is an API delivery site. API delivery sites are powered by both the WAF and CDN and have custom rulesets for each.
type WafCreateSiteRequestType string

// List of wafCreateSiteRequestType
const (
	WAFCREATESITEREQUESTTYPE_WAF WafCreateSiteRequestType = "WAF"
	WAFCREATESITEREQUESTTYPE_API WafCreateSiteRequestType = "API"
)

// Ptr returns reference to wafCreateSiteRequestType value
func (v WafCreateSiteRequestType) Ptr() *WafCreateSiteRequestType {
	return &v
}


type NullableWafCreateSiteRequestType struct {
	value *WafCreateSiteRequestType
	isSet bool
}

func (v NullableWafCreateSiteRequestType) Get() *WafCreateSiteRequestType {
	return v.value
}

func (v *NullableWafCreateSiteRequestType) Set(val *WafCreateSiteRequestType) {
	v.value = val
	v.isSet = true
}

func (v NullableWafCreateSiteRequestType) IsSet() bool {
	return v.isSet
}

func (v *NullableWafCreateSiteRequestType) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableWafCreateSiteRequestType(val *WafCreateSiteRequestType) *NullableWafCreateSiteRequestType {
	return &NullableWafCreateSiteRequestType{value: val, isSet: true}
}

func (v NullableWafCreateSiteRequestType) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableWafCreateSiteRequestType) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
