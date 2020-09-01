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

// CdnSiteFeature The features available to CDN sites  Multiple products can be served on a single CDN site. Features control how those products are managed on the StackPath backend.   - UNKNOWN: StackPath is unable to determine a site's feature  - CDN: A site has CDN caching abilities  - WAF: A site is protected by the StackPath Web Application Firewall
type CdnSiteFeature string

// List of cdnSiteFeature
const (
	UNKNOWN CdnSiteFeature = "UNKNOWN"
	CDN CdnSiteFeature = "CDN"
	WAF CdnSiteFeature = "WAF"
)

// Ptr returns reference to cdnSiteFeature value
func (v CdnSiteFeature) Ptr() *CdnSiteFeature {
	return &v
}


type NullableCdnSiteFeature struct {
	value *CdnSiteFeature
	isSet bool
}

func (v NullableCdnSiteFeature) Get() *CdnSiteFeature {
	return v.value
}

func (v *NullableCdnSiteFeature) Set(val *CdnSiteFeature) {
	v.value = val
	v.isSet = true
}

func (v NullableCdnSiteFeature) IsSet() bool {
	return v.isSet
}

func (v *NullableCdnSiteFeature) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCdnSiteFeature(val *CdnSiteFeature) *NullableCdnSiteFeature {
	return &NullableCdnSiteFeature{value: val, isSet: true}
}

func (v NullableCdnSiteFeature) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCdnSiteFeature) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
