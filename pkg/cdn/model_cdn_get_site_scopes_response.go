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

// CdnGetSiteScopesResponse The response from request to a CDN site's scopes
type CdnGetSiteScopesResponse struct {
	PageInfo *PaginationPageInfo `json:"pageInfo,omitempty"`
	// The requested scopes
	Results *[]CdnScope `json:"results,omitempty"`
}

// NewCdnGetSiteScopesResponse instantiates a new CdnGetSiteScopesResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCdnGetSiteScopesResponse() *CdnGetSiteScopesResponse {
	this := CdnGetSiteScopesResponse{}
	return &this
}

// NewCdnGetSiteScopesResponseWithDefaults instantiates a new CdnGetSiteScopesResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCdnGetSiteScopesResponseWithDefaults() *CdnGetSiteScopesResponse {
	this := CdnGetSiteScopesResponse{}
	return &this
}

// GetPageInfo returns the PageInfo field value if set, zero value otherwise.
func (o *CdnGetSiteScopesResponse) GetPageInfo() PaginationPageInfo {
	if o == nil || o.PageInfo == nil {
		var ret PaginationPageInfo
		return ret
	}
	return *o.PageInfo
}

// GetPageInfoOk returns a tuple with the PageInfo field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CdnGetSiteScopesResponse) GetPageInfoOk() (*PaginationPageInfo, bool) {
	if o == nil || o.PageInfo == nil {
		return nil, false
	}
	return o.PageInfo, true
}

// HasPageInfo returns a boolean if a field has been set.
func (o *CdnGetSiteScopesResponse) HasPageInfo() bool {
	if o != nil && o.PageInfo != nil {
		return true
	}

	return false
}

// SetPageInfo gets a reference to the given PaginationPageInfo and assigns it to the PageInfo field.
func (o *CdnGetSiteScopesResponse) SetPageInfo(v PaginationPageInfo) {
	o.PageInfo = &v
}

// GetResults returns the Results field value if set, zero value otherwise.
func (o *CdnGetSiteScopesResponse) GetResults() []CdnScope {
	if o == nil || o.Results == nil {
		var ret []CdnScope
		return ret
	}
	return *o.Results
}

// GetResultsOk returns a tuple with the Results field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CdnGetSiteScopesResponse) GetResultsOk() (*[]CdnScope, bool) {
	if o == nil || o.Results == nil {
		return nil, false
	}
	return o.Results, true
}

// HasResults returns a boolean if a field has been set.
func (o *CdnGetSiteScopesResponse) HasResults() bool {
	if o != nil && o.Results != nil {
		return true
	}

	return false
}

// SetResults gets a reference to the given []CdnScope and assigns it to the Results field.
func (o *CdnGetSiteScopesResponse) SetResults(v []CdnScope) {
	o.Results = &v
}

func (o CdnGetSiteScopesResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.PageInfo != nil {
		toSerialize["pageInfo"] = o.PageInfo
	}
	if o.Results != nil {
		toSerialize["results"] = o.Results
	}
	return json.Marshal(toSerialize)
}

type NullableCdnGetSiteScopesResponse struct {
	value *CdnGetSiteScopesResponse
	isSet bool
}

func (v NullableCdnGetSiteScopesResponse) Get() *CdnGetSiteScopesResponse {
	return v.value
}

func (v *NullableCdnGetSiteScopesResponse) Set(val *CdnGetSiteScopesResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableCdnGetSiteScopesResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableCdnGetSiteScopesResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCdnGetSiteScopesResponse(val *CdnGetSiteScopesResponse) *NullableCdnGetSiteScopesResponse {
	return &NullableCdnGetSiteScopesResponse{value: val, isSet: true}
}

func (v NullableCdnGetSiteScopesResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCdnGetSiteScopesResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
