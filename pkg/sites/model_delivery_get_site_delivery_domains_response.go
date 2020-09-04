/*
 * Sites
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sites

import (
	"encoding/json"
)

// DeliveryGetSiteDeliveryDomainsResponse The response from a request to retrieve a site's associated delivery domains
type DeliveryGetSiteDeliveryDomainsResponse struct {
	PageInfo *PaginationPageInfo `json:"pageInfo,omitempty"`
	// The requested site delivery domains
	Results *[]SchemadeliveryDeliveryDomain `json:"results,omitempty"`
}

// NewDeliveryGetSiteDeliveryDomainsResponse instantiates a new DeliveryGetSiteDeliveryDomainsResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewDeliveryGetSiteDeliveryDomainsResponse() *DeliveryGetSiteDeliveryDomainsResponse {
	this := DeliveryGetSiteDeliveryDomainsResponse{}
	return &this
}

// NewDeliveryGetSiteDeliveryDomainsResponseWithDefaults instantiates a new DeliveryGetSiteDeliveryDomainsResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewDeliveryGetSiteDeliveryDomainsResponseWithDefaults() *DeliveryGetSiteDeliveryDomainsResponse {
	this := DeliveryGetSiteDeliveryDomainsResponse{}
	return &this
}

// GetPageInfo returns the PageInfo field value if set, zero value otherwise.
func (o *DeliveryGetSiteDeliveryDomainsResponse) GetPageInfo() PaginationPageInfo {
	if o == nil || o.PageInfo == nil {
		var ret PaginationPageInfo
		return ret
	}
	return *o.PageInfo
}

// GetPageInfoOk returns a tuple with the PageInfo field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DeliveryGetSiteDeliveryDomainsResponse) GetPageInfoOk() (*PaginationPageInfo, bool) {
	if o == nil || o.PageInfo == nil {
		return nil, false
	}
	return o.PageInfo, true
}

// HasPageInfo returns a boolean if a field has been set.
func (o *DeliveryGetSiteDeliveryDomainsResponse) HasPageInfo() bool {
	if o != nil && o.PageInfo != nil {
		return true
	}

	return false
}

// SetPageInfo gets a reference to the given PaginationPageInfo and assigns it to the PageInfo field.
func (o *DeliveryGetSiteDeliveryDomainsResponse) SetPageInfo(v PaginationPageInfo) {
	o.PageInfo = &v
}

// GetResults returns the Results field value if set, zero value otherwise.
func (o *DeliveryGetSiteDeliveryDomainsResponse) GetResults() []SchemadeliveryDeliveryDomain {
	if o == nil || o.Results == nil {
		var ret []SchemadeliveryDeliveryDomain
		return ret
	}
	return *o.Results
}

// GetResultsOk returns a tuple with the Results field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *DeliveryGetSiteDeliveryDomainsResponse) GetResultsOk() (*[]SchemadeliveryDeliveryDomain, bool) {
	if o == nil || o.Results == nil {
		return nil, false
	}
	return o.Results, true
}

// HasResults returns a boolean if a field has been set.
func (o *DeliveryGetSiteDeliveryDomainsResponse) HasResults() bool {
	if o != nil && o.Results != nil {
		return true
	}

	return false
}

// SetResults gets a reference to the given []SchemadeliveryDeliveryDomain and assigns it to the Results field.
func (o *DeliveryGetSiteDeliveryDomainsResponse) SetResults(v []SchemadeliveryDeliveryDomain) {
	o.Results = &v
}

func (o DeliveryGetSiteDeliveryDomainsResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.PageInfo != nil {
		toSerialize["pageInfo"] = o.PageInfo
	}
	if o.Results != nil {
		toSerialize["results"] = o.Results
	}
	return json.Marshal(toSerialize)
}

type NullableDeliveryGetSiteDeliveryDomainsResponse struct {
	value *DeliveryGetSiteDeliveryDomainsResponse
	isSet bool
}

func (v NullableDeliveryGetSiteDeliveryDomainsResponse) Get() *DeliveryGetSiteDeliveryDomainsResponse {
	return v.value
}

func (v *NullableDeliveryGetSiteDeliveryDomainsResponse) Set(val *DeliveryGetSiteDeliveryDomainsResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableDeliveryGetSiteDeliveryDomainsResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableDeliveryGetSiteDeliveryDomainsResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableDeliveryGetSiteDeliveryDomainsResponse(val *DeliveryGetSiteDeliveryDomainsResponse) *NullableDeliveryGetSiteDeliveryDomainsResponse {
	return &NullableDeliveryGetSiteDeliveryDomainsResponse{value: val, isSet: true}
}

func (v NullableDeliveryGetSiteDeliveryDomainsResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableDeliveryGetSiteDeliveryDomainsResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
