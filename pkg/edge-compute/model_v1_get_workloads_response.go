/*
 * Edge Compute
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge-compute

import (
	"encoding/json"
)

// V1GetWorkloadsResponse A response from a request to retrieve a stack's workloads
type V1GetWorkloadsResponse struct {
	PageInfo *PaginationPageInfo `json:"pageInfo,omitempty"`
	// The requested workloads
	Results *[]V1Workload `json:"results,omitempty"`
}

// NewV1GetWorkloadsResponse instantiates a new V1GetWorkloadsResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewV1GetWorkloadsResponse() *V1GetWorkloadsResponse {
	this := V1GetWorkloadsResponse{}
	return &this
}

// NewV1GetWorkloadsResponseWithDefaults instantiates a new V1GetWorkloadsResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewV1GetWorkloadsResponseWithDefaults() *V1GetWorkloadsResponse {
	this := V1GetWorkloadsResponse{}
	return &this
}

// GetPageInfo returns the PageInfo field value if set, zero value otherwise.
func (o *V1GetWorkloadsResponse) GetPageInfo() PaginationPageInfo {
	if o == nil || o.PageInfo == nil {
		var ret PaginationPageInfo
		return ret
	}
	return *o.PageInfo
}

// GetPageInfoOk returns a tuple with the PageInfo field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1GetWorkloadsResponse) GetPageInfoOk() (*PaginationPageInfo, bool) {
	if o == nil || o.PageInfo == nil {
		return nil, false
	}
	return o.PageInfo, true
}

// HasPageInfo returns a boolean if a field has been set.
func (o *V1GetWorkloadsResponse) HasPageInfo() bool {
	if o != nil && o.PageInfo != nil {
		return true
	}

	return false
}

// SetPageInfo gets a reference to the given PaginationPageInfo and assigns it to the PageInfo field.
func (o *V1GetWorkloadsResponse) SetPageInfo(v PaginationPageInfo) {
	o.PageInfo = &v
}

// GetResults returns the Results field value if set, zero value otherwise.
func (o *V1GetWorkloadsResponse) GetResults() []V1Workload {
	if o == nil || o.Results == nil {
		var ret []V1Workload
		return ret
	}
	return *o.Results
}

// GetResultsOk returns a tuple with the Results field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1GetWorkloadsResponse) GetResultsOk() (*[]V1Workload, bool) {
	if o == nil || o.Results == nil {
		return nil, false
	}
	return o.Results, true
}

// HasResults returns a boolean if a field has been set.
func (o *V1GetWorkloadsResponse) HasResults() bool {
	if o != nil && o.Results != nil {
		return true
	}

	return false
}

// SetResults gets a reference to the given []V1Workload and assigns it to the Results field.
func (o *V1GetWorkloadsResponse) SetResults(v []V1Workload) {
	o.Results = &v
}

func (o V1GetWorkloadsResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.PageInfo != nil {
		toSerialize["pageInfo"] = o.PageInfo
	}
	if o.Results != nil {
		toSerialize["results"] = o.Results
	}
	return json.Marshal(toSerialize)
}

type NullableV1GetWorkloadsResponse struct {
	value *V1GetWorkloadsResponse
	isSet bool
}

func (v NullableV1GetWorkloadsResponse) Get() *V1GetWorkloadsResponse {
	return v.value
}

func (v *NullableV1GetWorkloadsResponse) Set(val *V1GetWorkloadsResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableV1GetWorkloadsResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableV1GetWorkloadsResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableV1GetWorkloadsResponse(val *V1GetWorkloadsResponse) *NullableV1GetWorkloadsResponse {
	return &NullableV1GetWorkloadsResponse{value: val, isSet: true}
}

func (v NullableV1GetWorkloadsResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableV1GetWorkloadsResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
