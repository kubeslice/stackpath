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

// CustconfDynamicContent The dynamic content caching policy allows you to specify a set of query string and/or HTTP header key/value pairs that should create a unique cache entry for a given URL. This policy is useful when your origin returns unique content for the same URL based on a set of query string parameters provided in the request.
type CustconfDynamicContent struct {
	// This is used by the API to perform conflict checking
	Id *string `json:"id,omitempty"`
	// String of values delimited by a ',' character. A comma separated list of query string parameters you want to include in the cache key generation. NOTE: This list is ignored when the Key Location is set to header.
	QueryParams *string `json:"queryParams,omitempty"`
	// String of values delimited by a ',' character. A comma-separated list of glob patterns that represent HTTP request headers you want included in the cache key generation. Via the use of a colon ':', users can define each glob pattern to match a header name only, or the pattern can be used to match both the header name and value. A pattern without a colon ':' is treated as a header name ONLY match. If the pattern matches the header, then all values are used as a part of the cache key. If the pattern contains a colon, the CDN uses the pattern on the left of the colon to match the header. The pattern to the right of the colon is used to match the value. The CDN only uses the header/value as a part of the cache key if both patterns result in a match. Note, no pattern after a colon indicates an empty header (no value). See the fnmatch manpage for acceptable glob patterns.
	HeaderFields *string `json:"headerFields,omitempty"`
	Enabled *bool `json:"enabled,omitempty"`
	// String of values delimited by a ',' character.
	MethodFilter *string `json:"methodFilter,omitempty"`
	// String of values delimited by a ',' character.
	PathFilter *string `json:"pathFilter,omitempty"`
	// String of values delimited by a ',' character.
	HeaderFilter *string `json:"headerFilter,omitempty"`
}

// NewCustconfDynamicContent instantiates a new CustconfDynamicContent object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCustconfDynamicContent() *CustconfDynamicContent {
	this := CustconfDynamicContent{}
	return &this
}

// NewCustconfDynamicContentWithDefaults instantiates a new CustconfDynamicContent object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCustconfDynamicContentWithDefaults() *CustconfDynamicContent {
	this := CustconfDynamicContent{}
	return &this
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *CustconfDynamicContent) GetId() string {
	if o == nil || o.Id == nil {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfDynamicContent) GetIdOk() (*string, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *CustconfDynamicContent) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *CustconfDynamicContent) SetId(v string) {
	o.Id = &v
}

// GetQueryParams returns the QueryParams field value if set, zero value otherwise.
func (o *CustconfDynamicContent) GetQueryParams() string {
	if o == nil || o.QueryParams == nil {
		var ret string
		return ret
	}
	return *o.QueryParams
}

// GetQueryParamsOk returns a tuple with the QueryParams field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfDynamicContent) GetQueryParamsOk() (*string, bool) {
	if o == nil || o.QueryParams == nil {
		return nil, false
	}
	return o.QueryParams, true
}

// HasQueryParams returns a boolean if a field has been set.
func (o *CustconfDynamicContent) HasQueryParams() bool {
	if o != nil && o.QueryParams != nil {
		return true
	}

	return false
}

// SetQueryParams gets a reference to the given string and assigns it to the QueryParams field.
func (o *CustconfDynamicContent) SetQueryParams(v string) {
	o.QueryParams = &v
}

// GetHeaderFields returns the HeaderFields field value if set, zero value otherwise.
func (o *CustconfDynamicContent) GetHeaderFields() string {
	if o == nil || o.HeaderFields == nil {
		var ret string
		return ret
	}
	return *o.HeaderFields
}

// GetHeaderFieldsOk returns a tuple with the HeaderFields field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfDynamicContent) GetHeaderFieldsOk() (*string, bool) {
	if o == nil || o.HeaderFields == nil {
		return nil, false
	}
	return o.HeaderFields, true
}

// HasHeaderFields returns a boolean if a field has been set.
func (o *CustconfDynamicContent) HasHeaderFields() bool {
	if o != nil && o.HeaderFields != nil {
		return true
	}

	return false
}

// SetHeaderFields gets a reference to the given string and assigns it to the HeaderFields field.
func (o *CustconfDynamicContent) SetHeaderFields(v string) {
	o.HeaderFields = &v
}

// GetEnabled returns the Enabled field value if set, zero value otherwise.
func (o *CustconfDynamicContent) GetEnabled() bool {
	if o == nil || o.Enabled == nil {
		var ret bool
		return ret
	}
	return *o.Enabled
}

// GetEnabledOk returns a tuple with the Enabled field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfDynamicContent) GetEnabledOk() (*bool, bool) {
	if o == nil || o.Enabled == nil {
		return nil, false
	}
	return o.Enabled, true
}

// HasEnabled returns a boolean if a field has been set.
func (o *CustconfDynamicContent) HasEnabled() bool {
	if o != nil && o.Enabled != nil {
		return true
	}

	return false
}

// SetEnabled gets a reference to the given bool and assigns it to the Enabled field.
func (o *CustconfDynamicContent) SetEnabled(v bool) {
	o.Enabled = &v
}

// GetMethodFilter returns the MethodFilter field value if set, zero value otherwise.
func (o *CustconfDynamicContent) GetMethodFilter() string {
	if o == nil || o.MethodFilter == nil {
		var ret string
		return ret
	}
	return *o.MethodFilter
}

// GetMethodFilterOk returns a tuple with the MethodFilter field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfDynamicContent) GetMethodFilterOk() (*string, bool) {
	if o == nil || o.MethodFilter == nil {
		return nil, false
	}
	return o.MethodFilter, true
}

// HasMethodFilter returns a boolean if a field has been set.
func (o *CustconfDynamicContent) HasMethodFilter() bool {
	if o != nil && o.MethodFilter != nil {
		return true
	}

	return false
}

// SetMethodFilter gets a reference to the given string and assigns it to the MethodFilter field.
func (o *CustconfDynamicContent) SetMethodFilter(v string) {
	o.MethodFilter = &v
}

// GetPathFilter returns the PathFilter field value if set, zero value otherwise.
func (o *CustconfDynamicContent) GetPathFilter() string {
	if o == nil || o.PathFilter == nil {
		var ret string
		return ret
	}
	return *o.PathFilter
}

// GetPathFilterOk returns a tuple with the PathFilter field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfDynamicContent) GetPathFilterOk() (*string, bool) {
	if o == nil || o.PathFilter == nil {
		return nil, false
	}
	return o.PathFilter, true
}

// HasPathFilter returns a boolean if a field has been set.
func (o *CustconfDynamicContent) HasPathFilter() bool {
	if o != nil && o.PathFilter != nil {
		return true
	}

	return false
}

// SetPathFilter gets a reference to the given string and assigns it to the PathFilter field.
func (o *CustconfDynamicContent) SetPathFilter(v string) {
	o.PathFilter = &v
}

// GetHeaderFilter returns the HeaderFilter field value if set, zero value otherwise.
func (o *CustconfDynamicContent) GetHeaderFilter() string {
	if o == nil || o.HeaderFilter == nil {
		var ret string
		return ret
	}
	return *o.HeaderFilter
}

// GetHeaderFilterOk returns a tuple with the HeaderFilter field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfDynamicContent) GetHeaderFilterOk() (*string, bool) {
	if o == nil || o.HeaderFilter == nil {
		return nil, false
	}
	return o.HeaderFilter, true
}

// HasHeaderFilter returns a boolean if a field has been set.
func (o *CustconfDynamicContent) HasHeaderFilter() bool {
	if o != nil && o.HeaderFilter != nil {
		return true
	}

	return false
}

// SetHeaderFilter gets a reference to the given string and assigns it to the HeaderFilter field.
func (o *CustconfDynamicContent) SetHeaderFilter(v string) {
	o.HeaderFilter = &v
}

func (o CustconfDynamicContent) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Id != nil {
		toSerialize["id"] = o.Id
	}
	if o.QueryParams != nil {
		toSerialize["queryParams"] = o.QueryParams
	}
	if o.HeaderFields != nil {
		toSerialize["headerFields"] = o.HeaderFields
	}
	if o.Enabled != nil {
		toSerialize["enabled"] = o.Enabled
	}
	if o.MethodFilter != nil {
		toSerialize["methodFilter"] = o.MethodFilter
	}
	if o.PathFilter != nil {
		toSerialize["pathFilter"] = o.PathFilter
	}
	if o.HeaderFilter != nil {
		toSerialize["headerFilter"] = o.HeaderFilter
	}
	return json.Marshal(toSerialize)
}

type NullableCustconfDynamicContent struct {
	value *CustconfDynamicContent
	isSet bool
}

func (v NullableCustconfDynamicContent) Get() *CustconfDynamicContent {
	return v.value
}

func (v *NullableCustconfDynamicContent) Set(val *CustconfDynamicContent) {
	v.value = val
	v.isSet = true
}

func (v NullableCustconfDynamicContent) IsSet() bool {
	return v.isSet
}

func (v *NullableCustconfDynamicContent) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCustconfDynamicContent(val *CustconfDynamicContent) *NullableCustconfDynamicContent {
	return &NullableCustconfDynamicContent{value: val, isSet: true}
}

func (v NullableCustconfDynamicContent) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCustconfDynamicContent) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
