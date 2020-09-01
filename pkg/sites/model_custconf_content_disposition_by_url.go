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

// CustconfContentDispositionByURL The content disposition by URL policy allows you to control Content-Disposition HTTP header delivered by the CDN caching servers. The policy gives you control over each of the header directives and allows you to specify a URL pattern match for determining when to apply the policy. Please note this policy takes precedence over all the other content disposition policies.
type CustconfContentDispositionByURL struct {
	// This is used by the API to perform conflict checking
	Id *string `json:"id,omitempty"`
	// This is the name of the query string parameter which contains the file name to use in the Content-Disposition header. This setting is typically used by customers to configure a \"friendly name\" for URLs that have obfuscated file names.
	DispositionNameQSParam *string `json:"dispositionNameQSParam,omitempty"`
	// This is the name of the query string parameter which contains the disposition type to use in the Content-Disposition header. Typically, this value is set to attachment if you want the browser to present the user with a \"File Download\" dialog box and set to inline if you want the browser to render the content inline (play an audio/video file instead of downloading it).
	DispositionTypeQSParam *string `json:"dispositionTypeQSParam,omitempty"`
	// This setting allows you to define a query string parameter that when present in the URL contains a string that should be used for the Content-Disposition header. The string specified in the URL will completely replace the value the CDN would have used based on other policies defined for the Content-Disposition header.
	DispositionOverrideQSParam *string `json:"dispositionOverrideQSParam,omitempty"`
	// This setting allows you to force the Content-Disposition generated by the CDN for this policy to override the Content-Disposition header cached from your origin.
	OverrideOriginHeader *bool `json:"overrideOriginHeader,omitempty"`
	Enabled *bool `json:"enabled,omitempty"`
}

// NewCustconfContentDispositionByURL instantiates a new CustconfContentDispositionByURL object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCustconfContentDispositionByURL() *CustconfContentDispositionByURL {
	this := CustconfContentDispositionByURL{}
	return &this
}

// NewCustconfContentDispositionByURLWithDefaults instantiates a new CustconfContentDispositionByURL object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCustconfContentDispositionByURLWithDefaults() *CustconfContentDispositionByURL {
	this := CustconfContentDispositionByURL{}
	return &this
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *CustconfContentDispositionByURL) GetId() string {
	if o == nil || o.Id == nil {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfContentDispositionByURL) GetIdOk() (*string, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *CustconfContentDispositionByURL) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *CustconfContentDispositionByURL) SetId(v string) {
	o.Id = &v
}

// GetDispositionNameQSParam returns the DispositionNameQSParam field value if set, zero value otherwise.
func (o *CustconfContentDispositionByURL) GetDispositionNameQSParam() string {
	if o == nil || o.DispositionNameQSParam == nil {
		var ret string
		return ret
	}
	return *o.DispositionNameQSParam
}

// GetDispositionNameQSParamOk returns a tuple with the DispositionNameQSParam field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfContentDispositionByURL) GetDispositionNameQSParamOk() (*string, bool) {
	if o == nil || o.DispositionNameQSParam == nil {
		return nil, false
	}
	return o.DispositionNameQSParam, true
}

// HasDispositionNameQSParam returns a boolean if a field has been set.
func (o *CustconfContentDispositionByURL) HasDispositionNameQSParam() bool {
	if o != nil && o.DispositionNameQSParam != nil {
		return true
	}

	return false
}

// SetDispositionNameQSParam gets a reference to the given string and assigns it to the DispositionNameQSParam field.
func (o *CustconfContentDispositionByURL) SetDispositionNameQSParam(v string) {
	o.DispositionNameQSParam = &v
}

// GetDispositionTypeQSParam returns the DispositionTypeQSParam field value if set, zero value otherwise.
func (o *CustconfContentDispositionByURL) GetDispositionTypeQSParam() string {
	if o == nil || o.DispositionTypeQSParam == nil {
		var ret string
		return ret
	}
	return *o.DispositionTypeQSParam
}

// GetDispositionTypeQSParamOk returns a tuple with the DispositionTypeQSParam field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfContentDispositionByURL) GetDispositionTypeQSParamOk() (*string, bool) {
	if o == nil || o.DispositionTypeQSParam == nil {
		return nil, false
	}
	return o.DispositionTypeQSParam, true
}

// HasDispositionTypeQSParam returns a boolean if a field has been set.
func (o *CustconfContentDispositionByURL) HasDispositionTypeQSParam() bool {
	if o != nil && o.DispositionTypeQSParam != nil {
		return true
	}

	return false
}

// SetDispositionTypeQSParam gets a reference to the given string and assigns it to the DispositionTypeQSParam field.
func (o *CustconfContentDispositionByURL) SetDispositionTypeQSParam(v string) {
	o.DispositionTypeQSParam = &v
}

// GetDispositionOverrideQSParam returns the DispositionOverrideQSParam field value if set, zero value otherwise.
func (o *CustconfContentDispositionByURL) GetDispositionOverrideQSParam() string {
	if o == nil || o.DispositionOverrideQSParam == nil {
		var ret string
		return ret
	}
	return *o.DispositionOverrideQSParam
}

// GetDispositionOverrideQSParamOk returns a tuple with the DispositionOverrideQSParam field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfContentDispositionByURL) GetDispositionOverrideQSParamOk() (*string, bool) {
	if o == nil || o.DispositionOverrideQSParam == nil {
		return nil, false
	}
	return o.DispositionOverrideQSParam, true
}

// HasDispositionOverrideQSParam returns a boolean if a field has been set.
func (o *CustconfContentDispositionByURL) HasDispositionOverrideQSParam() bool {
	if o != nil && o.DispositionOverrideQSParam != nil {
		return true
	}

	return false
}

// SetDispositionOverrideQSParam gets a reference to the given string and assigns it to the DispositionOverrideQSParam field.
func (o *CustconfContentDispositionByURL) SetDispositionOverrideQSParam(v string) {
	o.DispositionOverrideQSParam = &v
}

// GetOverrideOriginHeader returns the OverrideOriginHeader field value if set, zero value otherwise.
func (o *CustconfContentDispositionByURL) GetOverrideOriginHeader() bool {
	if o == nil || o.OverrideOriginHeader == nil {
		var ret bool
		return ret
	}
	return *o.OverrideOriginHeader
}

// GetOverrideOriginHeaderOk returns a tuple with the OverrideOriginHeader field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfContentDispositionByURL) GetOverrideOriginHeaderOk() (*bool, bool) {
	if o == nil || o.OverrideOriginHeader == nil {
		return nil, false
	}
	return o.OverrideOriginHeader, true
}

// HasOverrideOriginHeader returns a boolean if a field has been set.
func (o *CustconfContentDispositionByURL) HasOverrideOriginHeader() bool {
	if o != nil && o.OverrideOriginHeader != nil {
		return true
	}

	return false
}

// SetOverrideOriginHeader gets a reference to the given bool and assigns it to the OverrideOriginHeader field.
func (o *CustconfContentDispositionByURL) SetOverrideOriginHeader(v bool) {
	o.OverrideOriginHeader = &v
}

// GetEnabled returns the Enabled field value if set, zero value otherwise.
func (o *CustconfContentDispositionByURL) GetEnabled() bool {
	if o == nil || o.Enabled == nil {
		var ret bool
		return ret
	}
	return *o.Enabled
}

// GetEnabledOk returns a tuple with the Enabled field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfContentDispositionByURL) GetEnabledOk() (*bool, bool) {
	if o == nil || o.Enabled == nil {
		return nil, false
	}
	return o.Enabled, true
}

// HasEnabled returns a boolean if a field has been set.
func (o *CustconfContentDispositionByURL) HasEnabled() bool {
	if o != nil && o.Enabled != nil {
		return true
	}

	return false
}

// SetEnabled gets a reference to the given bool and assigns it to the Enabled field.
func (o *CustconfContentDispositionByURL) SetEnabled(v bool) {
	o.Enabled = &v
}

func (o CustconfContentDispositionByURL) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Id != nil {
		toSerialize["id"] = o.Id
	}
	if o.DispositionNameQSParam != nil {
		toSerialize["dispositionNameQSParam"] = o.DispositionNameQSParam
	}
	if o.DispositionTypeQSParam != nil {
		toSerialize["dispositionTypeQSParam"] = o.DispositionTypeQSParam
	}
	if o.DispositionOverrideQSParam != nil {
		toSerialize["dispositionOverrideQSParam"] = o.DispositionOverrideQSParam
	}
	if o.OverrideOriginHeader != nil {
		toSerialize["overrideOriginHeader"] = o.OverrideOriginHeader
	}
	if o.Enabled != nil {
		toSerialize["enabled"] = o.Enabled
	}
	return json.Marshal(toSerialize)
}

type NullableCustconfContentDispositionByURL struct {
	value *CustconfContentDispositionByURL
	isSet bool
}

func (v NullableCustconfContentDispositionByURL) Get() *CustconfContentDispositionByURL {
	return v.value
}

func (v *NullableCustconfContentDispositionByURL) Set(val *CustconfContentDispositionByURL) {
	v.value = val
	v.isSet = true
}

func (v NullableCustconfContentDispositionByURL) IsSet() bool {
	return v.isSet
}

func (v *NullableCustconfContentDispositionByURL) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCustconfContentDispositionByURL(val *CustconfContentDispositionByURL) *NullableCustconfContentDispositionByURL {
	return &NullableCustconfContentDispositionByURL{value: val, isSet: true}
}

func (v NullableCustconfContentDispositionByURL) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCustconfContentDispositionByURL) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
