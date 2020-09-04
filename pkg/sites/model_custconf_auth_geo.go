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

// CustconfAuthGeo Geographic restrictions allow you to restrict content to end users in specific locations. The IP address of incoming requests is checked against a current list of IP allocations to countries and to states within the US. If an end user's IP address is not found in the list, they are allowed access to the content by default. The feature has both an Include and an Exclude list which are used to target the allowed audience.
type CustconfAuthGeo struct {
	// This is used by the API to perform conflict checking
	Id *string `json:"id,omitempty"`
	Code *AuthGeoCodeEnumWrapperValue `json:"code,omitempty"`
	// String of values delimited by a ',' character. These are the region codes you are targeting for this policy. The values that can be supplied within this field are those that are supported by the MaxMind® GeoIP database.
	Values *string `json:"values,omitempty"`
	Enabled *bool `json:"enabled,omitempty"`
}

// NewCustconfAuthGeo instantiates a new CustconfAuthGeo object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCustconfAuthGeo() *CustconfAuthGeo {
	this := CustconfAuthGeo{}
	var code AuthGeoCodeEnumWrapperValue = "UNKNOWN"
	this.Code = &code
	return &this
}

// NewCustconfAuthGeoWithDefaults instantiates a new CustconfAuthGeo object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCustconfAuthGeoWithDefaults() *CustconfAuthGeo {
	this := CustconfAuthGeo{}
	var code AuthGeoCodeEnumWrapperValue = "UNKNOWN"
	this.Code = &code
	return &this
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *CustconfAuthGeo) GetId() string {
	if o == nil || o.Id == nil {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthGeo) GetIdOk() (*string, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *CustconfAuthGeo) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *CustconfAuthGeo) SetId(v string) {
	o.Id = &v
}

// GetCode returns the Code field value if set, zero value otherwise.
func (o *CustconfAuthGeo) GetCode() AuthGeoCodeEnumWrapperValue {
	if o == nil || o.Code == nil {
		var ret AuthGeoCodeEnumWrapperValue
		return ret
	}
	return *o.Code
}

// GetCodeOk returns a tuple with the Code field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthGeo) GetCodeOk() (*AuthGeoCodeEnumWrapperValue, bool) {
	if o == nil || o.Code == nil {
		return nil, false
	}
	return o.Code, true
}

// HasCode returns a boolean if a field has been set.
func (o *CustconfAuthGeo) HasCode() bool {
	if o != nil && o.Code != nil {
		return true
	}

	return false
}

// SetCode gets a reference to the given AuthGeoCodeEnumWrapperValue and assigns it to the Code field.
func (o *CustconfAuthGeo) SetCode(v AuthGeoCodeEnumWrapperValue) {
	o.Code = &v
}

// GetValues returns the Values field value if set, zero value otherwise.
func (o *CustconfAuthGeo) GetValues() string {
	if o == nil || o.Values == nil {
		var ret string
		return ret
	}
	return *o.Values
}

// GetValuesOk returns a tuple with the Values field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthGeo) GetValuesOk() (*string, bool) {
	if o == nil || o.Values == nil {
		return nil, false
	}
	return o.Values, true
}

// HasValues returns a boolean if a field has been set.
func (o *CustconfAuthGeo) HasValues() bool {
	if o != nil && o.Values != nil {
		return true
	}

	return false
}

// SetValues gets a reference to the given string and assigns it to the Values field.
func (o *CustconfAuthGeo) SetValues(v string) {
	o.Values = &v
}

// GetEnabled returns the Enabled field value if set, zero value otherwise.
func (o *CustconfAuthGeo) GetEnabled() bool {
	if o == nil || o.Enabled == nil {
		var ret bool
		return ret
	}
	return *o.Enabled
}

// GetEnabledOk returns a tuple with the Enabled field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthGeo) GetEnabledOk() (*bool, bool) {
	if o == nil || o.Enabled == nil {
		return nil, false
	}
	return o.Enabled, true
}

// HasEnabled returns a boolean if a field has been set.
func (o *CustconfAuthGeo) HasEnabled() bool {
	if o != nil && o.Enabled != nil {
		return true
	}

	return false
}

// SetEnabled gets a reference to the given bool and assigns it to the Enabled field.
func (o *CustconfAuthGeo) SetEnabled(v bool) {
	o.Enabled = &v
}

func (o CustconfAuthGeo) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Id != nil {
		toSerialize["id"] = o.Id
	}
	if o.Code != nil {
		toSerialize["code"] = o.Code
	}
	if o.Values != nil {
		toSerialize["values"] = o.Values
	}
	if o.Enabled != nil {
		toSerialize["enabled"] = o.Enabled
	}
	return json.Marshal(toSerialize)
}

type NullableCustconfAuthGeo struct {
	value *CustconfAuthGeo
	isSet bool
}

func (v NullableCustconfAuthGeo) Get() *CustconfAuthGeo {
	return v.value
}

func (v *NullableCustconfAuthGeo) Set(val *CustconfAuthGeo) {
	v.value = val
	v.isSet = true
}

func (v NullableCustconfAuthGeo) IsSet() bool {
	return v.isSet
}

func (v *NullableCustconfAuthGeo) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCustconfAuthGeo(val *CustconfAuthGeo) *NullableCustconfAuthGeo {
	return &NullableCustconfAuthGeo{value: val, isSet: true}
}

func (v NullableCustconfAuthGeo) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCustconfAuthGeo) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
