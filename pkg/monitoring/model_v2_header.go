/*
 * Monitoring
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package monitoring

import (
	"encoding/json"
)

// V2Header An HTTP header
type V2Header struct {
	// An HTTP header's field name
	Header *string `json:"header,omitempty"`
	// An HTTP header's value
	Value *string `json:"value,omitempty"`
}

// NewV2Header instantiates a new V2Header object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewV2Header() *V2Header {
	this := V2Header{}
	return &this
}

// NewV2HeaderWithDefaults instantiates a new V2Header object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewV2HeaderWithDefaults() *V2Header {
	this := V2Header{}
	return &this
}

// GetHeader returns the Header field value if set, zero value otherwise.
func (o *V2Header) GetHeader() string {
	if o == nil || o.Header == nil {
		var ret string
		return ret
	}
	return *o.Header
}

// GetHeaderOk returns a tuple with the Header field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V2Header) GetHeaderOk() (*string, bool) {
	if o == nil || o.Header == nil {
		return nil, false
	}
	return o.Header, true
}

// HasHeader returns a boolean if a field has been set.
func (o *V2Header) HasHeader() bool {
	if o != nil && o.Header != nil {
		return true
	}

	return false
}

// SetHeader gets a reference to the given string and assigns it to the Header field.
func (o *V2Header) SetHeader(v string) {
	o.Header = &v
}

// GetValue returns the Value field value if set, zero value otherwise.
func (o *V2Header) GetValue() string {
	if o == nil || o.Value == nil {
		var ret string
		return ret
	}
	return *o.Value
}

// GetValueOk returns a tuple with the Value field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V2Header) GetValueOk() (*string, bool) {
	if o == nil || o.Value == nil {
		return nil, false
	}
	return o.Value, true
}

// HasValue returns a boolean if a field has been set.
func (o *V2Header) HasValue() bool {
	if o != nil && o.Value != nil {
		return true
	}

	return false
}

// SetValue gets a reference to the given string and assigns it to the Value field.
func (o *V2Header) SetValue(v string) {
	o.Value = &v
}

func (o V2Header) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Header != nil {
		toSerialize["header"] = o.Header
	}
	if o.Value != nil {
		toSerialize["value"] = o.Value
	}
	return json.Marshal(toSerialize)
}

type NullableV2Header struct {
	value *V2Header
	isSet bool
}

func (v NullableV2Header) Get() *V2Header {
	return v.value
}

func (v *NullableV2Header) Set(val *V2Header) {
	v.value = val
	v.isSet = true
}

func (v NullableV2Header) IsSet() bool {
	return v.isSet
}

func (v *NullableV2Header) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableV2Header(val *V2Header) *NullableV2Header {
	return &NullableV2Header{value: val, isSet: true}
}

func (v NullableV2Header) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableV2Header) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
