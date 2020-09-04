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

// CdnPop A point of presence responsible for serving content to a geographic location  POPs contain edge nodes responsible for CDN, WAF, monitoring, and all other StackPath product offerings.
type CdnPop struct {
	// A StackPath POP's IATA formatted location code
	Code *string `json:"code,omitempty"`
	// A StackPath POP's name
	Name *string `json:"name,omitempty"`
	// A StackPath POP's latitude coordinates
	Latitude *float32 `json:"latitude,omitempty"`
	// A StackPath POP's longitude coordinates
	Longitude *float32 `json:"longitude,omitempty"`
}

// NewCdnPop instantiates a new CdnPop object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCdnPop() *CdnPop {
	this := CdnPop{}
	return &this
}

// NewCdnPopWithDefaults instantiates a new CdnPop object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCdnPopWithDefaults() *CdnPop {
	this := CdnPop{}
	return &this
}

// GetCode returns the Code field value if set, zero value otherwise.
func (o *CdnPop) GetCode() string {
	if o == nil || o.Code == nil {
		var ret string
		return ret
	}
	return *o.Code
}

// GetCodeOk returns a tuple with the Code field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CdnPop) GetCodeOk() (*string, bool) {
	if o == nil || o.Code == nil {
		return nil, false
	}
	return o.Code, true
}

// HasCode returns a boolean if a field has been set.
func (o *CdnPop) HasCode() bool {
	if o != nil && o.Code != nil {
		return true
	}

	return false
}

// SetCode gets a reference to the given string and assigns it to the Code field.
func (o *CdnPop) SetCode(v string) {
	o.Code = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *CdnPop) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CdnPop) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *CdnPop) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *CdnPop) SetName(v string) {
	o.Name = &v
}

// GetLatitude returns the Latitude field value if set, zero value otherwise.
func (o *CdnPop) GetLatitude() float32 {
	if o == nil || o.Latitude == nil {
		var ret float32
		return ret
	}
	return *o.Latitude
}

// GetLatitudeOk returns a tuple with the Latitude field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CdnPop) GetLatitudeOk() (*float32, bool) {
	if o == nil || o.Latitude == nil {
		return nil, false
	}
	return o.Latitude, true
}

// HasLatitude returns a boolean if a field has been set.
func (o *CdnPop) HasLatitude() bool {
	if o != nil && o.Latitude != nil {
		return true
	}

	return false
}

// SetLatitude gets a reference to the given float32 and assigns it to the Latitude field.
func (o *CdnPop) SetLatitude(v float32) {
	o.Latitude = &v
}

// GetLongitude returns the Longitude field value if set, zero value otherwise.
func (o *CdnPop) GetLongitude() float32 {
	if o == nil || o.Longitude == nil {
		var ret float32
		return ret
	}
	return *o.Longitude
}

// GetLongitudeOk returns a tuple with the Longitude field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CdnPop) GetLongitudeOk() (*float32, bool) {
	if o == nil || o.Longitude == nil {
		return nil, false
	}
	return o.Longitude, true
}

// HasLongitude returns a boolean if a field has been set.
func (o *CdnPop) HasLongitude() bool {
	if o != nil && o.Longitude != nil {
		return true
	}

	return false
}

// SetLongitude gets a reference to the given float32 and assigns it to the Longitude field.
func (o *CdnPop) SetLongitude(v float32) {
	o.Longitude = &v
}

func (o CdnPop) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Code != nil {
		toSerialize["code"] = o.Code
	}
	if o.Name != nil {
		toSerialize["name"] = o.Name
	}
	if o.Latitude != nil {
		toSerialize["latitude"] = o.Latitude
	}
	if o.Longitude != nil {
		toSerialize["longitude"] = o.Longitude
	}
	return json.Marshal(toSerialize)
}

type NullableCdnPop struct {
	value *CdnPop
	isSet bool
}

func (v NullableCdnPop) Get() *CdnPop {
	return v.value
}

func (v *NullableCdnPop) Set(val *CdnPop) {
	v.value = val
	v.isSet = true
}

func (v NullableCdnPop) IsSet() bool {
	return v.isSet
}

func (v *NullableCdnPop) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCdnPop(val *CdnPop) *NullableCdnPop {
	return &NullableCdnPop{value: val, isSet: true}
}

func (v NullableCdnPop) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCdnPop) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
