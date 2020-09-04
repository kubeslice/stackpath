/*
 * DNS
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package dns

import (
	"encoding/json"
)

// ZoneCreateZoneRecordResponse A response from a request to create a new DNS zone resource record
type ZoneCreateZoneRecordResponse struct {
	Record *ZoneZoneRecord `json:"record,omitempty"`
}

// NewZoneCreateZoneRecordResponse instantiates a new ZoneCreateZoneRecordResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewZoneCreateZoneRecordResponse() *ZoneCreateZoneRecordResponse {
	this := ZoneCreateZoneRecordResponse{}
	return &this
}

// NewZoneCreateZoneRecordResponseWithDefaults instantiates a new ZoneCreateZoneRecordResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewZoneCreateZoneRecordResponseWithDefaults() *ZoneCreateZoneRecordResponse {
	this := ZoneCreateZoneRecordResponse{}
	return &this
}

// GetRecord returns the Record field value if set, zero value otherwise.
func (o *ZoneCreateZoneRecordResponse) GetRecord() ZoneZoneRecord {
	if o == nil || o.Record == nil {
		var ret ZoneZoneRecord
		return ret
	}
	return *o.Record
}

// GetRecordOk returns a tuple with the Record field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ZoneCreateZoneRecordResponse) GetRecordOk() (*ZoneZoneRecord, bool) {
	if o == nil || o.Record == nil {
		return nil, false
	}
	return o.Record, true
}

// HasRecord returns a boolean if a field has been set.
func (o *ZoneCreateZoneRecordResponse) HasRecord() bool {
	if o != nil && o.Record != nil {
		return true
	}

	return false
}

// SetRecord gets a reference to the given ZoneZoneRecord and assigns it to the Record field.
func (o *ZoneCreateZoneRecordResponse) SetRecord(v ZoneZoneRecord) {
	o.Record = &v
}

func (o ZoneCreateZoneRecordResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Record != nil {
		toSerialize["record"] = o.Record
	}
	return json.Marshal(toSerialize)
}

type NullableZoneCreateZoneRecordResponse struct {
	value *ZoneCreateZoneRecordResponse
	isSet bool
}

func (v NullableZoneCreateZoneRecordResponse) Get() *ZoneCreateZoneRecordResponse {
	return v.value
}

func (v *NullableZoneCreateZoneRecordResponse) Set(val *ZoneCreateZoneRecordResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableZoneCreateZoneRecordResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableZoneCreateZoneRecordResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableZoneCreateZoneRecordResponse(val *ZoneCreateZoneRecordResponse) *NullableZoneCreateZoneRecordResponse {
	return &NullableZoneCreateZoneRecordResponse{value: val, isSet: true}
}

func (v NullableZoneCreateZoneRecordResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableZoneCreateZoneRecordResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
