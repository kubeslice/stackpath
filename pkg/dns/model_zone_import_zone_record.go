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

// ZoneImportZoneRecord A DNS zone resource record, as imported from a 3rd party provider
type ZoneImportZoneRecord struct {
	// A zone record's name
	Name *string `json:"name,omitempty"`
	Type *ZoneRecordType `json:"type,omitempty"`
	// A zone record's time to live  A record's TTL is the number of seconds that the record should be cached by DNS resolvers. Use lower TTL values if you expect zone records to change often. Use higher TTL values for records that won't change to prevent extra DNS lookups by clients.
	Ttl *int32 `json:"ttl,omitempty"`
	// A zone record's value  Expected data formats can vary depending on the zone record's type.
	Data *string `json:"data,omitempty"`
	// A zone record's priority  A resource record is replicated in StackPath's DNS infrastructure the number of times of the record's weight, giving it a more likely response to queries if a zone has records with the same name and type.
	Weight *int32 `json:"weight,omitempty"`
}

// NewZoneImportZoneRecord instantiates a new ZoneImportZoneRecord object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewZoneImportZoneRecord() *ZoneImportZoneRecord {
	this := ZoneImportZoneRecord{}
	var type_ ZoneRecordType = "EMPTY"
	this.Type = &type_
	return &this
}

// NewZoneImportZoneRecordWithDefaults instantiates a new ZoneImportZoneRecord object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewZoneImportZoneRecordWithDefaults() *ZoneImportZoneRecord {
	this := ZoneImportZoneRecord{}
	var type_ ZoneRecordType = "EMPTY"
	this.Type = &type_
	return &this
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *ZoneImportZoneRecord) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ZoneImportZoneRecord) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *ZoneImportZoneRecord) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *ZoneImportZoneRecord) SetName(v string) {
	o.Name = &v
}

// GetType returns the Type field value if set, zero value otherwise.
func (o *ZoneImportZoneRecord) GetType() ZoneRecordType {
	if o == nil || o.Type == nil {
		var ret ZoneRecordType
		return ret
	}
	return *o.Type
}

// GetTypeOk returns a tuple with the Type field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ZoneImportZoneRecord) GetTypeOk() (*ZoneRecordType, bool) {
	if o == nil || o.Type == nil {
		return nil, false
	}
	return o.Type, true
}

// HasType returns a boolean if a field has been set.
func (o *ZoneImportZoneRecord) HasType() bool {
	if o != nil && o.Type != nil {
		return true
	}

	return false
}

// SetType gets a reference to the given ZoneRecordType and assigns it to the Type field.
func (o *ZoneImportZoneRecord) SetType(v ZoneRecordType) {
	o.Type = &v
}

// GetTtl returns the Ttl field value if set, zero value otherwise.
func (o *ZoneImportZoneRecord) GetTtl() int32 {
	if o == nil || o.Ttl == nil {
		var ret int32
		return ret
	}
	return *o.Ttl
}

// GetTtlOk returns a tuple with the Ttl field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ZoneImportZoneRecord) GetTtlOk() (*int32, bool) {
	if o == nil || o.Ttl == nil {
		return nil, false
	}
	return o.Ttl, true
}

// HasTtl returns a boolean if a field has been set.
func (o *ZoneImportZoneRecord) HasTtl() bool {
	if o != nil && o.Ttl != nil {
		return true
	}

	return false
}

// SetTtl gets a reference to the given int32 and assigns it to the Ttl field.
func (o *ZoneImportZoneRecord) SetTtl(v int32) {
	o.Ttl = &v
}

// GetData returns the Data field value if set, zero value otherwise.
func (o *ZoneImportZoneRecord) GetData() string {
	if o == nil || o.Data == nil {
		var ret string
		return ret
	}
	return *o.Data
}

// GetDataOk returns a tuple with the Data field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ZoneImportZoneRecord) GetDataOk() (*string, bool) {
	if o == nil || o.Data == nil {
		return nil, false
	}
	return o.Data, true
}

// HasData returns a boolean if a field has been set.
func (o *ZoneImportZoneRecord) HasData() bool {
	if o != nil && o.Data != nil {
		return true
	}

	return false
}

// SetData gets a reference to the given string and assigns it to the Data field.
func (o *ZoneImportZoneRecord) SetData(v string) {
	o.Data = &v
}

// GetWeight returns the Weight field value if set, zero value otherwise.
func (o *ZoneImportZoneRecord) GetWeight() int32 {
	if o == nil || o.Weight == nil {
		var ret int32
		return ret
	}
	return *o.Weight
}

// GetWeightOk returns a tuple with the Weight field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ZoneImportZoneRecord) GetWeightOk() (*int32, bool) {
	if o == nil || o.Weight == nil {
		return nil, false
	}
	return o.Weight, true
}

// HasWeight returns a boolean if a field has been set.
func (o *ZoneImportZoneRecord) HasWeight() bool {
	if o != nil && o.Weight != nil {
		return true
	}

	return false
}

// SetWeight gets a reference to the given int32 and assigns it to the Weight field.
func (o *ZoneImportZoneRecord) SetWeight(v int32) {
	o.Weight = &v
}

func (o ZoneImportZoneRecord) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Name != nil {
		toSerialize["name"] = o.Name
	}
	if o.Type != nil {
		toSerialize["type"] = o.Type
	}
	if o.Ttl != nil {
		toSerialize["ttl"] = o.Ttl
	}
	if o.Data != nil {
		toSerialize["data"] = o.Data
	}
	if o.Weight != nil {
		toSerialize["weight"] = o.Weight
	}
	return json.Marshal(toSerialize)
}

type NullableZoneImportZoneRecord struct {
	value *ZoneImportZoneRecord
	isSet bool
}

func (v NullableZoneImportZoneRecord) Get() *ZoneImportZoneRecord {
	return v.value
}

func (v *NullableZoneImportZoneRecord) Set(val *ZoneImportZoneRecord) {
	v.value = val
	v.isSet = true
}

func (v NullableZoneImportZoneRecord) IsSet() bool {
	return v.isSet
}

func (v *NullableZoneImportZoneRecord) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableZoneImportZoneRecord(val *ZoneImportZoneRecord) *NullableZoneImportZoneRecord {
	return &NullableZoneImportZoneRecord{value: val, isSet: true}
}

func (v NullableZoneImportZoneRecord) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableZoneImportZoneRecord) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
