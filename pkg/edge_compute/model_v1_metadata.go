/*
 * Edge Compute
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute

import (
	"encoding/json"
	"time"
)

// V1Metadata Metadata associated with an entity
type V1Metadata struct {
	// A string to string key/value pair
	Annotations *map[string]string `json:"annotations,omitempty"`
	// A string to string key/value pair
	Labels *map[string]string `json:"labels,omitempty"`
	// The date that a metadata entry was created
	CreatedAt NullableTime `json:"createdAt,omitempty"`
	// The date that a metadata entry was last updated
	UpdatedAt NullableTime `json:"updatedAt,omitempty"`
	// The date an entity was requested to be deleted
	DeleteRequestedAt NullableTime `json:"deleteRequestedAt,omitempty"`
	// A metadata entry's version number  Metadata versions start at 1 when they are created and increment by 1 every time they are updated.
	Version *string `json:"version,omitempty"`
}

// NewV1Metadata instantiates a new V1Metadata object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewV1Metadata() *V1Metadata {
	this := V1Metadata{}
	return &this
}

// NewV1MetadataWithDefaults instantiates a new V1Metadata object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewV1MetadataWithDefaults() *V1Metadata {
	this := V1Metadata{}
	return &this
}

// GetAnnotations returns the Annotations field value if set, zero value otherwise.
func (o *V1Metadata) GetAnnotations() map[string]string {
	if o == nil || o.Annotations == nil {
		var ret map[string]string
		return ret
	}
	return *o.Annotations
}

// GetAnnotationsOk returns a tuple with the Annotations field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Metadata) GetAnnotationsOk() (*map[string]string, bool) {
	if o == nil || o.Annotations == nil {
		return nil, false
	}
	return o.Annotations, true
}

// HasAnnotations returns a boolean if a field has been set.
func (o *V1Metadata) HasAnnotations() bool {
	if o != nil && o.Annotations != nil {
		return true
	}

	return false
}

// SetAnnotations gets a reference to the given map[string]string and assigns it to the Annotations field.
func (o *V1Metadata) SetAnnotations(v map[string]string) {
	o.Annotations = &v
}

// GetLabels returns the Labels field value if set, zero value otherwise.
func (o *V1Metadata) GetLabels() map[string]string {
	if o == nil || o.Labels == nil {
		var ret map[string]string
		return ret
	}
	return *o.Labels
}

// GetLabelsOk returns a tuple with the Labels field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Metadata) GetLabelsOk() (*map[string]string, bool) {
	if o == nil || o.Labels == nil {
		return nil, false
	}
	return o.Labels, true
}

// HasLabels returns a boolean if a field has been set.
func (o *V1Metadata) HasLabels() bool {
	if o != nil && o.Labels != nil {
		return true
	}

	return false
}

// SetLabels gets a reference to the given map[string]string and assigns it to the Labels field.
func (o *V1Metadata) SetLabels(v map[string]string) {
	o.Labels = &v
}

// GetCreatedAt returns the CreatedAt field value if set, zero value otherwise (both if not set or set to explicit null).
func (o *V1Metadata) GetCreatedAt() time.Time {
	if o == nil || o.CreatedAt.Get() == nil {
		var ret time.Time
		return ret
	}
	return *o.CreatedAt.Get()
}

// GetCreatedAtOk returns a tuple with the CreatedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
// NOTE: If the value is an explicit nil, `nil, true` will be returned
func (o *V1Metadata) GetCreatedAtOk() (*time.Time, bool) {
	if o == nil  {
		return nil, false
	}
	return o.CreatedAt.Get(), o.CreatedAt.IsSet()
}

// HasCreatedAt returns a boolean if a field has been set.
func (o *V1Metadata) HasCreatedAt() bool {
	if o != nil && o.CreatedAt.IsSet() {
		return true
	}

	return false
}

// SetCreatedAt gets a reference to the given NullableTime and assigns it to the CreatedAt field.
func (o *V1Metadata) SetCreatedAt(v time.Time) {
	o.CreatedAt.Set(&v)
}
// SetCreatedAtNil sets the value for CreatedAt to be an explicit nil
func (o *V1Metadata) SetCreatedAtNil() {
	o.CreatedAt.Set(nil)
}

// UnsetCreatedAt ensures that no value is present for CreatedAt, not even an explicit nil
func (o *V1Metadata) UnsetCreatedAt() {
	o.CreatedAt.Unset()
}

// GetUpdatedAt returns the UpdatedAt field value if set, zero value otherwise (both if not set or set to explicit null).
func (o *V1Metadata) GetUpdatedAt() time.Time {
	if o == nil || o.UpdatedAt.Get() == nil {
		var ret time.Time
		return ret
	}
	return *o.UpdatedAt.Get()
}

// GetUpdatedAtOk returns a tuple with the UpdatedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
// NOTE: If the value is an explicit nil, `nil, true` will be returned
func (o *V1Metadata) GetUpdatedAtOk() (*time.Time, bool) {
	if o == nil  {
		return nil, false
	}
	return o.UpdatedAt.Get(), o.UpdatedAt.IsSet()
}

// HasUpdatedAt returns a boolean if a field has been set.
func (o *V1Metadata) HasUpdatedAt() bool {
	if o != nil && o.UpdatedAt.IsSet() {
		return true
	}

	return false
}

// SetUpdatedAt gets a reference to the given NullableTime and assigns it to the UpdatedAt field.
func (o *V1Metadata) SetUpdatedAt(v time.Time) {
	o.UpdatedAt.Set(&v)
}
// SetUpdatedAtNil sets the value for UpdatedAt to be an explicit nil
func (o *V1Metadata) SetUpdatedAtNil() {
	o.UpdatedAt.Set(nil)
}

// UnsetUpdatedAt ensures that no value is present for UpdatedAt, not even an explicit nil
func (o *V1Metadata) UnsetUpdatedAt() {
	o.UpdatedAt.Unset()
}

// GetDeleteRequestedAt returns the DeleteRequestedAt field value if set, zero value otherwise (both if not set or set to explicit null).
func (o *V1Metadata) GetDeleteRequestedAt() time.Time {
	if o == nil || o.DeleteRequestedAt.Get() == nil {
		var ret time.Time
		return ret
	}
	return *o.DeleteRequestedAt.Get()
}

// GetDeleteRequestedAtOk returns a tuple with the DeleteRequestedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
// NOTE: If the value is an explicit nil, `nil, true` will be returned
func (o *V1Metadata) GetDeleteRequestedAtOk() (*time.Time, bool) {
	if o == nil  {
		return nil, false
	}
	return o.DeleteRequestedAt.Get(), o.DeleteRequestedAt.IsSet()
}

// HasDeleteRequestedAt returns a boolean if a field has been set.
func (o *V1Metadata) HasDeleteRequestedAt() bool {
	if o != nil && o.DeleteRequestedAt.IsSet() {
		return true
	}

	return false
}

// SetDeleteRequestedAt gets a reference to the given NullableTime and assigns it to the DeleteRequestedAt field.
func (o *V1Metadata) SetDeleteRequestedAt(v time.Time) {
	o.DeleteRequestedAt.Set(&v)
}
// SetDeleteRequestedAtNil sets the value for DeleteRequestedAt to be an explicit nil
func (o *V1Metadata) SetDeleteRequestedAtNil() {
	o.DeleteRequestedAt.Set(nil)
}

// UnsetDeleteRequestedAt ensures that no value is present for DeleteRequestedAt, not even an explicit nil
func (o *V1Metadata) UnsetDeleteRequestedAt() {
	o.DeleteRequestedAt.Unset()
}

// GetVersion returns the Version field value if set, zero value otherwise.
func (o *V1Metadata) GetVersion() string {
	if o == nil || o.Version == nil {
		var ret string
		return ret
	}
	return *o.Version
}

// GetVersionOk returns a tuple with the Version field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Metadata) GetVersionOk() (*string, bool) {
	if o == nil || o.Version == nil {
		return nil, false
	}
	return o.Version, true
}

// HasVersion returns a boolean if a field has been set.
func (o *V1Metadata) HasVersion() bool {
	if o != nil && o.Version != nil {
		return true
	}

	return false
}

// SetVersion gets a reference to the given string and assigns it to the Version field.
func (o *V1Metadata) SetVersion(v string) {
	o.Version = &v
}

func (o V1Metadata) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Annotations != nil {
		toSerialize["annotations"] = o.Annotations
	}
	if o.Labels != nil {
		toSerialize["labels"] = o.Labels
	}
	if o.CreatedAt.IsSet() {
		toSerialize["createdAt"] = o.CreatedAt.Get()
	}
	if o.UpdatedAt.IsSet() {
		toSerialize["updatedAt"] = o.UpdatedAt.Get()
	}
	if o.DeleteRequestedAt.IsSet() {
		toSerialize["deleteRequestedAt"] = o.DeleteRequestedAt.Get()
	}
	if o.Version != nil {
		toSerialize["version"] = o.Version
	}
	return json.Marshal(toSerialize)
}

type NullableV1Metadata struct {
	value *V1Metadata
	isSet bool
}

func (v NullableV1Metadata) Get() *V1Metadata {
	return v.value
}

func (v *NullableV1Metadata) Set(val *V1Metadata) {
	v.value = val
	v.isSet = true
}

func (v NullableV1Metadata) IsSet() bool {
	return v.isSet
}

func (v *NullableV1Metadata) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableV1Metadata(val *V1Metadata) *NullableV1Metadata {
	return &NullableV1Metadata{value: val, isSet: true}
}

func (v NullableV1Metadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableV1Metadata) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
