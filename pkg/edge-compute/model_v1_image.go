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

// V1Image A virtual machine image
type V1Image struct {
	// The ID of the stack that an image belongs to
	StackId *string `json:"stackId,omitempty"`
	// An image's unique identifier
	Id *string `json:"id,omitempty"`
	// An image's family  Families are logical groupings of images
	Family *string `json:"family,omitempty"`
	// The image's tag  Image tags are akin to versions
	Tag *string `json:"tag,omitempty"`
	Metadata *V1ImageMetadata `json:"metadata,omitempty"`
	// An image's description  This is optional and may not be more than 1,000 characters
	Description *string `json:"description,omitempty"`
	Status *V1ImageStatus `json:"status,omitempty"`
	// An image's archive size in bytes  This is only available on ready images
	ImageSize *string `json:"imageSize,omitempty"`
	// An image's volume size in bytes  This is only available on ready images
	VolumeSize *string `json:"volumeSize,omitempty"`
	Deprecation *V1ImageDeprecation `json:"deprecation,omitempty"`
	// Details about an image's status
	Conditions *[]V1ImageCondition `json:"conditions,omitempty"`
}

// NewV1Image instantiates a new V1Image object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewV1Image() *V1Image {
	this := V1Image{}
	var status V1ImageStatus = "IMAGE_STATUS_UNKNOWN"
	this.Status = &status
	return &this
}

// NewV1ImageWithDefaults instantiates a new V1Image object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewV1ImageWithDefaults() *V1Image {
	this := V1Image{}
	var status V1ImageStatus = "IMAGE_STATUS_UNKNOWN"
	this.Status = &status
	return &this
}

// GetStackId returns the StackId field value if set, zero value otherwise.
func (o *V1Image) GetStackId() string {
	if o == nil || o.StackId == nil {
		var ret string
		return ret
	}
	return *o.StackId
}

// GetStackIdOk returns a tuple with the StackId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Image) GetStackIdOk() (*string, bool) {
	if o == nil || o.StackId == nil {
		return nil, false
	}
	return o.StackId, true
}

// HasStackId returns a boolean if a field has been set.
func (o *V1Image) HasStackId() bool {
	if o != nil && o.StackId != nil {
		return true
	}

	return false
}

// SetStackId gets a reference to the given string and assigns it to the StackId field.
func (o *V1Image) SetStackId(v string) {
	o.StackId = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *V1Image) GetId() string {
	if o == nil || o.Id == nil {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Image) GetIdOk() (*string, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *V1Image) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *V1Image) SetId(v string) {
	o.Id = &v
}

// GetFamily returns the Family field value if set, zero value otherwise.
func (o *V1Image) GetFamily() string {
	if o == nil || o.Family == nil {
		var ret string
		return ret
	}
	return *o.Family
}

// GetFamilyOk returns a tuple with the Family field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Image) GetFamilyOk() (*string, bool) {
	if o == nil || o.Family == nil {
		return nil, false
	}
	return o.Family, true
}

// HasFamily returns a boolean if a field has been set.
func (o *V1Image) HasFamily() bool {
	if o != nil && o.Family != nil {
		return true
	}

	return false
}

// SetFamily gets a reference to the given string and assigns it to the Family field.
func (o *V1Image) SetFamily(v string) {
	o.Family = &v
}

// GetTag returns the Tag field value if set, zero value otherwise.
func (o *V1Image) GetTag() string {
	if o == nil || o.Tag == nil {
		var ret string
		return ret
	}
	return *o.Tag
}

// GetTagOk returns a tuple with the Tag field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Image) GetTagOk() (*string, bool) {
	if o == nil || o.Tag == nil {
		return nil, false
	}
	return o.Tag, true
}

// HasTag returns a boolean if a field has been set.
func (o *V1Image) HasTag() bool {
	if o != nil && o.Tag != nil {
		return true
	}

	return false
}

// SetTag gets a reference to the given string and assigns it to the Tag field.
func (o *V1Image) SetTag(v string) {
	o.Tag = &v
}

// GetMetadata returns the Metadata field value if set, zero value otherwise.
func (o *V1Image) GetMetadata() V1ImageMetadata {
	if o == nil || o.Metadata == nil {
		var ret V1ImageMetadata
		return ret
	}
	return *o.Metadata
}

// GetMetadataOk returns a tuple with the Metadata field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Image) GetMetadataOk() (*V1ImageMetadata, bool) {
	if o == nil || o.Metadata == nil {
		return nil, false
	}
	return o.Metadata, true
}

// HasMetadata returns a boolean if a field has been set.
func (o *V1Image) HasMetadata() bool {
	if o != nil && o.Metadata != nil {
		return true
	}

	return false
}

// SetMetadata gets a reference to the given V1ImageMetadata and assigns it to the Metadata field.
func (o *V1Image) SetMetadata(v V1ImageMetadata) {
	o.Metadata = &v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *V1Image) GetDescription() string {
	if o == nil || o.Description == nil {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Image) GetDescriptionOk() (*string, bool) {
	if o == nil || o.Description == nil {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *V1Image) HasDescription() bool {
	if o != nil && o.Description != nil {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *V1Image) SetDescription(v string) {
	o.Description = &v
}

// GetStatus returns the Status field value if set, zero value otherwise.
func (o *V1Image) GetStatus() V1ImageStatus {
	if o == nil || o.Status == nil {
		var ret V1ImageStatus
		return ret
	}
	return *o.Status
}

// GetStatusOk returns a tuple with the Status field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Image) GetStatusOk() (*V1ImageStatus, bool) {
	if o == nil || o.Status == nil {
		return nil, false
	}
	return o.Status, true
}

// HasStatus returns a boolean if a field has been set.
func (o *V1Image) HasStatus() bool {
	if o != nil && o.Status != nil {
		return true
	}

	return false
}

// SetStatus gets a reference to the given V1ImageStatus and assigns it to the Status field.
func (o *V1Image) SetStatus(v V1ImageStatus) {
	o.Status = &v
}

// GetImageSize returns the ImageSize field value if set, zero value otherwise.
func (o *V1Image) GetImageSize() string {
	if o == nil || o.ImageSize == nil {
		var ret string
		return ret
	}
	return *o.ImageSize
}

// GetImageSizeOk returns a tuple with the ImageSize field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Image) GetImageSizeOk() (*string, bool) {
	if o == nil || o.ImageSize == nil {
		return nil, false
	}
	return o.ImageSize, true
}

// HasImageSize returns a boolean if a field has been set.
func (o *V1Image) HasImageSize() bool {
	if o != nil && o.ImageSize != nil {
		return true
	}

	return false
}

// SetImageSize gets a reference to the given string and assigns it to the ImageSize field.
func (o *V1Image) SetImageSize(v string) {
	o.ImageSize = &v
}

// GetVolumeSize returns the VolumeSize field value if set, zero value otherwise.
func (o *V1Image) GetVolumeSize() string {
	if o == nil || o.VolumeSize == nil {
		var ret string
		return ret
	}
	return *o.VolumeSize
}

// GetVolumeSizeOk returns a tuple with the VolumeSize field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Image) GetVolumeSizeOk() (*string, bool) {
	if o == nil || o.VolumeSize == nil {
		return nil, false
	}
	return o.VolumeSize, true
}

// HasVolumeSize returns a boolean if a field has been set.
func (o *V1Image) HasVolumeSize() bool {
	if o != nil && o.VolumeSize != nil {
		return true
	}

	return false
}

// SetVolumeSize gets a reference to the given string and assigns it to the VolumeSize field.
func (o *V1Image) SetVolumeSize(v string) {
	o.VolumeSize = &v
}

// GetDeprecation returns the Deprecation field value if set, zero value otherwise.
func (o *V1Image) GetDeprecation() V1ImageDeprecation {
	if o == nil || o.Deprecation == nil {
		var ret V1ImageDeprecation
		return ret
	}
	return *o.Deprecation
}

// GetDeprecationOk returns a tuple with the Deprecation field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Image) GetDeprecationOk() (*V1ImageDeprecation, bool) {
	if o == nil || o.Deprecation == nil {
		return nil, false
	}
	return o.Deprecation, true
}

// HasDeprecation returns a boolean if a field has been set.
func (o *V1Image) HasDeprecation() bool {
	if o != nil && o.Deprecation != nil {
		return true
	}

	return false
}

// SetDeprecation gets a reference to the given V1ImageDeprecation and assigns it to the Deprecation field.
func (o *V1Image) SetDeprecation(v V1ImageDeprecation) {
	o.Deprecation = &v
}

// GetConditions returns the Conditions field value if set, zero value otherwise.
func (o *V1Image) GetConditions() []V1ImageCondition {
	if o == nil || o.Conditions == nil {
		var ret []V1ImageCondition
		return ret
	}
	return *o.Conditions
}

// GetConditionsOk returns a tuple with the Conditions field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Image) GetConditionsOk() (*[]V1ImageCondition, bool) {
	if o == nil || o.Conditions == nil {
		return nil, false
	}
	return o.Conditions, true
}

// HasConditions returns a boolean if a field has been set.
func (o *V1Image) HasConditions() bool {
	if o != nil && o.Conditions != nil {
		return true
	}

	return false
}

// SetConditions gets a reference to the given []V1ImageCondition and assigns it to the Conditions field.
func (o *V1Image) SetConditions(v []V1ImageCondition) {
	o.Conditions = &v
}

func (o V1Image) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.StackId != nil {
		toSerialize["stackId"] = o.StackId
	}
	if o.Id != nil {
		toSerialize["id"] = o.Id
	}
	if o.Family != nil {
		toSerialize["family"] = o.Family
	}
	if o.Tag != nil {
		toSerialize["tag"] = o.Tag
	}
	if o.Metadata != nil {
		toSerialize["metadata"] = o.Metadata
	}
	if o.Description != nil {
		toSerialize["description"] = o.Description
	}
	if o.Status != nil {
		toSerialize["status"] = o.Status
	}
	if o.ImageSize != nil {
		toSerialize["imageSize"] = o.ImageSize
	}
	if o.VolumeSize != nil {
		toSerialize["volumeSize"] = o.VolumeSize
	}
	if o.Deprecation != nil {
		toSerialize["deprecation"] = o.Deprecation
	}
	if o.Conditions != nil {
		toSerialize["conditions"] = o.Conditions
	}
	return json.Marshal(toSerialize)
}

type NullableV1Image struct {
	value *V1Image
	isSet bool
}

func (v NullableV1Image) Get() *V1Image {
	return v.value
}

func (v *NullableV1Image) Set(val *V1Image) {
	v.value = val
	v.isSet = true
}

func (v NullableV1Image) IsSet() bool {
	return v.isSet
}

func (v *NullableV1Image) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableV1Image(val *V1Image) *NullableV1Image {
	return &NullableV1Image{value: val, isSet: true}
}

func (v NullableV1Image) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableV1Image) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
