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

// StackpathRpcResourceInfoAllOf struct for StackpathRpcResourceInfoAllOf
type StackpathRpcResourceInfoAllOf struct {
	ResourceType *string `json:"resourceType,omitempty"`
	ResourceName *string `json:"resourceName,omitempty"`
	Owner *string `json:"owner,omitempty"`
	Description *string `json:"description,omitempty"`
}

// NewStackpathRpcResourceInfoAllOf instantiates a new StackpathRpcResourceInfoAllOf object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcResourceInfoAllOf() *StackpathRpcResourceInfoAllOf {
	this := StackpathRpcResourceInfoAllOf{}
	return &this
}

// NewStackpathRpcResourceInfoAllOfWithDefaults instantiates a new StackpathRpcResourceInfoAllOf object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcResourceInfoAllOfWithDefaults() *StackpathRpcResourceInfoAllOf {
	this := StackpathRpcResourceInfoAllOf{}
	return &this
}

// GetResourceType returns the ResourceType field value if set, zero value otherwise.
func (o *StackpathRpcResourceInfoAllOf) GetResourceType() string {
	if o == nil || o.ResourceType == nil {
		var ret string
		return ret
	}
	return *o.ResourceType
}

// GetResourceTypeOk returns a tuple with the ResourceType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcResourceInfoAllOf) GetResourceTypeOk() (*string, bool) {
	if o == nil || o.ResourceType == nil {
		return nil, false
	}
	return o.ResourceType, true
}

// HasResourceType returns a boolean if a field has been set.
func (o *StackpathRpcResourceInfoAllOf) HasResourceType() bool {
	if o != nil && o.ResourceType != nil {
		return true
	}

	return false
}

// SetResourceType gets a reference to the given string and assigns it to the ResourceType field.
func (o *StackpathRpcResourceInfoAllOf) SetResourceType(v string) {
	o.ResourceType = &v
}

// GetResourceName returns the ResourceName field value if set, zero value otherwise.
func (o *StackpathRpcResourceInfoAllOf) GetResourceName() string {
	if o == nil || o.ResourceName == nil {
		var ret string
		return ret
	}
	return *o.ResourceName
}

// GetResourceNameOk returns a tuple with the ResourceName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcResourceInfoAllOf) GetResourceNameOk() (*string, bool) {
	if o == nil || o.ResourceName == nil {
		return nil, false
	}
	return o.ResourceName, true
}

// HasResourceName returns a boolean if a field has been set.
func (o *StackpathRpcResourceInfoAllOf) HasResourceName() bool {
	if o != nil && o.ResourceName != nil {
		return true
	}

	return false
}

// SetResourceName gets a reference to the given string and assigns it to the ResourceName field.
func (o *StackpathRpcResourceInfoAllOf) SetResourceName(v string) {
	o.ResourceName = &v
}

// GetOwner returns the Owner field value if set, zero value otherwise.
func (o *StackpathRpcResourceInfoAllOf) GetOwner() string {
	if o == nil || o.Owner == nil {
		var ret string
		return ret
	}
	return *o.Owner
}

// GetOwnerOk returns a tuple with the Owner field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcResourceInfoAllOf) GetOwnerOk() (*string, bool) {
	if o == nil || o.Owner == nil {
		return nil, false
	}
	return o.Owner, true
}

// HasOwner returns a boolean if a field has been set.
func (o *StackpathRpcResourceInfoAllOf) HasOwner() bool {
	if o != nil && o.Owner != nil {
		return true
	}

	return false
}

// SetOwner gets a reference to the given string and assigns it to the Owner field.
func (o *StackpathRpcResourceInfoAllOf) SetOwner(v string) {
	o.Owner = &v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *StackpathRpcResourceInfoAllOf) GetDescription() string {
	if o == nil || o.Description == nil {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcResourceInfoAllOf) GetDescriptionOk() (*string, bool) {
	if o == nil || o.Description == nil {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *StackpathRpcResourceInfoAllOf) HasDescription() bool {
	if o != nil && o.Description != nil {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *StackpathRpcResourceInfoAllOf) SetDescription(v string) {
	o.Description = &v
}

func (o StackpathRpcResourceInfoAllOf) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.ResourceType != nil {
		toSerialize["resourceType"] = o.ResourceType
	}
	if o.ResourceName != nil {
		toSerialize["resourceName"] = o.ResourceName
	}
	if o.Owner != nil {
		toSerialize["owner"] = o.Owner
	}
	if o.Description != nil {
		toSerialize["description"] = o.Description
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathRpcResourceInfoAllOf struct {
	value *StackpathRpcResourceInfoAllOf
	isSet bool
}

func (v NullableStackpathRpcResourceInfoAllOf) Get() *StackpathRpcResourceInfoAllOf {
	return v.value
}

func (v *NullableStackpathRpcResourceInfoAllOf) Set(val *StackpathRpcResourceInfoAllOf) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcResourceInfoAllOf) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcResourceInfoAllOf) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcResourceInfoAllOf(val *StackpathRpcResourceInfoAllOf) *NullableStackpathRpcResourceInfoAllOf {
	return &NullableStackpathRpcResourceInfoAllOf{value: val, isSet: true}
}

func (v NullableStackpathRpcResourceInfoAllOf) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcResourceInfoAllOf) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
