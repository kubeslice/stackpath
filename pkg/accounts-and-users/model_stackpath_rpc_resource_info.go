/*
 * Accounts and Users
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package accounts-and-users

import (
	"encoding/json"
)

// StackpathRpcResourceInfo struct for StackpathRpcResourceInfo
type StackpathRpcResourceInfo struct {
	ApiStatusDetail
	ResourceType *string `json:"resourceType,omitempty"`
	ResourceName *string `json:"resourceName,omitempty"`
	Owner *string `json:"owner,omitempty"`
	Description *string `json:"description,omitempty"`
}

// NewStackpathRpcResourceInfo instantiates a new StackpathRpcResourceInfo object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcResourceInfo() *StackpathRpcResourceInfo {
	this := StackpathRpcResourceInfo{}
	return &this
}

// NewStackpathRpcResourceInfoWithDefaults instantiates a new StackpathRpcResourceInfo object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcResourceInfoWithDefaults() *StackpathRpcResourceInfo {
	this := StackpathRpcResourceInfo{}
	return &this
}

// GetResourceType returns the ResourceType field value if set, zero value otherwise.
func (o *StackpathRpcResourceInfo) GetResourceType() string {
	if o == nil || o.ResourceType == nil {
		var ret string
		return ret
	}
	return *o.ResourceType
}

// GetResourceTypeOk returns a tuple with the ResourceType field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcResourceInfo) GetResourceTypeOk() (*string, bool) {
	if o == nil || o.ResourceType == nil {
		return nil, false
	}
	return o.ResourceType, true
}

// HasResourceType returns a boolean if a field has been set.
func (o *StackpathRpcResourceInfo) HasResourceType() bool {
	if o != nil && o.ResourceType != nil {
		return true
	}

	return false
}

// SetResourceType gets a reference to the given string and assigns it to the ResourceType field.
func (o *StackpathRpcResourceInfo) SetResourceType(v string) {
	o.ResourceType = &v
}

// GetResourceName returns the ResourceName field value if set, zero value otherwise.
func (o *StackpathRpcResourceInfo) GetResourceName() string {
	if o == nil || o.ResourceName == nil {
		var ret string
		return ret
	}
	return *o.ResourceName
}

// GetResourceNameOk returns a tuple with the ResourceName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcResourceInfo) GetResourceNameOk() (*string, bool) {
	if o == nil || o.ResourceName == nil {
		return nil, false
	}
	return o.ResourceName, true
}

// HasResourceName returns a boolean if a field has been set.
func (o *StackpathRpcResourceInfo) HasResourceName() bool {
	if o != nil && o.ResourceName != nil {
		return true
	}

	return false
}

// SetResourceName gets a reference to the given string and assigns it to the ResourceName field.
func (o *StackpathRpcResourceInfo) SetResourceName(v string) {
	o.ResourceName = &v
}

// GetOwner returns the Owner field value if set, zero value otherwise.
func (o *StackpathRpcResourceInfo) GetOwner() string {
	if o == nil || o.Owner == nil {
		var ret string
		return ret
	}
	return *o.Owner
}

// GetOwnerOk returns a tuple with the Owner field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcResourceInfo) GetOwnerOk() (*string, bool) {
	if o == nil || o.Owner == nil {
		return nil, false
	}
	return o.Owner, true
}

// HasOwner returns a boolean if a field has been set.
func (o *StackpathRpcResourceInfo) HasOwner() bool {
	if o != nil && o.Owner != nil {
		return true
	}

	return false
}

// SetOwner gets a reference to the given string and assigns it to the Owner field.
func (o *StackpathRpcResourceInfo) SetOwner(v string) {
	o.Owner = &v
}

// GetDescription returns the Description field value if set, zero value otherwise.
func (o *StackpathRpcResourceInfo) GetDescription() string {
	if o == nil || o.Description == nil {
		var ret string
		return ret
	}
	return *o.Description
}

// GetDescriptionOk returns a tuple with the Description field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcResourceInfo) GetDescriptionOk() (*string, bool) {
	if o == nil || o.Description == nil {
		return nil, false
	}
	return o.Description, true
}

// HasDescription returns a boolean if a field has been set.
func (o *StackpathRpcResourceInfo) HasDescription() bool {
	if o != nil && o.Description != nil {
		return true
	}

	return false
}

// SetDescription gets a reference to the given string and assigns it to the Description field.
func (o *StackpathRpcResourceInfo) SetDescription(v string) {
	o.Description = &v
}

func (o StackpathRpcResourceInfo) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	serializedApiStatusDetail, errApiStatusDetail := json.Marshal(o.ApiStatusDetail)
	if errApiStatusDetail != nil {
		return []byte{}, errApiStatusDetail
	}
	errApiStatusDetail = json.Unmarshal([]byte(serializedApiStatusDetail), &toSerialize)
	if errApiStatusDetail != nil {
		return []byte{}, errApiStatusDetail
	}
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

type NullableStackpathRpcResourceInfo struct {
	value *StackpathRpcResourceInfo
	isSet bool
}

func (v NullableStackpathRpcResourceInfo) Get() *StackpathRpcResourceInfo {
	return v.value
}

func (v *NullableStackpathRpcResourceInfo) Set(val *StackpathRpcResourceInfo) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcResourceInfo) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcResourceInfo) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcResourceInfo(val *StackpathRpcResourceInfo) *NullableStackpathRpcResourceInfo {
	return &NullableStackpathRpcResourceInfo{value: val, isSet: true}
}

func (v NullableStackpathRpcResourceInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcResourceInfo) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
