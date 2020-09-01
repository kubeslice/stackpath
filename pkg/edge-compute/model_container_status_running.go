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
	"time"
)

// ContainerStatusRunning Properties related to running containers
type ContainerStatusRunning struct {
	// The date a container started
	StartedAt *time.Time `json:"startedAt,omitempty"`
}

// NewContainerStatusRunning instantiates a new ContainerStatusRunning object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewContainerStatusRunning() *ContainerStatusRunning {
	this := ContainerStatusRunning{}
	return &this
}

// NewContainerStatusRunningWithDefaults instantiates a new ContainerStatusRunning object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewContainerStatusRunningWithDefaults() *ContainerStatusRunning {
	this := ContainerStatusRunning{}
	return &this
}

// GetStartedAt returns the StartedAt field value if set, zero value otherwise.
func (o *ContainerStatusRunning) GetStartedAt() time.Time {
	if o == nil || o.StartedAt == nil {
		var ret time.Time
		return ret
	}
	return *o.StartedAt
}

// GetStartedAtOk returns a tuple with the StartedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *ContainerStatusRunning) GetStartedAtOk() (*time.Time, bool) {
	if o == nil || o.StartedAt == nil {
		return nil, false
	}
	return o.StartedAt, true
}

// HasStartedAt returns a boolean if a field has been set.
func (o *ContainerStatusRunning) HasStartedAt() bool {
	if o != nil && o.StartedAt != nil {
		return true
	}

	return false
}

// SetStartedAt gets a reference to the given time.Time and assigns it to the StartedAt field.
func (o *ContainerStatusRunning) SetStartedAt(v time.Time) {
	o.StartedAt = &v
}

func (o ContainerStatusRunning) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.StartedAt != nil {
		toSerialize["startedAt"] = o.StartedAt
	}
	return json.Marshal(toSerialize)
}

type NullableContainerStatusRunning struct {
	value *ContainerStatusRunning
	isSet bool
}

func (v NullableContainerStatusRunning) Get() *ContainerStatusRunning {
	return v.value
}

func (v *NullableContainerStatusRunning) Set(val *ContainerStatusRunning) {
	v.value = val
	v.isSet = true
}

func (v NullableContainerStatusRunning) IsSet() bool {
	return v.isSet
}

func (v *NullableContainerStatusRunning) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableContainerStatusRunning(val *ContainerStatusRunning) *NullableContainerStatusRunning {
	return &NullableContainerStatusRunning{value: val, isSet: true}
}

func (v NullableContainerStatusRunning) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableContainerStatusRunning) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
