/*
 * Accounts and Users
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package accounts_and_users

import (
	"encoding/json"
	"time"
)

// IamPolicy A policy on a StackPath resource
type IamPolicy struct {
	// Bindings to assign members to roles
	Bindings *[]PolicyBinding `json:"bindings,omitempty"`
	// The current update number used to ensure updates happen to the expected version.  On first update this must be 0 and on each successive update this must be the last known version. When getting or as the result of a set, this will be the current version.
	Version *int64 `json:"version,omitempty"`
	// When this policy was created.  Always present on get, ignored on set.
	CreatedAt *time.Time `json:"createdAt,omitempty"`
	// When this policy was last updated.  Could be absent on get if not updated since initial creation. Ignored on set.
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
}

// NewIamPolicy instantiates a new IamPolicy object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewIamPolicy() *IamPolicy {
	this := IamPolicy{}
	return &this
}

// NewIamPolicyWithDefaults instantiates a new IamPolicy object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewIamPolicyWithDefaults() *IamPolicy {
	this := IamPolicy{}
	return &this
}

// GetBindings returns the Bindings field value if set, zero value otherwise.
func (o *IamPolicy) GetBindings() []PolicyBinding {
	if o == nil || o.Bindings == nil {
		var ret []PolicyBinding
		return ret
	}
	return *o.Bindings
}

// GetBindingsOk returns a tuple with the Bindings field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *IamPolicy) GetBindingsOk() (*[]PolicyBinding, bool) {
	if o == nil || o.Bindings == nil {
		return nil, false
	}
	return o.Bindings, true
}

// HasBindings returns a boolean if a field has been set.
func (o *IamPolicy) HasBindings() bool {
	if o != nil && o.Bindings != nil {
		return true
	}

	return false
}

// SetBindings gets a reference to the given []PolicyBinding and assigns it to the Bindings field.
func (o *IamPolicy) SetBindings(v []PolicyBinding) {
	o.Bindings = &v
}

// GetVersion returns the Version field value if set, zero value otherwise.
func (o *IamPolicy) GetVersion() int64 {
	if o == nil || o.Version == nil {
		var ret int64
		return ret
	}
	return *o.Version
}

// GetVersionOk returns a tuple with the Version field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *IamPolicy) GetVersionOk() (*int64, bool) {
	if o == nil || o.Version == nil {
		return nil, false
	}
	return o.Version, true
}

// HasVersion returns a boolean if a field has been set.
func (o *IamPolicy) HasVersion() bool {
	if o != nil && o.Version != nil {
		return true
	}

	return false
}

// SetVersion gets a reference to the given int64 and assigns it to the Version field.
func (o *IamPolicy) SetVersion(v int64) {
	o.Version = &v
}

// GetCreatedAt returns the CreatedAt field value if set, zero value otherwise.
func (o *IamPolicy) GetCreatedAt() time.Time {
	if o == nil || o.CreatedAt == nil {
		var ret time.Time
		return ret
	}
	return *o.CreatedAt
}

// GetCreatedAtOk returns a tuple with the CreatedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *IamPolicy) GetCreatedAtOk() (*time.Time, bool) {
	if o == nil || o.CreatedAt == nil {
		return nil, false
	}
	return o.CreatedAt, true
}

// HasCreatedAt returns a boolean if a field has been set.
func (o *IamPolicy) HasCreatedAt() bool {
	if o != nil && o.CreatedAt != nil {
		return true
	}

	return false
}

// SetCreatedAt gets a reference to the given time.Time and assigns it to the CreatedAt field.
func (o *IamPolicy) SetCreatedAt(v time.Time) {
	o.CreatedAt = &v
}

// GetUpdatedAt returns the UpdatedAt field value if set, zero value otherwise.
func (o *IamPolicy) GetUpdatedAt() time.Time {
	if o == nil || o.UpdatedAt == nil {
		var ret time.Time
		return ret
	}
	return *o.UpdatedAt
}

// GetUpdatedAtOk returns a tuple with the UpdatedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *IamPolicy) GetUpdatedAtOk() (*time.Time, bool) {
	if o == nil || o.UpdatedAt == nil {
		return nil, false
	}
	return o.UpdatedAt, true
}

// HasUpdatedAt returns a boolean if a field has been set.
func (o *IamPolicy) HasUpdatedAt() bool {
	if o != nil && o.UpdatedAt != nil {
		return true
	}

	return false
}

// SetUpdatedAt gets a reference to the given time.Time and assigns it to the UpdatedAt field.
func (o *IamPolicy) SetUpdatedAt(v time.Time) {
	o.UpdatedAt = &v
}

func (o IamPolicy) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Bindings != nil {
		toSerialize["bindings"] = o.Bindings
	}
	if o.Version != nil {
		toSerialize["version"] = o.Version
	}
	if o.CreatedAt != nil {
		toSerialize["createdAt"] = o.CreatedAt
	}
	if o.UpdatedAt != nil {
		toSerialize["updatedAt"] = o.UpdatedAt
	}
	return json.Marshal(toSerialize)
}

type NullableIamPolicy struct {
	value *IamPolicy
	isSet bool
}

func (v NullableIamPolicy) Get() *IamPolicy {
	return v.value
}

func (v *NullableIamPolicy) Set(val *IamPolicy) {
	v.value = val
	v.isSet = true
}

func (v NullableIamPolicy) IsSet() bool {
	return v.isSet
}

func (v *NullableIamPolicy) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableIamPolicy(val *IamPolicy) *NullableIamPolicy {
	return &NullableIamPolicy{value: val, isSet: true}
}

func (v NullableIamPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableIamPolicy) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
