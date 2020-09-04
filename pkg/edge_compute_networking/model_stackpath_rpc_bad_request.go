/*
 * Edge Compute Networking
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute_networking

import (
	"encoding/json"
)

// StackpathRpcBadRequest struct for StackpathRpcBadRequest
type StackpathRpcBadRequest struct {
	ApiStatusDetail
	FieldViolations *[]StackpathRpcBadRequestFieldViolation `json:"fieldViolations,omitempty"`
}

// NewStackpathRpcBadRequest instantiates a new StackpathRpcBadRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcBadRequest() *StackpathRpcBadRequest {
	this := StackpathRpcBadRequest{}
	return &this
}

// NewStackpathRpcBadRequestWithDefaults instantiates a new StackpathRpcBadRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcBadRequestWithDefaults() *StackpathRpcBadRequest {
	this := StackpathRpcBadRequest{}
	return &this
}

// GetFieldViolations returns the FieldViolations field value if set, zero value otherwise.
func (o *StackpathRpcBadRequest) GetFieldViolations() []StackpathRpcBadRequestFieldViolation {
	if o == nil || o.FieldViolations == nil {
		var ret []StackpathRpcBadRequestFieldViolation
		return ret
	}
	return *o.FieldViolations
}

// GetFieldViolationsOk returns a tuple with the FieldViolations field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcBadRequest) GetFieldViolationsOk() (*[]StackpathRpcBadRequestFieldViolation, bool) {
	if o == nil || o.FieldViolations == nil {
		return nil, false
	}
	return o.FieldViolations, true
}

// HasFieldViolations returns a boolean if a field has been set.
func (o *StackpathRpcBadRequest) HasFieldViolations() bool {
	if o != nil && o.FieldViolations != nil {
		return true
	}

	return false
}

// SetFieldViolations gets a reference to the given []StackpathRpcBadRequestFieldViolation and assigns it to the FieldViolations field.
func (o *StackpathRpcBadRequest) SetFieldViolations(v []StackpathRpcBadRequestFieldViolation) {
	o.FieldViolations = &v
}

func (o StackpathRpcBadRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	serializedApiStatusDetail, errApiStatusDetail := json.Marshal(o.ApiStatusDetail)
	if errApiStatusDetail != nil {
		return []byte{}, errApiStatusDetail
	}
	errApiStatusDetail = json.Unmarshal([]byte(serializedApiStatusDetail), &toSerialize)
	if errApiStatusDetail != nil {
		return []byte{}, errApiStatusDetail
	}
	if o.FieldViolations != nil {
		toSerialize["fieldViolations"] = o.FieldViolations
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathRpcBadRequest struct {
	value *StackpathRpcBadRequest
	isSet bool
}

func (v NullableStackpathRpcBadRequest) Get() *StackpathRpcBadRequest {
	return v.value
}

func (v *NullableStackpathRpcBadRequest) Set(val *StackpathRpcBadRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcBadRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcBadRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcBadRequest(val *StackpathRpcBadRequest) *NullableStackpathRpcBadRequest {
	return &NullableStackpathRpcBadRequest{value: val, isSet: true}
}

func (v NullableStackpathRpcBadRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcBadRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
