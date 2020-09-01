/*
 * Object Storage
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package object-storage

import (
	"encoding/json"
)

// StackpathRpcRequestInfo struct for StackpathRpcRequestInfo
type StackpathRpcRequestInfo struct {
	ApiStatusDetail
	RequestId *string `json:"requestId,omitempty"`
	ServingData *string `json:"servingData,omitempty"`
}

// NewStackpathRpcRequestInfo instantiates a new StackpathRpcRequestInfo object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStackpathRpcRequestInfo() *StackpathRpcRequestInfo {
	this := StackpathRpcRequestInfo{}
	return &this
}

// NewStackpathRpcRequestInfoWithDefaults instantiates a new StackpathRpcRequestInfo object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStackpathRpcRequestInfoWithDefaults() *StackpathRpcRequestInfo {
	this := StackpathRpcRequestInfo{}
	return &this
}

// GetRequestId returns the RequestId field value if set, zero value otherwise.
func (o *StackpathRpcRequestInfo) GetRequestId() string {
	if o == nil || o.RequestId == nil {
		var ret string
		return ret
	}
	return *o.RequestId
}

// GetRequestIdOk returns a tuple with the RequestId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcRequestInfo) GetRequestIdOk() (*string, bool) {
	if o == nil || o.RequestId == nil {
		return nil, false
	}
	return o.RequestId, true
}

// HasRequestId returns a boolean if a field has been set.
func (o *StackpathRpcRequestInfo) HasRequestId() bool {
	if o != nil && o.RequestId != nil {
		return true
	}

	return false
}

// SetRequestId gets a reference to the given string and assigns it to the RequestId field.
func (o *StackpathRpcRequestInfo) SetRequestId(v string) {
	o.RequestId = &v
}

// GetServingData returns the ServingData field value if set, zero value otherwise.
func (o *StackpathRpcRequestInfo) GetServingData() string {
	if o == nil || o.ServingData == nil {
		var ret string
		return ret
	}
	return *o.ServingData
}

// GetServingDataOk returns a tuple with the ServingData field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StackpathRpcRequestInfo) GetServingDataOk() (*string, bool) {
	if o == nil || o.ServingData == nil {
		return nil, false
	}
	return o.ServingData, true
}

// HasServingData returns a boolean if a field has been set.
func (o *StackpathRpcRequestInfo) HasServingData() bool {
	if o != nil && o.ServingData != nil {
		return true
	}

	return false
}

// SetServingData gets a reference to the given string and assigns it to the ServingData field.
func (o *StackpathRpcRequestInfo) SetServingData(v string) {
	o.ServingData = &v
}

func (o StackpathRpcRequestInfo) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	serializedApiStatusDetail, errApiStatusDetail := json.Marshal(o.ApiStatusDetail)
	if errApiStatusDetail != nil {
		return []byte{}, errApiStatusDetail
	}
	errApiStatusDetail = json.Unmarshal([]byte(serializedApiStatusDetail), &toSerialize)
	if errApiStatusDetail != nil {
		return []byte{}, errApiStatusDetail
	}
	if o.RequestId != nil {
		toSerialize["requestId"] = o.RequestId
	}
	if o.ServingData != nil {
		toSerialize["servingData"] = o.ServingData
	}
	return json.Marshal(toSerialize)
}

type NullableStackpathRpcRequestInfo struct {
	value *StackpathRpcRequestInfo
	isSet bool
}

func (v NullableStackpathRpcRequestInfo) Get() *StackpathRpcRequestInfo {
	return v.value
}

func (v *NullableStackpathRpcRequestInfo) Set(val *StackpathRpcRequestInfo) {
	v.value = val
	v.isSet = true
}

func (v NullableStackpathRpcRequestInfo) IsSet() bool {
	return v.isSet
}

func (v *NullableStackpathRpcRequestInfo) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStackpathRpcRequestInfo(val *StackpathRpcRequestInfo) *NullableStackpathRpcRequestInfo {
	return &NullableStackpathRpcRequestInfo{value: val, isSet: true}
}

func (v NullableStackpathRpcRequestInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStackpathRpcRequestInfo) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
