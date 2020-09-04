/*
 * Object Storage
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package object_storage

import (
	"encoding/json"
)

// StorageGetBucketResponse The bucket for the given stack
type StorageGetBucketResponse struct {
	Bucket *StorageBucket `json:"bucket,omitempty"`
}

// NewStorageGetBucketResponse instantiates a new StorageGetBucketResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStorageGetBucketResponse() *StorageGetBucketResponse {
	this := StorageGetBucketResponse{}
	return &this
}

// NewStorageGetBucketResponseWithDefaults instantiates a new StorageGetBucketResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStorageGetBucketResponseWithDefaults() *StorageGetBucketResponse {
	this := StorageGetBucketResponse{}
	return &this
}

// GetBucket returns the Bucket field value if set, zero value otherwise.
func (o *StorageGetBucketResponse) GetBucket() StorageBucket {
	if o == nil || o.Bucket == nil {
		var ret StorageBucket
		return ret
	}
	return *o.Bucket
}

// GetBucketOk returns a tuple with the Bucket field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StorageGetBucketResponse) GetBucketOk() (*StorageBucket, bool) {
	if o == nil || o.Bucket == nil {
		return nil, false
	}
	return o.Bucket, true
}

// HasBucket returns a boolean if a field has been set.
func (o *StorageGetBucketResponse) HasBucket() bool {
	if o != nil && o.Bucket != nil {
		return true
	}

	return false
}

// SetBucket gets a reference to the given StorageBucket and assigns it to the Bucket field.
func (o *StorageGetBucketResponse) SetBucket(v StorageBucket) {
	o.Bucket = &v
}

func (o StorageGetBucketResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Bucket != nil {
		toSerialize["bucket"] = o.Bucket
	}
	return json.Marshal(toSerialize)
}

type NullableStorageGetBucketResponse struct {
	value *StorageGetBucketResponse
	isSet bool
}

func (v NullableStorageGetBucketResponse) Get() *StorageGetBucketResponse {
	return v.value
}

func (v *NullableStorageGetBucketResponse) Set(val *StorageGetBucketResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableStorageGetBucketResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableStorageGetBucketResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStorageGetBucketResponse(val *StorageGetBucketResponse) *NullableStorageGetBucketResponse {
	return &NullableStorageGetBucketResponse{value: val, isSet: true}
}

func (v NullableStorageGetBucketResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStorageGetBucketResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
