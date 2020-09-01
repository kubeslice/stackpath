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

// StorageUpdateBucketResponse A response of the updated bucket
type StorageUpdateBucketResponse struct {
	Bucket *StorageBucket `json:"bucket,omitempty"`
}

// NewStorageUpdateBucketResponse instantiates a new StorageUpdateBucketResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewStorageUpdateBucketResponse() *StorageUpdateBucketResponse {
	this := StorageUpdateBucketResponse{}
	return &this
}

// NewStorageUpdateBucketResponseWithDefaults instantiates a new StorageUpdateBucketResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewStorageUpdateBucketResponseWithDefaults() *StorageUpdateBucketResponse {
	this := StorageUpdateBucketResponse{}
	return &this
}

// GetBucket returns the Bucket field value if set, zero value otherwise.
func (o *StorageUpdateBucketResponse) GetBucket() StorageBucket {
	if o == nil || o.Bucket == nil {
		var ret StorageBucket
		return ret
	}
	return *o.Bucket
}

// GetBucketOk returns a tuple with the Bucket field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *StorageUpdateBucketResponse) GetBucketOk() (*StorageBucket, bool) {
	if o == nil || o.Bucket == nil {
		return nil, false
	}
	return o.Bucket, true
}

// HasBucket returns a boolean if a field has been set.
func (o *StorageUpdateBucketResponse) HasBucket() bool {
	if o != nil && o.Bucket != nil {
		return true
	}

	return false
}

// SetBucket gets a reference to the given StorageBucket and assigns it to the Bucket field.
func (o *StorageUpdateBucketResponse) SetBucket(v StorageBucket) {
	o.Bucket = &v
}

func (o StorageUpdateBucketResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Bucket != nil {
		toSerialize["bucket"] = o.Bucket
	}
	return json.Marshal(toSerialize)
}

type NullableStorageUpdateBucketResponse struct {
	value *StorageUpdateBucketResponse
	isSet bool
}

func (v NullableStorageUpdateBucketResponse) Get() *StorageUpdateBucketResponse {
	return v.value
}

func (v *NullableStorageUpdateBucketResponse) Set(val *StorageUpdateBucketResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableStorageUpdateBucketResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableStorageUpdateBucketResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableStorageUpdateBucketResponse(val *StorageUpdateBucketResponse) *NullableStorageUpdateBucketResponse {
	return &NullableStorageUpdateBucketResponse{value: val, isSet: true}
}

func (v NullableStorageUpdateBucketResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableStorageUpdateBucketResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
