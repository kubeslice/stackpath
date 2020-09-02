/*
 * Object Storage
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package object_storage
// StorageCreateBucketRequest struct for StorageCreateBucketRequest
type StorageCreateBucketRequest struct {
	// The name of the bucket to be created
	Label string `json:"label,omitempty"`
	// The region where to create the bucket, defaults to us-east-1
	Region string `json:"region,omitempty"`
}
