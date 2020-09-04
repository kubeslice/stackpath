/*
 * Edge Compute
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute
// V1ImageStatus Which capture status an image is currently in  - IMAGE_STATUS_UNKNOWN: The image status is unknown  - PENDING: The image is pending creation  - PROCESSING: The image is processing  - READY: The image is ready  - FAILED: The image failed to be created
type V1ImageStatus string

// List of v1ImageStatus
const (
	V1IMAGESTATUS_IMAGE_STATUS_UNKNOWN V1ImageStatus = "IMAGE_STATUS_UNKNOWN"
	V1IMAGESTATUS_PENDING V1ImageStatus = "PENDING"
	V1IMAGESTATUS_PROCESSING V1ImageStatus = "PROCESSING"
	V1IMAGESTATUS_READY V1ImageStatus = "READY"
	V1IMAGESTATUS_FAILED V1ImageStatus = "FAILED"
)
