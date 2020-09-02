/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// PurgeContentRequestPurgeSelectorType The kinds of content that can be purged from the CDN  - HEADER: Purge content based on an HTTP response header  - TAG: Purge content based on an X-TAG HTTP header value. Purging by tag can be useful when content on the origin is tagged.
type PurgeContentRequestPurgeSelectorType string

// List of PurgeContentRequestPurgeSelectorType
const (
	HEADER PurgeContentRequestPurgeSelectorType = "HEADER"
	TAG PurgeContentRequestPurgeSelectorType = "TAG"
)
