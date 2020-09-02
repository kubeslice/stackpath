/*
 * Sites
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sites
// SchemadeliveryOrigin A CDN site's origin  Origins are the original sources of the data that is cached by the CDN on request.
type SchemadeliveryOrigin struct {
	// An origin's unique identifier
	Id string `json:"id,omitempty"`
	// The stack for which the origin belongs to
	StackId string `json:"stackId,omitempty"`
	// Whether or not an origin is dedicated to a CDN site  Dedicated origins cannot be used by any site other than that to which it is dedicated.
	Dedicated bool `json:"dedicated,omitempty"`
	// The ID of the CDN site to which an origin is dedicated
	SiteId string `json:"siteId,omitempty"`
	Http DeliveryHttpOrigin `json:"http,omitempty"`
	StackpathStorage DeliveryStackPathStorageOrigin `json:"stackpathStorage,omitempty"`
	S3Storage DeliveryAwss3Origin `json:"s3Storage,omitempty"`
	GoogleCloudStorage DeliveryGoogleStorageOrigin `json:"googleCloudStorage,omitempty"`
}
