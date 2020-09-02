/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// CdnHttpVerificationDetails HTTP-based domain ownership verification details
type CdnHttpVerificationDetails struct {
	// Path to the verification file
	Path string `json:"path,omitempty"`
	// Response content type
	ContentType string `json:"contentType,omitempty"`
	// Body content of response
	Body string `json:"body,omitempty"`
}
