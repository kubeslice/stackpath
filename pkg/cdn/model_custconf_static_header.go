/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// CustconfStaticHeader The static header injection policy allows you to insert headers into the CDN request and response processor.
type CustconfStaticHeader struct {
	// This is used by the API to perform conflict checking
	Id string `json:"id,omitempty"`
	// This is the static HTTP header you want inserted into the CDN request.
	ClientRequest string `json:"clientRequest,omitempty"`
	// This is the static HTTP header you want inserted into the CDN response.
	Http string `json:"http,omitempty"`
	// This is the HTTP header you want inserted into the origin pull request.
	OriginPull string `json:"originPull,omitempty"`
	Enabled bool `json:"enabled,omitempty"`
	// String of values delimited by a ',' character.
	MethodFilter string `json:"methodFilter,omitempty"`
	// String of values delimited by a ',' character.
	PathFilter string `json:"pathFilter,omitempty"`
	// String of values delimited by a ',' character.
	HeaderFilter string `json:"headerFilter,omitempty"`
}
