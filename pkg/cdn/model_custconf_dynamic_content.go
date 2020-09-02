/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// CustconfDynamicContent The dynamic content caching policy allows you to specify a set of query string and/or HTTP header key/value pairs that should create a unique cache entry for a given URL. This policy is useful when your origin returns unique content for the same URL based on a set of query string parameters provided in the request.
type CustconfDynamicContent struct {
	// This is used by the API to perform conflict checking
	Id string `json:"id,omitempty"`
	// String of values delimited by a ',' character. A comma separated list of query string parameters you want to include in the cache key generation. NOTE: This list is ignored when the Key Location is set to header.
	QueryParams string `json:"queryParams,omitempty"`
	// String of values delimited by a ',' character. A comma-separated list of glob patterns that represent HTTP request headers you want included in the cache key generation. Via the use of a colon ':', users can define each glob pattern to match a header name only, or the pattern can be used to match both the header name and value. A pattern without a colon ':' is treated as a header name ONLY match. If the pattern matches the header, then all values are used as a part of the cache key. If the pattern contains a colon, the CDN uses the pattern on the left of the colon to match the header. The pattern to the right of the colon is used to match the value. The CDN only uses the header/value as a part of the cache key if both patterns result in a match. Note, no pattern after a colon indicates an empty header (no value). See the fnmatch manpage for acceptable glob patterns.
	HeaderFields string `json:"headerFields,omitempty"`
	Enabled bool `json:"enabled,omitempty"`
	// String of values delimited by a ',' character.
	MethodFilter string `json:"methodFilter,omitempty"`
	// String of values delimited by a ',' character.
	PathFilter string `json:"pathFilter,omitempty"`
	// String of values delimited by a ',' character.
	HeaderFilter string `json:"headerFilter,omitempty"`
}
