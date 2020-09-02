/*
 * Sites
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sites
// CustconfBypassCache Bypass content caching on filter match
type CustconfBypassCache struct {
	// This is used by the API to perform conflict checking
	Id string `json:"id,omitempty"`
	Enabled bool `json:"enabled,omitempty"`
	// String of values delimited by a ',' character.
	MethodFilter string `json:"methodFilter,omitempty"`
	// String of values delimited by a ',' character.
	PathFilter string `json:"pathFilter,omitempty"`
	// String of values delimited by a ',' character.
	HeaderFilter string `json:"headerFilter,omitempty"`
	// String of values delimited by a ',' character.
	CookieFilter string `json:"cookieFilter,omitempty"`
}
