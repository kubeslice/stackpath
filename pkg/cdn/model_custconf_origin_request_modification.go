/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// CustconfOriginRequestModification struct for CustconfOriginRequestModification
type CustconfOriginRequestModification struct {
	// This is used by the API to perform conflict checking
	Id string `json:"id,omitempty"`
	UrlPattern string `json:"urlPattern,omitempty"`
	UrlRewrite string `json:"urlRewrite,omitempty"`
	HeaderPattern string `json:"headerPattern,omitempty"`
	HeaderRewrite string `json:"headerRewrite,omitempty"`
	// String of values delimited by a '|' character. This is the static HTTP header you want inserted into the CDN request. Start value with \"append:\", \"replace:\" or \"create:\" which defines if Header will be added, replaced or create if not exists. Default is append.
	AddHeaders string `json:"addHeaders,omitempty"`
	FlowControl string `json:"flowControl,omitempty"`
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
