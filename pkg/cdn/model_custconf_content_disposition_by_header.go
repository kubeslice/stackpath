/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// CustconfContentDispositionByHeader The content disposition by HTTP header match policy allows you to control the Content-Disposition delivered by the CDN using a pattern match against the value of any HTTP header present in the request. If you are using URL query string parameters to control the Content-Disposition header (using the Content Disposition by URL policy) then the Content-Disposition header generated by this policy will not be used on that specific request. A typical use case for this policy is to set a different Content-Disposition header based on the User-Agent in the request.
type CustconfContentDispositionByHeader struct {
	// This is used by the API to perform conflict checking
	Id string `json:"id,omitempty"`
	// The setting allows you to specify the name of the HTTP header you'd like to use in the pattern match for this policy.
	HeaderFieldName string `json:"headerFieldName,omitempty"`
	// String of values delimited by a ',' character. A list of glob patterns that apply this policy if any of them match against the value of the header specified.
	HeaderValueMatch string `json:"headerValueMatch,omitempty"`
	DefaultType ContentDispositionByHeaderDefaultTypeEnumWrapperValue `json:"defaultType,omitempty"`
	// This setting allows you to force the Content-Disposition generated by the CDN for this policy to override the Content-Disposition header cached from your origin.
	OverrideOriginHeader bool `json:"overrideOriginHeader,omitempty"`
	Enabled bool `json:"enabled,omitempty"`
	// String of values delimited by a ',' character.
	MethodFilter string `json:"methodFilter,omitempty"`
	// String of values delimited by a ',' character.
	PathFilter string `json:"pathFilter,omitempty"`
	// String of values delimited by a ',' character.
	HeaderFilter string `json:"headerFilter,omitempty"`
}
