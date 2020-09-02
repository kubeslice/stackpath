/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// CustconfContentDispositionByUrl The content disposition by URL policy allows you to control Content-Disposition HTTP header delivered by the CDN caching servers. The policy gives you control over each of the header directives and allows you to specify a URL pattern match for determining when to apply the policy. Please note this policy takes precedence over all the other content disposition policies.
type CustconfContentDispositionByUrl struct {
	// This is used by the API to perform conflict checking
	Id string `json:"id,omitempty"`
	// This is the name of the query string parameter which contains the file name to use in the Content-Disposition header. This setting is typically used by customers to configure a \"friendly name\" for URLs that have obfuscated file names.
	DispositionNameQSParam string `json:"dispositionNameQSParam,omitempty"`
	// This is the name of the query string parameter which contains the disposition type to use in the Content-Disposition header. Typically, this value is set to attachment if you want the browser to present the user with a \"File Download\" dialog box and set to inline if you want the browser to render the content inline (play an audio/video file instead of downloading it).
	DispositionTypeQSParam string `json:"dispositionTypeQSParam,omitempty"`
	// This setting allows you to define a query string parameter that when present in the URL contains a string that should be used for the Content-Disposition header. The string specified in the URL will completely replace the value the CDN would have used based on other policies defined for the Content-Disposition header.
	DispositionOverrideQSParam string `json:"dispositionOverrideQSParam,omitempty"`
	// This setting allows you to force the Content-Disposition generated by the CDN for this policy to override the Content-Disposition header cached from your origin.
	OverrideOriginHeader bool `json:"overrideOriginHeader,omitempty"`
	Enabled bool `json:"enabled,omitempty"`
}
