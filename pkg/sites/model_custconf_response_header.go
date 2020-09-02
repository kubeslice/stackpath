/*
 * Sites
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sites
// CustconfResponseHeader The custom HTTP response headers policy allows you to specify a list of HTTP headers you want the CDN caching servers to include in the response to clients.
type CustconfResponseHeader struct {
	// This is used by the API to perform conflict checking
	Id string `json:"id,omitempty"`
	// A pipe delimited list of rules that instructs the CDN caching servers to include a content-disposition header. The rules included in this setting must be entered in the following format: Content-Disposition:<User Agent>:<file extension 1>, <file extension 2>. For example, to send the Content-Disposition header for all Mozilla browsers on the delivery of mp3, exe, tar, zip, gz and rar files, you would enter the following in the field: Content-Disposition:Mozilla*:mp3,exe,tar,zip,gz,rar
	Http string `json:"http,omitempty"`
	// This gives the ability to disable the ETag header on the response.
	EnableETag bool `json:"enableETag,omitempty"`
	Enabled bool `json:"enabled,omitempty"`
}
