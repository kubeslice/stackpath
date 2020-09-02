/*
 * Sites
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sites
// CustconfOriginPullProtocol The Origin Pull Protocol allows you to configure the CDN caching servers to use secured or non-secured connection to Origin.
type CustconfOriginPullProtocol struct {
	// This is used by the API to perform conflict checking
	Id string `json:"id,omitempty"`
	Protocol CustconfOriginPullProtocolProtocolEnumWrapperValue `json:"protocol,omitempty"`
	// This key allows you to configure the CDN caching servers to use SNI while making Secured Connection to Origin.
	EnableSNI bool `json:"enableSNI,omitempty"`
}
