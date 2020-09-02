/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// CustconfOriginPullCacheExtension The cache extension policy allows you to define cache revalidation exceptions on expired content. This policy is applied by the CDN caching servers when they are are unable to revalidate an expired asset with your origin due to network connectivity issues or unresponsiveness from your origin.
type CustconfOriginPullCacheExtension struct {
	// This is used by the API to perform conflict checking
	Id string `json:"id,omitempty"`
	// This is the number of seconds to extend an asset's TTL when the origin is unavailable. The CDN will continue to retry the origin up to the Origin Unavailable Max TTL.
	ExpiredCacheExtension int32 `json:"expiredCacheExtension,omitempty"`
	// The origin unavailable max TTL value is used by the caching server when your origin is unresponsive or the CDN cannot establish a connection to your origin. Under these conditions, the CDN can continue to serve expired assets from the cache. The value specified in this field establishes a maximum allowable TTL for your expired assets. If your origin connectivity or responsiveness is not corrected within your maximum allowable TTL, the CDN no longer serves your expired assets.
	OriginUnreachableCacheExtension int32 `json:"originUnreachableCacheExtension,omitempty"`
	Enabled bool `json:"enabled,omitempty"`
}
