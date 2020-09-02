/*
 * Sites
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sites
// CustconfCacheKeyModification The Cache Key Modification policy allows for manipulation of the way the cache uniquely stores assets.
type CustconfCacheKeyModification struct {
	// This is used by the API to perform conflict checking
	Id string `json:"id,omitempty"`
	// When set, purges and requests for a file will be case insensitive. This setting is useful if you have a case insensitive origin server and would like to avoid duplicating assets.
	NormalizeKeyPathToLowerCase bool `json:"normalizeKeyPathToLowerCase,omitempty"`
	Enabled bool `json:"enabled,omitempty"`
}
