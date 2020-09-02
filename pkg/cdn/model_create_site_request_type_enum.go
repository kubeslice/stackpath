/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn
// CreateSiteRequestTypeEnum The CDN site's type  A site's type determines how StackPath delivers content to incoming HTTP(S) requests.   - CDN: The site is a CDN only site  - WAF: The site is either a standalone WAF site or a WAF site with attached CDN service  - API: The site is an API delivery site. API delivery sites are powered by both the WAF and CDN and have custom rulesets for each.
type CreateSiteRequestTypeEnum string

// List of CreateSiteRequestTypeEnum
const (
	CDN CreateSiteRequestTypeEnum = "CDN"
	WAF CreateSiteRequestTypeEnum = "WAF"
	API CreateSiteRequestTypeEnum = "API"
)
