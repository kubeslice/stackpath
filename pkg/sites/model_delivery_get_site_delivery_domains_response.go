/*
 * Sites
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sites
// DeliveryGetSiteDeliveryDomainsResponse The response from a request to retrieve a site's associated delivery domains
type DeliveryGetSiteDeliveryDomainsResponse struct {
	PageInfo PaginationPageInfo `json:"pageInfo,omitempty"`
	// The requested site delivery domains
	Results []SchemadeliveryDeliveryDomain `json:"results,omitempty"`
}
