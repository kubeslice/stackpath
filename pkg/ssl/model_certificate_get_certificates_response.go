/*
 * SSL
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package ssl
// CertificateGetCertificatesResponse struct for CertificateGetCertificatesResponse
type CertificateGetCertificatesResponse struct {
	PageInfo PaginationPageInfo `json:"pageInfo,omitempty"`
	Results []CertificateCertificate `json:"results,omitempty"`
}
