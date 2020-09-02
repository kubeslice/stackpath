/*
 * Web Application Firewall
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package waf
// WafCertificateVerificationMethod The Certificate Verification Method  Verification method used to validate a requested certificate on a site   - DNS: Verify a certificate using DNS records  - HTTP: Verify a certificate by using HTTP validation. This will require that all hosts on the certificate point to the site hash or IP
type WafCertificateVerificationMethod string

// List of wafCertificateVerificationMethod
const (
	DNS WafCertificateVerificationMethod = "DNS"
	HTTP WafCertificateVerificationMethod = "HTTP"
)
