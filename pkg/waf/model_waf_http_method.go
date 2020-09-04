/*
 * Web Application Firewall
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package waf
// WafHttpMethod HTTP methods of a request  - METHOD_UNSPECIFIED: Unspecified HTTP method  - GET: HTTP GET method  - POST: HTTP POST method  - PUT: HTTP PUT method  - DELETE: HTTP DELETE method  - HEAD: HTTP HEAD method  - PATCH: HTTP PATCH method  - OPTIONS: HTTP OPTIONS method  - CONNECT: HTTP CONNECT method  - TRACE: HTTP TRACE method
type WafHttpMethod string

// List of wafHttpMethod
const (
	WAFHTTPMETHOD_METHOD_UNSPECIFIED WafHttpMethod = "METHOD_UNSPECIFIED"
	WAFHTTPMETHOD_GET WafHttpMethod = "GET"
	WAFHTTPMETHOD_POST WafHttpMethod = "POST"
	WAFHTTPMETHOD_PUT WafHttpMethod = "PUT"
	WAFHTTPMETHOD_DELETE WafHttpMethod = "DELETE"
	WAFHTTPMETHOD_HEAD WafHttpMethod = "HEAD"
	WAFHTTPMETHOD_PATCH WafHttpMethod = "PATCH"
	WAFHTTPMETHOD_OPTIONS WafHttpMethod = "OPTIONS"
	WAFHTTPMETHOD_CONNECT WafHttpMethod = "CONNECT"
	WAFHTTPMETHOD_TRACE WafHttpMethod = "TRACE"
)
