/*
 * Web Application Firewall
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package waf

import (
	_context "context"
	_ioutil "io/ioutil"
	_nethttp "net/http"
	_neturl "net/url"
	"strings"
)

// Linger please
var (
	_ _context.Context
)

// ConfigurationApiService ConfigurationApi service
type ConfigurationApiService service

type apiGetSiteDnsTargetsRequest struct {
	ctx _context.Context
	apiService *ConfigurationApiService
	stackId string
	siteId string
}


/*
GetSiteDnsTargets Get CNAME targets
A site's hostname should point to these CNAME targets in order for traffic to be sent through StackPath's edge nodes.
 * @param ctx _context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 * @param stackId A stack ID or slug
 * @param siteId A site ID
@return apiGetSiteDnsTargetsRequest
*/
func (a *ConfigurationApiService) GetSiteDnsTargets(ctx _context.Context, stackId string, siteId string) apiGetSiteDnsTargetsRequest {
	return apiGetSiteDnsTargetsRequest{
		apiService: a,
		ctx: ctx,
		stackId: stackId,
		siteId: siteId,
	}
}

/*
Execute executes the request
 @return WafGetSiteDnsTargetsResponse
*/
func (r apiGetSiteDnsTargetsRequest) Execute() (WafGetSiteDnsTargetsResponse, *_nethttp.Response, error) {
	var (
		localVarHTTPMethod   = _nethttp.MethodGet
		localVarPostBody     interface{}
		localVarFormFileName string
		localVarFileName     string
		localVarFileBytes    []byte
		localVarReturnValue  WafGetSiteDnsTargetsResponse
	)

	localBasePath, err := r.apiService.client.cfg.ServerURLWithContext(r.ctx, "ConfigurationApiService.GetSiteDnsTargets")
	if err != nil {
		return localVarReturnValue, nil, GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/waf/v1/stacks/{stack_id}/sites/{site_id}/delivery/dns/targets"
	localVarPath = strings.Replace(localVarPath, "{"+"stack_id"+"}", _neturl.QueryEscape(parameterToString(r.stackId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"site_id"+"}", _neturl.QueryEscape(parameterToString(r.siteId, "")) , -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := _neturl.Values{}
	localVarFormParams := _neturl.Values{}
	
	

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{}

	// set Content-Type header
	localVarHTTPContentType := selectHeaderContentType(localVarHTTPContentTypes)
	if localVarHTTPContentType != "" {
		localVarHeaderParams["Content-Type"] = localVarHTTPContentType
	}

	// to determine the Accept header
	localVarHTTPHeaderAccepts := []string{"application/json"}

	// set Accept header
	localVarHTTPHeaderAccept := selectHeaderAccept(localVarHTTPHeaderAccepts)
	if localVarHTTPHeaderAccept != "" {
		localVarHeaderParams["Accept"] = localVarHTTPHeaderAccept
	}
	req, err := r.apiService.client.prepareRequest(r.ctx, localVarPath, localVarHTTPMethod, localVarPostBody, localVarHeaderParams, localVarQueryParams, localVarFormParams, localVarFormFileName, localVarFileName, localVarFileBytes)
	if err != nil {
		return localVarReturnValue, nil, err
	}

	localVarHTTPResponse, err := r.apiService.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	localVarBody, err := _ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	if err != nil {
		return localVarReturnValue, localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 401 {
			var v StackpathapiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 500 {
			var v StackpathapiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
			var v StackpathapiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	err = r.apiService.client.decode(&localVarReturnValue, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
	if err != nil {
		newErr := GenericOpenAPIError{
			body:  localVarBody,
			error: err.Error(),
		}
		return localVarReturnValue, localVarHTTPResponse, newErr
	}

	return localVarReturnValue, localVarHTTPResponse, nil
}
