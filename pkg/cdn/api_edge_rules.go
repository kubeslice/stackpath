/*
 * Content Delivery Network
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package cdn

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

// EdgeRulesApiService EdgeRulesApi service
type EdgeRulesApiService service

type apiCreateScopeRuleRequest struct {
	ctx _context.Context
	apiService *EdgeRulesApiService
	stackId string
	siteId string
	scopeId string
	cdnCreateScopeRuleRequest *CdnCreateScopeRuleRequest
}


func (r apiCreateScopeRuleRequest) CdnCreateScopeRuleRequest(cdnCreateScopeRuleRequest CdnCreateScopeRuleRequest) apiCreateScopeRuleRequest {
	r.cdnCreateScopeRuleRequest = &cdnCreateScopeRuleRequest
	return r
}

/*
CreateScopeRule Create an EdgeRule
 * @param ctx _context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 * @param stackId A stack ID or slug
 * @param siteId A site ID
 * @param scopeId A scope ID
@return apiCreateScopeRuleRequest
*/
func (a *EdgeRulesApiService) CreateScopeRule(ctx _context.Context, stackId string, siteId string, scopeId string) apiCreateScopeRuleRequest {
	return apiCreateScopeRuleRequest{
		apiService: a,
		ctx: ctx,
		stackId: stackId,
		siteId: siteId,
		scopeId: scopeId,
	}
}

/*
Execute executes the request
 @return CdnCreateScopeRuleResponse
*/
func (r apiCreateScopeRuleRequest) Execute() (CdnCreateScopeRuleResponse, *_nethttp.Response, error) {
	var (
		localVarHTTPMethod   = _nethttp.MethodPost
		localVarPostBody     interface{}
		localVarFormFileName string
		localVarFileName     string
		localVarFileBytes    []byte
		localVarReturnValue  CdnCreateScopeRuleResponse
	)

	localBasePath, err := r.apiService.client.cfg.ServerURLWithContext(r.ctx, "EdgeRulesApiService.CreateScopeRule")
	if err != nil {
		return localVarReturnValue, nil, GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/cdn/v1/stacks/{stack_id}/sites/{site_id}/scopes/{scope_id}/rules"
	localVarPath = strings.Replace(localVarPath, "{"+"stack_id"+"}", _neturl.QueryEscape(parameterToString(r.stackId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"site_id"+"}", _neturl.QueryEscape(parameterToString(r.siteId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"scope_id"+"}", _neturl.QueryEscape(parameterToString(r.scopeId, "")) , -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := _neturl.Values{}
	localVarFormParams := _neturl.Values{}
	
	
	
	
	if r.cdnCreateScopeRuleRequest == nil {
		return localVarReturnValue, nil, reportError("cdnCreateScopeRuleRequest is required and must be specified")
	}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{"application/json"}

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
	// body params
	localVarPostBody = r.cdnCreateScopeRuleRequest
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
			var v ApiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 500 {
			var v ApiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
			var v ApiStatus
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
type apiDeleteScopeRuleRequest struct {
	ctx _context.Context
	apiService *EdgeRulesApiService
	stackId string
	siteId string
	scopeId string
	ruleId string
}


/*
DeleteScopeRule Delete an EdgeRule
 * @param ctx _context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 * @param stackId A stack ID or slug
 * @param siteId A site ID
 * @param scopeId A scope ID
 * @param ruleId An EdgeRule ID
@return apiDeleteScopeRuleRequest
*/
func (a *EdgeRulesApiService) DeleteScopeRule(ctx _context.Context, stackId string, siteId string, scopeId string, ruleId string) apiDeleteScopeRuleRequest {
	return apiDeleteScopeRuleRequest{
		apiService: a,
		ctx: ctx,
		stackId: stackId,
		siteId: siteId,
		scopeId: scopeId,
		ruleId: ruleId,
	}
}

/*
Execute executes the request

*/
func (r apiDeleteScopeRuleRequest) Execute() (*_nethttp.Response, error) {
	var (
		localVarHTTPMethod   = _nethttp.MethodDelete
		localVarPostBody     interface{}
		localVarFormFileName string
		localVarFileName     string
		localVarFileBytes    []byte
		
	)

	localBasePath, err := r.apiService.client.cfg.ServerURLWithContext(r.ctx, "EdgeRulesApiService.DeleteScopeRule")
	if err != nil {
		return nil, GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/cdn/v1/stacks/{stack_id}/sites/{site_id}/scopes/{scope_id}/rules/{rule_id}"
	localVarPath = strings.Replace(localVarPath, "{"+"stack_id"+"}", _neturl.QueryEscape(parameterToString(r.stackId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"site_id"+"}", _neturl.QueryEscape(parameterToString(r.siteId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"scope_id"+"}", _neturl.QueryEscape(parameterToString(r.scopeId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"rule_id"+"}", _neturl.QueryEscape(parameterToString(r.ruleId, "")) , -1)

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
		return nil, err
	}

	localVarHTTPResponse, err := r.apiService.client.callAPI(req)
	if err != nil || localVarHTTPResponse == nil {
		return localVarHTTPResponse, err
	}

	localVarBody, err := _ioutil.ReadAll(localVarHTTPResponse.Body)
	localVarHTTPResponse.Body.Close()
	if err != nil {
		return localVarHTTPResponse, err
	}

	if localVarHTTPResponse.StatusCode >= 300 {
		newErr := GenericOpenAPIError{
			body:  localVarBody,
			error: localVarHTTPResponse.Status,
		}
		if localVarHTTPResponse.StatusCode == 401 {
			var v ApiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 500 {
			var v ApiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarHTTPResponse, newErr
		}
			var v ApiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarHTTPResponse, newErr
			}
			newErr.model = v
		return localVarHTTPResponse, newErr
	}

	return localVarHTTPResponse, nil
}
type apiGetScopeRuleRequest struct {
	ctx _context.Context
	apiService *EdgeRulesApiService
	stackId string
	siteId string
	scopeId string
	ruleId string
}


/*
GetScopeRule Get an EdgeRule
 * @param ctx _context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 * @param stackId A stack ID or slug
 * @param siteId A site ID
 * @param scopeId A scope ID
 * @param ruleId An EdgeRule ID
@return apiGetScopeRuleRequest
*/
func (a *EdgeRulesApiService) GetScopeRule(ctx _context.Context, stackId string, siteId string, scopeId string, ruleId string) apiGetScopeRuleRequest {
	return apiGetScopeRuleRequest{
		apiService: a,
		ctx: ctx,
		stackId: stackId,
		siteId: siteId,
		scopeId: scopeId,
		ruleId: ruleId,
	}
}

/*
Execute executes the request
 @return CdnGetScopeRuleResponse
*/
func (r apiGetScopeRuleRequest) Execute() (CdnGetScopeRuleResponse, *_nethttp.Response, error) {
	var (
		localVarHTTPMethod   = _nethttp.MethodGet
		localVarPostBody     interface{}
		localVarFormFileName string
		localVarFileName     string
		localVarFileBytes    []byte
		localVarReturnValue  CdnGetScopeRuleResponse
	)

	localBasePath, err := r.apiService.client.cfg.ServerURLWithContext(r.ctx, "EdgeRulesApiService.GetScopeRule")
	if err != nil {
		return localVarReturnValue, nil, GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/cdn/v1/stacks/{stack_id}/sites/{site_id}/scopes/{scope_id}/rules/{rule_id}"
	localVarPath = strings.Replace(localVarPath, "{"+"stack_id"+"}", _neturl.QueryEscape(parameterToString(r.stackId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"site_id"+"}", _neturl.QueryEscape(parameterToString(r.siteId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"scope_id"+"}", _neturl.QueryEscape(parameterToString(r.scopeId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"rule_id"+"}", _neturl.QueryEscape(parameterToString(r.ruleId, "")) , -1)

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
			var v ApiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 500 {
			var v ApiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
			var v ApiStatus
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
type apiGetScopeRuleConfigurationRequest struct {
	ctx _context.Context
	apiService *EdgeRulesApiService
	stackId string
	siteId string
	scopeId string
	ruleId string
}


/*
GetScopeRuleConfiguration Get an EdgeRule's configuration
 * @param ctx _context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 * @param stackId A stack ID or slug
 * @param siteId A site ID
 * @param scopeId A scope ID
 * @param ruleId An EdgeRule ID
@return apiGetScopeRuleConfigurationRequest
*/
func (a *EdgeRulesApiService) GetScopeRuleConfiguration(ctx _context.Context, stackId string, siteId string, scopeId string, ruleId string) apiGetScopeRuleConfigurationRequest {
	return apiGetScopeRuleConfigurationRequest{
		apiService: a,
		ctx: ctx,
		stackId: stackId,
		siteId: siteId,
		scopeId: scopeId,
		ruleId: ruleId,
	}
}

/*
Execute executes the request
 @return CdnGetScopeRuleConfigurationResponse
*/
func (r apiGetScopeRuleConfigurationRequest) Execute() (CdnGetScopeRuleConfigurationResponse, *_nethttp.Response, error) {
	var (
		localVarHTTPMethod   = _nethttp.MethodGet
		localVarPostBody     interface{}
		localVarFormFileName string
		localVarFileName     string
		localVarFileBytes    []byte
		localVarReturnValue  CdnGetScopeRuleConfigurationResponse
	)

	localBasePath, err := r.apiService.client.cfg.ServerURLWithContext(r.ctx, "EdgeRulesApiService.GetScopeRuleConfiguration")
	if err != nil {
		return localVarReturnValue, nil, GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/cdn/v1/stacks/{stack_id}/sites/{site_id}/scopes/{scope_id}/rules/{rule_id}/configuration"
	localVarPath = strings.Replace(localVarPath, "{"+"stack_id"+"}", _neturl.QueryEscape(parameterToString(r.stackId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"site_id"+"}", _neturl.QueryEscape(parameterToString(r.siteId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"scope_id"+"}", _neturl.QueryEscape(parameterToString(r.scopeId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"rule_id"+"}", _neturl.QueryEscape(parameterToString(r.ruleId, "")) , -1)

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
			var v ApiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 500 {
			var v ApiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
			var v ApiStatus
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
type apiGetScopeRulesRequest struct {
	ctx _context.Context
	apiService *EdgeRulesApiService
	stackId string
	siteId string
	scopeId string
	pageRequestFirst *string
	pageRequestAfter *string
	pageRequestFilter *string
	pageRequestSortBy *string
}


func (r apiGetScopeRulesRequest) PageRequestFirst(pageRequestFirst string) apiGetScopeRulesRequest {
	r.pageRequestFirst = &pageRequestFirst
	return r
}

func (r apiGetScopeRulesRequest) PageRequestAfter(pageRequestAfter string) apiGetScopeRulesRequest {
	r.pageRequestAfter = &pageRequestAfter
	return r
}

func (r apiGetScopeRulesRequest) PageRequestFilter(pageRequestFilter string) apiGetScopeRulesRequest {
	r.pageRequestFilter = &pageRequestFilter
	return r
}

func (r apiGetScopeRulesRequest) PageRequestSortBy(pageRequestSortBy string) apiGetScopeRulesRequest {
	r.pageRequestSortBy = &pageRequestSortBy
	return r
}

/*
GetScopeRules Get all EdgeRules
 * @param ctx _context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 * @param stackId A stack ID or slug
 * @param siteId A site ID
 * @param scopeId A scope ID
@return apiGetScopeRulesRequest
*/
func (a *EdgeRulesApiService) GetScopeRules(ctx _context.Context, stackId string, siteId string, scopeId string) apiGetScopeRulesRequest {
	return apiGetScopeRulesRequest{
		apiService: a,
		ctx: ctx,
		stackId: stackId,
		siteId: siteId,
		scopeId: scopeId,
	}
}

/*
Execute executes the request
 @return CdnGetScopeRulesResponse
*/
func (r apiGetScopeRulesRequest) Execute() (CdnGetScopeRulesResponse, *_nethttp.Response, error) {
	var (
		localVarHTTPMethod   = _nethttp.MethodGet
		localVarPostBody     interface{}
		localVarFormFileName string
		localVarFileName     string
		localVarFileBytes    []byte
		localVarReturnValue  CdnGetScopeRulesResponse
	)

	localBasePath, err := r.apiService.client.cfg.ServerURLWithContext(r.ctx, "EdgeRulesApiService.GetScopeRules")
	if err != nil {
		return localVarReturnValue, nil, GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/cdn/v1/stacks/{stack_id}/sites/{site_id}/scopes/{scope_id}/rules"
	localVarPath = strings.Replace(localVarPath, "{"+"stack_id"+"}", _neturl.QueryEscape(parameterToString(r.stackId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"site_id"+"}", _neturl.QueryEscape(parameterToString(r.siteId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"scope_id"+"}", _neturl.QueryEscape(parameterToString(r.scopeId, "")) , -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := _neturl.Values{}
	localVarFormParams := _neturl.Values{}
	
	
	
				
	if r.pageRequestFirst != nil {
		localVarQueryParams.Add("page_request.first", parameterToString(*r.pageRequestFirst, ""))
	}
	if r.pageRequestAfter != nil {
		localVarQueryParams.Add("page_request.after", parameterToString(*r.pageRequestAfter, ""))
	}
	if r.pageRequestFilter != nil {
		localVarQueryParams.Add("page_request.filter", parameterToString(*r.pageRequestFilter, ""))
	}
	if r.pageRequestSortBy != nil {
		localVarQueryParams.Add("page_request.sort_by", parameterToString(*r.pageRequestSortBy, ""))
	}
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
			var v ApiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 500 {
			var v ApiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
			var v ApiStatus
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
type apiUpdateScopeRuleConfigurationRequest struct {
	ctx _context.Context
	apiService *EdgeRulesApiService
	stackId string
	siteId string
	scopeId string
	ruleId string
	cdnUpdateScopeRuleConfigurationRequest *CdnUpdateScopeRuleConfigurationRequest
}


func (r apiUpdateScopeRuleConfigurationRequest) CdnUpdateScopeRuleConfigurationRequest(cdnUpdateScopeRuleConfigurationRequest CdnUpdateScopeRuleConfigurationRequest) apiUpdateScopeRuleConfigurationRequest {
	r.cdnUpdateScopeRuleConfigurationRequest = &cdnUpdateScopeRuleConfigurationRequest
	return r
}

/*
UpdateScopeRuleConfiguration Update an EdgeRule's configuration
 * @param ctx _context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 * @param stackId A stack ID or slug
 * @param siteId A site ID
 * @param scopeId A scope ID
 * @param ruleId An EdgeRule ID
@return apiUpdateScopeRuleConfigurationRequest
*/
func (a *EdgeRulesApiService) UpdateScopeRuleConfiguration(ctx _context.Context, stackId string, siteId string, scopeId string, ruleId string) apiUpdateScopeRuleConfigurationRequest {
	return apiUpdateScopeRuleConfigurationRequest{
		apiService: a,
		ctx: ctx,
		stackId: stackId,
		siteId: siteId,
		scopeId: scopeId,
		ruleId: ruleId,
	}
}

/*
Execute executes the request
 @return CdnUpdateScopeRuleConfigurationResponse
*/
func (r apiUpdateScopeRuleConfigurationRequest) Execute() (CdnUpdateScopeRuleConfigurationResponse, *_nethttp.Response, error) {
	var (
		localVarHTTPMethod   = _nethttp.MethodPatch
		localVarPostBody     interface{}
		localVarFormFileName string
		localVarFileName     string
		localVarFileBytes    []byte
		localVarReturnValue  CdnUpdateScopeRuleConfigurationResponse
	)

	localBasePath, err := r.apiService.client.cfg.ServerURLWithContext(r.ctx, "EdgeRulesApiService.UpdateScopeRuleConfiguration")
	if err != nil {
		return localVarReturnValue, nil, GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/cdn/v1/stacks/{stack_id}/sites/{site_id}/scopes/{scope_id}/rules/{rule_id}/configuration"
	localVarPath = strings.Replace(localVarPath, "{"+"stack_id"+"}", _neturl.QueryEscape(parameterToString(r.stackId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"site_id"+"}", _neturl.QueryEscape(parameterToString(r.siteId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"scope_id"+"}", _neturl.QueryEscape(parameterToString(r.scopeId, "")) , -1)
	localVarPath = strings.Replace(localVarPath, "{"+"rule_id"+"}", _neturl.QueryEscape(parameterToString(r.ruleId, "")) , -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := _neturl.Values{}
	localVarFormParams := _neturl.Values{}
	
	
	
	
	
	if r.cdnUpdateScopeRuleConfigurationRequest == nil {
		return localVarReturnValue, nil, reportError("cdnUpdateScopeRuleConfigurationRequest is required and must be specified")
	}

	// to determine the Content-Type header
	localVarHTTPContentTypes := []string{"application/json"}

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
	// body params
	localVarPostBody = r.cdnUpdateScopeRuleConfigurationRequest
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
			var v ApiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
		if localVarHTTPResponse.StatusCode == 500 {
			var v ApiStatus
			err = r.apiService.client.decode(&v, localVarBody, localVarHTTPResponse.Header.Get("Content-Type"))
			if err != nil {
				newErr.error = err.Error()
				return localVarReturnValue, localVarHTTPResponse, newErr
			}
			newErr.model = v
			return localVarReturnValue, localVarHTTPResponse, newErr
		}
			var v ApiStatus
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
