/*
 * Sites
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package sites

import (
	_context "context"
	_ioutil "io/ioutil"
	_nethttp "net/http"
	_neturl "net/url"
	"strings"
	"time"
	"reflect"
)

// Linger please
var (
	_ _context.Context
)

// MetricsApiService MetricsApi service
type MetricsApiService service

type apiGetMetricsRequest struct {
	ctx _context.Context
	apiService *MetricsApiService
	stackId string
	startDate *time.Time
	endDate *time.Time
	granularity *string
	statusCategories *[]string
	statusCodes *[]string
	sites *[]string
	groupBy *string
	billingRegions *[]string
	pops *[]string
	platforms *[]string
	siteTypeFilter *[]string
	metricType *string
}


func (r apiGetMetricsRequest) StartDate(startDate time.Time) apiGetMetricsRequest {
	r.startDate = &startDate
	return r
}

func (r apiGetMetricsRequest) EndDate(endDate time.Time) apiGetMetricsRequest {
	r.endDate = &endDate
	return r
}

func (r apiGetMetricsRequest) Granularity(granularity string) apiGetMetricsRequest {
	r.granularity = &granularity
	return r
}

func (r apiGetMetricsRequest) StatusCategories(statusCategories []string) apiGetMetricsRequest {
	r.statusCategories = &statusCategories
	return r
}

func (r apiGetMetricsRequest) StatusCodes(statusCodes []string) apiGetMetricsRequest {
	r.statusCodes = &statusCodes
	return r
}

func (r apiGetMetricsRequest) Sites(sites []string) apiGetMetricsRequest {
	r.sites = &sites
	return r
}

func (r apiGetMetricsRequest) GroupBy(groupBy string) apiGetMetricsRequest {
	r.groupBy = &groupBy
	return r
}

func (r apiGetMetricsRequest) BillingRegions(billingRegions []string) apiGetMetricsRequest {
	r.billingRegions = &billingRegions
	return r
}

func (r apiGetMetricsRequest) Pops(pops []string) apiGetMetricsRequest {
	r.pops = &pops
	return r
}

func (r apiGetMetricsRequest) Platforms(platforms []string) apiGetMetricsRequest {
	r.platforms = &platforms
	return r
}

func (r apiGetMetricsRequest) SiteTypeFilter(siteTypeFilter []string) apiGetMetricsRequest {
	r.siteTypeFilter = &siteTypeFilter
	return r
}

func (r apiGetMetricsRequest) MetricType(metricType string) apiGetMetricsRequest {
	r.metricType = &metricType
	return r
}

/*
GetMetrics Get metrics
The last 24 hours of metrics are retrieved if the start and end dates are not provided
 * @param ctx _context.Context - for authentication, logging, cancellation, deadlines, tracing, etc. Passed from http.Request or context.Background().
 * @param stackId A stack ID or slug
@return apiGetMetricsRequest
*/
func (a *MetricsApiService) GetMetrics(ctx _context.Context, stackId string) apiGetMetricsRequest {
	return apiGetMetricsRequest{
		apiService: a,
		ctx: ctx,
		stackId: stackId,
	}
}

/*
Execute executes the request
 @return PrometheusMetrics
*/
func (r apiGetMetricsRequest) Execute() (PrometheusMetrics, *_nethttp.Response, error) {
	var (
		localVarHTTPMethod   = _nethttp.MethodGet
		localVarPostBody     interface{}
		localVarFormFileName string
		localVarFileName     string
		localVarFileBytes    []byte
		localVarReturnValue  PrometheusMetrics
	)

	localBasePath, err := r.apiService.client.cfg.ServerURLWithContext(r.ctx, "MetricsApiService.GetMetrics")
	if err != nil {
		return localVarReturnValue, nil, GenericOpenAPIError{error: err.Error()}
	}

	localVarPath := localBasePath + "/delivery/v1/stacks/{stack_id}/metrics"
	localVarPath = strings.Replace(localVarPath, "{"+"stack_id"+"}", _neturl.QueryEscape(parameterToString(r.stackId, "")) , -1)

	localVarHeaderParams := make(map[string]string)
	localVarQueryParams := _neturl.Values{}
	localVarFormParams := _neturl.Values{}
	
												
	if r.startDate != nil {
		localVarQueryParams.Add("start_date", parameterToString(*r.startDate, ""))
	}
	if r.endDate != nil {
		localVarQueryParams.Add("end_date", parameterToString(*r.endDate, ""))
	}
	if r.granularity != nil {
		localVarQueryParams.Add("granularity", parameterToString(*r.granularity, ""))
	}
	if r.statusCategories != nil {
		t := *r.statusCategories
		if reflect.TypeOf(t).Kind() == reflect.Slice {
			s := reflect.ValueOf(t)
			for i := 0; i < s.Len(); i++ {
				localVarQueryParams.Add("status_categories", parameterToString(s.Index(i), "multi"))
			}
		} else {
			localVarQueryParams.Add("status_categories", parameterToString(t, "multi"))
		}
	}
	if r.statusCodes != nil {
		t := *r.statusCodes
		if reflect.TypeOf(t).Kind() == reflect.Slice {
			s := reflect.ValueOf(t)
			for i := 0; i < s.Len(); i++ {
				localVarQueryParams.Add("status_codes", parameterToString(s.Index(i), "multi"))
			}
		} else {
			localVarQueryParams.Add("status_codes", parameterToString(t, "multi"))
		}
	}
	if r.sites != nil {
		t := *r.sites
		if reflect.TypeOf(t).Kind() == reflect.Slice {
			s := reflect.ValueOf(t)
			for i := 0; i < s.Len(); i++ {
				localVarQueryParams.Add("sites", parameterToString(s.Index(i), "multi"))
			}
		} else {
			localVarQueryParams.Add("sites", parameterToString(t, "multi"))
		}
	}
	if r.groupBy != nil {
		localVarQueryParams.Add("group_by", parameterToString(*r.groupBy, ""))
	}
	if r.billingRegions != nil {
		t := *r.billingRegions
		if reflect.TypeOf(t).Kind() == reflect.Slice {
			s := reflect.ValueOf(t)
			for i := 0; i < s.Len(); i++ {
				localVarQueryParams.Add("billing_regions", parameterToString(s.Index(i), "multi"))
			}
		} else {
			localVarQueryParams.Add("billing_regions", parameterToString(t, "multi"))
		}
	}
	if r.pops != nil {
		t := *r.pops
		if reflect.TypeOf(t).Kind() == reflect.Slice {
			s := reflect.ValueOf(t)
			for i := 0; i < s.Len(); i++ {
				localVarQueryParams.Add("pops", parameterToString(s.Index(i), "multi"))
			}
		} else {
			localVarQueryParams.Add("pops", parameterToString(t, "multi"))
		}
	}
	if r.platforms != nil {
		t := *r.platforms
		if reflect.TypeOf(t).Kind() == reflect.Slice {
			s := reflect.ValueOf(t)
			for i := 0; i < s.Len(); i++ {
				localVarQueryParams.Add("platforms", parameterToString(s.Index(i), "multi"))
			}
		} else {
			localVarQueryParams.Add("platforms", parameterToString(t, "multi"))
		}
	}
	if r.siteTypeFilter != nil {
		t := *r.siteTypeFilter
		if reflect.TypeOf(t).Kind() == reflect.Slice {
			s := reflect.ValueOf(t)
			for i := 0; i < s.Len(); i++ {
				localVarQueryParams.Add("site_type_filter", parameterToString(s.Index(i), "multi"))
			}
		} else {
			localVarQueryParams.Add("site_type_filter", parameterToString(t, "multi"))
		}
	}
	if r.metricType != nil {
		localVarQueryParams.Add("metric_type", parameterToString(*r.metricType, ""))
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
