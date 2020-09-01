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
	"encoding/json"
)

// WafEventRequest struct for WafEventRequest
type WafEventRequest struct {
	// The requested domain name
	Domain *string `json:"domain,omitempty"`
	// The HTTP method that triggered a WAF event
	Method *string `json:"method,omitempty"`
	// The URL scheme that triggered a WAF event
	Scheme *string `json:"scheme,omitempty"`
	// The full URL that triggered a WAF event
	Uri *string `json:"uri,omitempty"`
	// The query string portion of a URL that triggered a WAF event
	QueryString *string `json:"queryString,omitempty"`
	// A key/value pair of the event's request headers
	Headers *map[string]string `json:"headers,omitempty"`
	UserAgent *EventRequestUserAgent `json:"userAgent,omitempty"`
}

// NewWafEventRequest instantiates a new WafEventRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewWafEventRequest() *WafEventRequest {
	this := WafEventRequest{}
	return &this
}

// NewWafEventRequestWithDefaults instantiates a new WafEventRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewWafEventRequestWithDefaults() *WafEventRequest {
	this := WafEventRequest{}
	return &this
}

// GetDomain returns the Domain field value if set, zero value otherwise.
func (o *WafEventRequest) GetDomain() string {
	if o == nil || o.Domain == nil {
		var ret string
		return ret
	}
	return *o.Domain
}

// GetDomainOk returns a tuple with the Domain field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WafEventRequest) GetDomainOk() (*string, bool) {
	if o == nil || o.Domain == nil {
		return nil, false
	}
	return o.Domain, true
}

// HasDomain returns a boolean if a field has been set.
func (o *WafEventRequest) HasDomain() bool {
	if o != nil && o.Domain != nil {
		return true
	}

	return false
}

// SetDomain gets a reference to the given string and assigns it to the Domain field.
func (o *WafEventRequest) SetDomain(v string) {
	o.Domain = &v
}

// GetMethod returns the Method field value if set, zero value otherwise.
func (o *WafEventRequest) GetMethod() string {
	if o == nil || o.Method == nil {
		var ret string
		return ret
	}
	return *o.Method
}

// GetMethodOk returns a tuple with the Method field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WafEventRequest) GetMethodOk() (*string, bool) {
	if o == nil || o.Method == nil {
		return nil, false
	}
	return o.Method, true
}

// HasMethod returns a boolean if a field has been set.
func (o *WafEventRequest) HasMethod() bool {
	if o != nil && o.Method != nil {
		return true
	}

	return false
}

// SetMethod gets a reference to the given string and assigns it to the Method field.
func (o *WafEventRequest) SetMethod(v string) {
	o.Method = &v
}

// GetScheme returns the Scheme field value if set, zero value otherwise.
func (o *WafEventRequest) GetScheme() string {
	if o == nil || o.Scheme == nil {
		var ret string
		return ret
	}
	return *o.Scheme
}

// GetSchemeOk returns a tuple with the Scheme field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WafEventRequest) GetSchemeOk() (*string, bool) {
	if o == nil || o.Scheme == nil {
		return nil, false
	}
	return o.Scheme, true
}

// HasScheme returns a boolean if a field has been set.
func (o *WafEventRequest) HasScheme() bool {
	if o != nil && o.Scheme != nil {
		return true
	}

	return false
}

// SetScheme gets a reference to the given string and assigns it to the Scheme field.
func (o *WafEventRequest) SetScheme(v string) {
	o.Scheme = &v
}

// GetUri returns the Uri field value if set, zero value otherwise.
func (o *WafEventRequest) GetUri() string {
	if o == nil || o.Uri == nil {
		var ret string
		return ret
	}
	return *o.Uri
}

// GetUriOk returns a tuple with the Uri field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WafEventRequest) GetUriOk() (*string, bool) {
	if o == nil || o.Uri == nil {
		return nil, false
	}
	return o.Uri, true
}

// HasUri returns a boolean if a field has been set.
func (o *WafEventRequest) HasUri() bool {
	if o != nil && o.Uri != nil {
		return true
	}

	return false
}

// SetUri gets a reference to the given string and assigns it to the Uri field.
func (o *WafEventRequest) SetUri(v string) {
	o.Uri = &v
}

// GetQueryString returns the QueryString field value if set, zero value otherwise.
func (o *WafEventRequest) GetQueryString() string {
	if o == nil || o.QueryString == nil {
		var ret string
		return ret
	}
	return *o.QueryString
}

// GetQueryStringOk returns a tuple with the QueryString field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WafEventRequest) GetQueryStringOk() (*string, bool) {
	if o == nil || o.QueryString == nil {
		return nil, false
	}
	return o.QueryString, true
}

// HasQueryString returns a boolean if a field has been set.
func (o *WafEventRequest) HasQueryString() bool {
	if o != nil && o.QueryString != nil {
		return true
	}

	return false
}

// SetQueryString gets a reference to the given string and assigns it to the QueryString field.
func (o *WafEventRequest) SetQueryString(v string) {
	o.QueryString = &v
}

// GetHeaders returns the Headers field value if set, zero value otherwise.
func (o *WafEventRequest) GetHeaders() map[string]string {
	if o == nil || o.Headers == nil {
		var ret map[string]string
		return ret
	}
	return *o.Headers
}

// GetHeadersOk returns a tuple with the Headers field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WafEventRequest) GetHeadersOk() (*map[string]string, bool) {
	if o == nil || o.Headers == nil {
		return nil, false
	}
	return o.Headers, true
}

// HasHeaders returns a boolean if a field has been set.
func (o *WafEventRequest) HasHeaders() bool {
	if o != nil && o.Headers != nil {
		return true
	}

	return false
}

// SetHeaders gets a reference to the given map[string]string and assigns it to the Headers field.
func (o *WafEventRequest) SetHeaders(v map[string]string) {
	o.Headers = &v
}

// GetUserAgent returns the UserAgent field value if set, zero value otherwise.
func (o *WafEventRequest) GetUserAgent() EventRequestUserAgent {
	if o == nil || o.UserAgent == nil {
		var ret EventRequestUserAgent
		return ret
	}
	return *o.UserAgent
}

// GetUserAgentOk returns a tuple with the UserAgent field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WafEventRequest) GetUserAgentOk() (*EventRequestUserAgent, bool) {
	if o == nil || o.UserAgent == nil {
		return nil, false
	}
	return o.UserAgent, true
}

// HasUserAgent returns a boolean if a field has been set.
func (o *WafEventRequest) HasUserAgent() bool {
	if o != nil && o.UserAgent != nil {
		return true
	}

	return false
}

// SetUserAgent gets a reference to the given EventRequestUserAgent and assigns it to the UserAgent field.
func (o *WafEventRequest) SetUserAgent(v EventRequestUserAgent) {
	o.UserAgent = &v
}

func (o WafEventRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Domain != nil {
		toSerialize["domain"] = o.Domain
	}
	if o.Method != nil {
		toSerialize["method"] = o.Method
	}
	if o.Scheme != nil {
		toSerialize["scheme"] = o.Scheme
	}
	if o.Uri != nil {
		toSerialize["uri"] = o.Uri
	}
	if o.QueryString != nil {
		toSerialize["queryString"] = o.QueryString
	}
	if o.Headers != nil {
		toSerialize["headers"] = o.Headers
	}
	if o.UserAgent != nil {
		toSerialize["userAgent"] = o.UserAgent
	}
	return json.Marshal(toSerialize)
}

type NullableWafEventRequest struct {
	value *WafEventRequest
	isSet bool
}

func (v NullableWafEventRequest) Get() *WafEventRequest {
	return v.value
}

func (v *NullableWafEventRequest) Set(val *WafEventRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableWafEventRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableWafEventRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableWafEventRequest(val *WafEventRequest) *NullableWafEventRequest {
	return &NullableWafEventRequest{value: val, isSet: true}
}

func (v NullableWafEventRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableWafEventRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
