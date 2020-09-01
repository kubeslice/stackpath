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

// WafCreateCertificateRequest struct for WafCreateCertificateRequest
type WafCreateCertificateRequest struct {
	// A PEM PKCS #7 formatted SSL certificate
	Certificate *string `json:"certificate,omitempty"`
	// A PEM PKCS #7 formatted private key  Private keys are sent directly to the edge nodes and are not stored elsewhere on StackPath's systems.
	Key *string `json:"key,omitempty"`
	// A PEM PKCS #7 formatted certificate authority bundle
	CaBundle *string `json:"caBundle,omitempty"`
}

// NewWafCreateCertificateRequest instantiates a new WafCreateCertificateRequest object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewWafCreateCertificateRequest() *WafCreateCertificateRequest {
	this := WafCreateCertificateRequest{}
	return &this
}

// NewWafCreateCertificateRequestWithDefaults instantiates a new WafCreateCertificateRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewWafCreateCertificateRequestWithDefaults() *WafCreateCertificateRequest {
	this := WafCreateCertificateRequest{}
	return &this
}

// GetCertificate returns the Certificate field value if set, zero value otherwise.
func (o *WafCreateCertificateRequest) GetCertificate() string {
	if o == nil || o.Certificate == nil {
		var ret string
		return ret
	}
	return *o.Certificate
}

// GetCertificateOk returns a tuple with the Certificate field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WafCreateCertificateRequest) GetCertificateOk() (*string, bool) {
	if o == nil || o.Certificate == nil {
		return nil, false
	}
	return o.Certificate, true
}

// HasCertificate returns a boolean if a field has been set.
func (o *WafCreateCertificateRequest) HasCertificate() bool {
	if o != nil && o.Certificate != nil {
		return true
	}

	return false
}

// SetCertificate gets a reference to the given string and assigns it to the Certificate field.
func (o *WafCreateCertificateRequest) SetCertificate(v string) {
	o.Certificate = &v
}

// GetKey returns the Key field value if set, zero value otherwise.
func (o *WafCreateCertificateRequest) GetKey() string {
	if o == nil || o.Key == nil {
		var ret string
		return ret
	}
	return *o.Key
}

// GetKeyOk returns a tuple with the Key field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WafCreateCertificateRequest) GetKeyOk() (*string, bool) {
	if o == nil || o.Key == nil {
		return nil, false
	}
	return o.Key, true
}

// HasKey returns a boolean if a field has been set.
func (o *WafCreateCertificateRequest) HasKey() bool {
	if o != nil && o.Key != nil {
		return true
	}

	return false
}

// SetKey gets a reference to the given string and assigns it to the Key field.
func (o *WafCreateCertificateRequest) SetKey(v string) {
	o.Key = &v
}

// GetCaBundle returns the CaBundle field value if set, zero value otherwise.
func (o *WafCreateCertificateRequest) GetCaBundle() string {
	if o == nil || o.CaBundle == nil {
		var ret string
		return ret
	}
	return *o.CaBundle
}

// GetCaBundleOk returns a tuple with the CaBundle field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WafCreateCertificateRequest) GetCaBundleOk() (*string, bool) {
	if o == nil || o.CaBundle == nil {
		return nil, false
	}
	return o.CaBundle, true
}

// HasCaBundle returns a boolean if a field has been set.
func (o *WafCreateCertificateRequest) HasCaBundle() bool {
	if o != nil && o.CaBundle != nil {
		return true
	}

	return false
}

// SetCaBundle gets a reference to the given string and assigns it to the CaBundle field.
func (o *WafCreateCertificateRequest) SetCaBundle(v string) {
	o.CaBundle = &v
}

func (o WafCreateCertificateRequest) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Certificate != nil {
		toSerialize["certificate"] = o.Certificate
	}
	if o.Key != nil {
		toSerialize["key"] = o.Key
	}
	if o.CaBundle != nil {
		toSerialize["caBundle"] = o.CaBundle
	}
	return json.Marshal(toSerialize)
}

type NullableWafCreateCertificateRequest struct {
	value *WafCreateCertificateRequest
	isSet bool
}

func (v NullableWafCreateCertificateRequest) Get() *WafCreateCertificateRequest {
	return v.value
}

func (v *NullableWafCreateCertificateRequest) Set(val *WafCreateCertificateRequest) {
	v.value = val
	v.isSet = true
}

func (v NullableWafCreateCertificateRequest) IsSet() bool {
	return v.isSet
}

func (v *NullableWafCreateCertificateRequest) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableWafCreateCertificateRequest(val *WafCreateCertificateRequest) *NullableWafCreateCertificateRequest {
	return &NullableWafCreateCertificateRequest{value: val, isSet: true}
}

func (v NullableWafCreateCertificateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableWafCreateCertificateRequest) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
