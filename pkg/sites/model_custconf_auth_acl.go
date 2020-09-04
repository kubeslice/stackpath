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
	"encoding/json"
)

// CustconfAuthACL IP address restrictions allow you to configure your CDN container to grant or deny a specific IP addresses or range of IP addresses from accessing content cached in a directory in your CDN container.
type CustconfAuthACL struct {
	// This is used by the API to perform conflict checking
	Id *string `json:"id,omitempty"`
	AccessCode *AuthACLAccessCodeEnumWrapperValue `json:"accessCode,omitempty"`
	// String of values delimited by a ',' character. This is a list of IP addresses considered for this policy.
	IpList *string `json:"ipList,omitempty"`
	Protocol *CustconfAuthACLProtocolEnumWrapperValue `json:"protocol,omitempty"`
	ClientIPSrc *AuthACLClientIPSrcEnumWrapperValue `json:"clientIPSrc,omitempty"`
	// This allows you to specify the name of a HTTP request header which will contain the client IP address to use for this policy.
	Header *string `json:"header,omitempty"`
	Enabled *bool `json:"enabled,omitempty"`
}

// NewCustconfAuthACL instantiates a new CustconfAuthACL object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCustconfAuthACL() *CustconfAuthACL {
	this := CustconfAuthACL{}
	var accessCode AuthACLAccessCodeEnumWrapperValue = "UNKNOWN"
	this.AccessCode = &accessCode
	var protocol CustconfAuthACLProtocolEnumWrapperValue = "UNKNOWN"
	this.Protocol = &protocol
	var clientIPSrc AuthACLClientIPSrcEnumWrapperValue = "UNKNOWN"
	this.ClientIPSrc = &clientIPSrc
	return &this
}

// NewCustconfAuthACLWithDefaults instantiates a new CustconfAuthACL object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCustconfAuthACLWithDefaults() *CustconfAuthACL {
	this := CustconfAuthACL{}
	var accessCode AuthACLAccessCodeEnumWrapperValue = "UNKNOWN"
	this.AccessCode = &accessCode
	var protocol CustconfAuthACLProtocolEnumWrapperValue = "UNKNOWN"
	this.Protocol = &protocol
	var clientIPSrc AuthACLClientIPSrcEnumWrapperValue = "UNKNOWN"
	this.ClientIPSrc = &clientIPSrc
	return &this
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *CustconfAuthACL) GetId() string {
	if o == nil || o.Id == nil {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthACL) GetIdOk() (*string, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *CustconfAuthACL) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *CustconfAuthACL) SetId(v string) {
	o.Id = &v
}

// GetAccessCode returns the AccessCode field value if set, zero value otherwise.
func (o *CustconfAuthACL) GetAccessCode() AuthACLAccessCodeEnumWrapperValue {
	if o == nil || o.AccessCode == nil {
		var ret AuthACLAccessCodeEnumWrapperValue
		return ret
	}
	return *o.AccessCode
}

// GetAccessCodeOk returns a tuple with the AccessCode field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthACL) GetAccessCodeOk() (*AuthACLAccessCodeEnumWrapperValue, bool) {
	if o == nil || o.AccessCode == nil {
		return nil, false
	}
	return o.AccessCode, true
}

// HasAccessCode returns a boolean if a field has been set.
func (o *CustconfAuthACL) HasAccessCode() bool {
	if o != nil && o.AccessCode != nil {
		return true
	}

	return false
}

// SetAccessCode gets a reference to the given AuthACLAccessCodeEnumWrapperValue and assigns it to the AccessCode field.
func (o *CustconfAuthACL) SetAccessCode(v AuthACLAccessCodeEnumWrapperValue) {
	o.AccessCode = &v
}

// GetIpList returns the IpList field value if set, zero value otherwise.
func (o *CustconfAuthACL) GetIpList() string {
	if o == nil || o.IpList == nil {
		var ret string
		return ret
	}
	return *o.IpList
}

// GetIpListOk returns a tuple with the IpList field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthACL) GetIpListOk() (*string, bool) {
	if o == nil || o.IpList == nil {
		return nil, false
	}
	return o.IpList, true
}

// HasIpList returns a boolean if a field has been set.
func (o *CustconfAuthACL) HasIpList() bool {
	if o != nil && o.IpList != nil {
		return true
	}

	return false
}

// SetIpList gets a reference to the given string and assigns it to the IpList field.
func (o *CustconfAuthACL) SetIpList(v string) {
	o.IpList = &v
}

// GetProtocol returns the Protocol field value if set, zero value otherwise.
func (o *CustconfAuthACL) GetProtocol() CustconfAuthACLProtocolEnumWrapperValue {
	if o == nil || o.Protocol == nil {
		var ret CustconfAuthACLProtocolEnumWrapperValue
		return ret
	}
	return *o.Protocol
}

// GetProtocolOk returns a tuple with the Protocol field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthACL) GetProtocolOk() (*CustconfAuthACLProtocolEnumWrapperValue, bool) {
	if o == nil || o.Protocol == nil {
		return nil, false
	}
	return o.Protocol, true
}

// HasProtocol returns a boolean if a field has been set.
func (o *CustconfAuthACL) HasProtocol() bool {
	if o != nil && o.Protocol != nil {
		return true
	}

	return false
}

// SetProtocol gets a reference to the given CustconfAuthACLProtocolEnumWrapperValue and assigns it to the Protocol field.
func (o *CustconfAuthACL) SetProtocol(v CustconfAuthACLProtocolEnumWrapperValue) {
	o.Protocol = &v
}

// GetClientIPSrc returns the ClientIPSrc field value if set, zero value otherwise.
func (o *CustconfAuthACL) GetClientIPSrc() AuthACLClientIPSrcEnumWrapperValue {
	if o == nil || o.ClientIPSrc == nil {
		var ret AuthACLClientIPSrcEnumWrapperValue
		return ret
	}
	return *o.ClientIPSrc
}

// GetClientIPSrcOk returns a tuple with the ClientIPSrc field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthACL) GetClientIPSrcOk() (*AuthACLClientIPSrcEnumWrapperValue, bool) {
	if o == nil || o.ClientIPSrc == nil {
		return nil, false
	}
	return o.ClientIPSrc, true
}

// HasClientIPSrc returns a boolean if a field has been set.
func (o *CustconfAuthACL) HasClientIPSrc() bool {
	if o != nil && o.ClientIPSrc != nil {
		return true
	}

	return false
}

// SetClientIPSrc gets a reference to the given AuthACLClientIPSrcEnumWrapperValue and assigns it to the ClientIPSrc field.
func (o *CustconfAuthACL) SetClientIPSrc(v AuthACLClientIPSrcEnumWrapperValue) {
	o.ClientIPSrc = &v
}

// GetHeader returns the Header field value if set, zero value otherwise.
func (o *CustconfAuthACL) GetHeader() string {
	if o == nil || o.Header == nil {
		var ret string
		return ret
	}
	return *o.Header
}

// GetHeaderOk returns a tuple with the Header field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthACL) GetHeaderOk() (*string, bool) {
	if o == nil || o.Header == nil {
		return nil, false
	}
	return o.Header, true
}

// HasHeader returns a boolean if a field has been set.
func (o *CustconfAuthACL) HasHeader() bool {
	if o != nil && o.Header != nil {
		return true
	}

	return false
}

// SetHeader gets a reference to the given string and assigns it to the Header field.
func (o *CustconfAuthACL) SetHeader(v string) {
	o.Header = &v
}

// GetEnabled returns the Enabled field value if set, zero value otherwise.
func (o *CustconfAuthACL) GetEnabled() bool {
	if o == nil || o.Enabled == nil {
		var ret bool
		return ret
	}
	return *o.Enabled
}

// GetEnabledOk returns a tuple with the Enabled field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthACL) GetEnabledOk() (*bool, bool) {
	if o == nil || o.Enabled == nil {
		return nil, false
	}
	return o.Enabled, true
}

// HasEnabled returns a boolean if a field has been set.
func (o *CustconfAuthACL) HasEnabled() bool {
	if o != nil && o.Enabled != nil {
		return true
	}

	return false
}

// SetEnabled gets a reference to the given bool and assigns it to the Enabled field.
func (o *CustconfAuthACL) SetEnabled(v bool) {
	o.Enabled = &v
}

func (o CustconfAuthACL) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Id != nil {
		toSerialize["id"] = o.Id
	}
	if o.AccessCode != nil {
		toSerialize["accessCode"] = o.AccessCode
	}
	if o.IpList != nil {
		toSerialize["ipList"] = o.IpList
	}
	if o.Protocol != nil {
		toSerialize["protocol"] = o.Protocol
	}
	if o.ClientIPSrc != nil {
		toSerialize["clientIPSrc"] = o.ClientIPSrc
	}
	if o.Header != nil {
		toSerialize["header"] = o.Header
	}
	if o.Enabled != nil {
		toSerialize["enabled"] = o.Enabled
	}
	return json.Marshal(toSerialize)
}

type NullableCustconfAuthACL struct {
	value *CustconfAuthACL
	isSet bool
}

func (v NullableCustconfAuthACL) Get() *CustconfAuthACL {
	return v.value
}

func (v *NullableCustconfAuthACL) Set(val *CustconfAuthACL) {
	v.value = val
	v.isSet = true
}

func (v NullableCustconfAuthACL) IsSet() bool {
	return v.isSet
}

func (v *NullableCustconfAuthACL) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCustconfAuthACL(val *CustconfAuthACL) *NullableCustconfAuthACL {
	return &NullableCustconfAuthACL{value: val, isSet: true}
}

func (v NullableCustconfAuthACL) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCustconfAuthACL) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
