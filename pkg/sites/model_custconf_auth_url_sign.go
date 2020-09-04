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

// CustconfAuthUrlSign URL Signing policies allow you to restrict access to your content by configuring a \"shared secret\" with StackPath. This \"shared secret\" is used to apply an MD5 hashing algorithm on the URL to validate the signature supplied on the request. Since the \"shared secret\" is only known by the publisher and StackPath, URL signatures cannot be generated by unauthorized users.
type CustconfAuthUrlSign struct {
	// This is used by the API to perform conflict checking
	Id *string `json:"id,omitempty"`
	// This is the name of the query string parameter that will be used by the publisher to specify the signature for the URL.
	TokenField *string `json:"tokenField,omitempty"`
	// Select this option if you want StackPath to exclude query string parameters specified after the passphrase in the validation process.
	IgnoreFieldsAfterToken *bool `json:"ignoreFieldsAfterToken,omitempty"`
	// This is the name of the query string parameter that contains the value of the secret. This query string parameter is only used during the generation and validation of a URL signature and should not be present in the published URL.
	PassPhraseField *string `json:"passPhraseField,omitempty"`
	// The shared secret used during the signing process. This value should only be known by StackPath and systems authorized to sign your content.
	PassPhrase *string `json:"passPhrase,omitempty"`
	// This is the name of the query string parameter that contains the Epoch time after which the URL is considered invalid.
	ExpiresField *string `json:"expiresField,omitempty"`
	// This is a query string parameter that contains an IPv4 address to which the published URL will be restricted.
	IpAddressField *string `json:"ipAddressField,omitempty"`
	// This is a query string parameter used to limit the number of characters in the path that should be considered when validating the URL signature. This feature allows you to reuse the same signature on all assets stored in the same cache path. Setting this value to 0 will strip off the filename in the URL (leaving the trailing slash) when calculating the checksum.
	UriLengthField *string `json:"uriLengthField,omitempty"`
	// This is a query string parameter used to restrict the published URL to a specific user agent. Publishers can use this feature during the signing process to ensure that only a specific user agent can access the published content. You do not need to specify the user agent on the published URL. StackPath will use the HTTP User-Agent header value during signature validation.
	UserAgentField *string `json:"userAgentField,omitempty"`
	Enabled *bool `json:"enabled,omitempty"`
	// String of values delimited by a ',' character.
	MethodFilter *string `json:"methodFilter,omitempty"`
	// String of values delimited by a ',' character.
	PathFilter *string `json:"pathFilter,omitempty"`
	// String of values delimited by a ',' character.
	HeaderFilter *string `json:"headerFilter,omitempty"`
}

// NewCustconfAuthUrlSign instantiates a new CustconfAuthUrlSign object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCustconfAuthUrlSign() *CustconfAuthUrlSign {
	this := CustconfAuthUrlSign{}
	return &this
}

// NewCustconfAuthUrlSignWithDefaults instantiates a new CustconfAuthUrlSign object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCustconfAuthUrlSignWithDefaults() *CustconfAuthUrlSign {
	this := CustconfAuthUrlSign{}
	return &this
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *CustconfAuthUrlSign) GetId() string {
	if o == nil || o.Id == nil {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlSign) GetIdOk() (*string, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *CustconfAuthUrlSign) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *CustconfAuthUrlSign) SetId(v string) {
	o.Id = &v
}

// GetTokenField returns the TokenField field value if set, zero value otherwise.
func (o *CustconfAuthUrlSign) GetTokenField() string {
	if o == nil || o.TokenField == nil {
		var ret string
		return ret
	}
	return *o.TokenField
}

// GetTokenFieldOk returns a tuple with the TokenField field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlSign) GetTokenFieldOk() (*string, bool) {
	if o == nil || o.TokenField == nil {
		return nil, false
	}
	return o.TokenField, true
}

// HasTokenField returns a boolean if a field has been set.
func (o *CustconfAuthUrlSign) HasTokenField() bool {
	if o != nil && o.TokenField != nil {
		return true
	}

	return false
}

// SetTokenField gets a reference to the given string and assigns it to the TokenField field.
func (o *CustconfAuthUrlSign) SetTokenField(v string) {
	o.TokenField = &v
}

// GetIgnoreFieldsAfterToken returns the IgnoreFieldsAfterToken field value if set, zero value otherwise.
func (o *CustconfAuthUrlSign) GetIgnoreFieldsAfterToken() bool {
	if o == nil || o.IgnoreFieldsAfterToken == nil {
		var ret bool
		return ret
	}
	return *o.IgnoreFieldsAfterToken
}

// GetIgnoreFieldsAfterTokenOk returns a tuple with the IgnoreFieldsAfterToken field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlSign) GetIgnoreFieldsAfterTokenOk() (*bool, bool) {
	if o == nil || o.IgnoreFieldsAfterToken == nil {
		return nil, false
	}
	return o.IgnoreFieldsAfterToken, true
}

// HasIgnoreFieldsAfterToken returns a boolean if a field has been set.
func (o *CustconfAuthUrlSign) HasIgnoreFieldsAfterToken() bool {
	if o != nil && o.IgnoreFieldsAfterToken != nil {
		return true
	}

	return false
}

// SetIgnoreFieldsAfterToken gets a reference to the given bool and assigns it to the IgnoreFieldsAfterToken field.
func (o *CustconfAuthUrlSign) SetIgnoreFieldsAfterToken(v bool) {
	o.IgnoreFieldsAfterToken = &v
}

// GetPassPhraseField returns the PassPhraseField field value if set, zero value otherwise.
func (o *CustconfAuthUrlSign) GetPassPhraseField() string {
	if o == nil || o.PassPhraseField == nil {
		var ret string
		return ret
	}
	return *o.PassPhraseField
}

// GetPassPhraseFieldOk returns a tuple with the PassPhraseField field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlSign) GetPassPhraseFieldOk() (*string, bool) {
	if o == nil || o.PassPhraseField == nil {
		return nil, false
	}
	return o.PassPhraseField, true
}

// HasPassPhraseField returns a boolean if a field has been set.
func (o *CustconfAuthUrlSign) HasPassPhraseField() bool {
	if o != nil && o.PassPhraseField != nil {
		return true
	}

	return false
}

// SetPassPhraseField gets a reference to the given string and assigns it to the PassPhraseField field.
func (o *CustconfAuthUrlSign) SetPassPhraseField(v string) {
	o.PassPhraseField = &v
}

// GetPassPhrase returns the PassPhrase field value if set, zero value otherwise.
func (o *CustconfAuthUrlSign) GetPassPhrase() string {
	if o == nil || o.PassPhrase == nil {
		var ret string
		return ret
	}
	return *o.PassPhrase
}

// GetPassPhraseOk returns a tuple with the PassPhrase field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlSign) GetPassPhraseOk() (*string, bool) {
	if o == nil || o.PassPhrase == nil {
		return nil, false
	}
	return o.PassPhrase, true
}

// HasPassPhrase returns a boolean if a field has been set.
func (o *CustconfAuthUrlSign) HasPassPhrase() bool {
	if o != nil && o.PassPhrase != nil {
		return true
	}

	return false
}

// SetPassPhrase gets a reference to the given string and assigns it to the PassPhrase field.
func (o *CustconfAuthUrlSign) SetPassPhrase(v string) {
	o.PassPhrase = &v
}

// GetExpiresField returns the ExpiresField field value if set, zero value otherwise.
func (o *CustconfAuthUrlSign) GetExpiresField() string {
	if o == nil || o.ExpiresField == nil {
		var ret string
		return ret
	}
	return *o.ExpiresField
}

// GetExpiresFieldOk returns a tuple with the ExpiresField field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlSign) GetExpiresFieldOk() (*string, bool) {
	if o == nil || o.ExpiresField == nil {
		return nil, false
	}
	return o.ExpiresField, true
}

// HasExpiresField returns a boolean if a field has been set.
func (o *CustconfAuthUrlSign) HasExpiresField() bool {
	if o != nil && o.ExpiresField != nil {
		return true
	}

	return false
}

// SetExpiresField gets a reference to the given string and assigns it to the ExpiresField field.
func (o *CustconfAuthUrlSign) SetExpiresField(v string) {
	o.ExpiresField = &v
}

// GetIpAddressField returns the IpAddressField field value if set, zero value otherwise.
func (o *CustconfAuthUrlSign) GetIpAddressField() string {
	if o == nil || o.IpAddressField == nil {
		var ret string
		return ret
	}
	return *o.IpAddressField
}

// GetIpAddressFieldOk returns a tuple with the IpAddressField field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlSign) GetIpAddressFieldOk() (*string, bool) {
	if o == nil || o.IpAddressField == nil {
		return nil, false
	}
	return o.IpAddressField, true
}

// HasIpAddressField returns a boolean if a field has been set.
func (o *CustconfAuthUrlSign) HasIpAddressField() bool {
	if o != nil && o.IpAddressField != nil {
		return true
	}

	return false
}

// SetIpAddressField gets a reference to the given string and assigns it to the IpAddressField field.
func (o *CustconfAuthUrlSign) SetIpAddressField(v string) {
	o.IpAddressField = &v
}

// GetUriLengthField returns the UriLengthField field value if set, zero value otherwise.
func (o *CustconfAuthUrlSign) GetUriLengthField() string {
	if o == nil || o.UriLengthField == nil {
		var ret string
		return ret
	}
	return *o.UriLengthField
}

// GetUriLengthFieldOk returns a tuple with the UriLengthField field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlSign) GetUriLengthFieldOk() (*string, bool) {
	if o == nil || o.UriLengthField == nil {
		return nil, false
	}
	return o.UriLengthField, true
}

// HasUriLengthField returns a boolean if a field has been set.
func (o *CustconfAuthUrlSign) HasUriLengthField() bool {
	if o != nil && o.UriLengthField != nil {
		return true
	}

	return false
}

// SetUriLengthField gets a reference to the given string and assigns it to the UriLengthField field.
func (o *CustconfAuthUrlSign) SetUriLengthField(v string) {
	o.UriLengthField = &v
}

// GetUserAgentField returns the UserAgentField field value if set, zero value otherwise.
func (o *CustconfAuthUrlSign) GetUserAgentField() string {
	if o == nil || o.UserAgentField == nil {
		var ret string
		return ret
	}
	return *o.UserAgentField
}

// GetUserAgentFieldOk returns a tuple with the UserAgentField field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlSign) GetUserAgentFieldOk() (*string, bool) {
	if o == nil || o.UserAgentField == nil {
		return nil, false
	}
	return o.UserAgentField, true
}

// HasUserAgentField returns a boolean if a field has been set.
func (o *CustconfAuthUrlSign) HasUserAgentField() bool {
	if o != nil && o.UserAgentField != nil {
		return true
	}

	return false
}

// SetUserAgentField gets a reference to the given string and assigns it to the UserAgentField field.
func (o *CustconfAuthUrlSign) SetUserAgentField(v string) {
	o.UserAgentField = &v
}

// GetEnabled returns the Enabled field value if set, zero value otherwise.
func (o *CustconfAuthUrlSign) GetEnabled() bool {
	if o == nil || o.Enabled == nil {
		var ret bool
		return ret
	}
	return *o.Enabled
}

// GetEnabledOk returns a tuple with the Enabled field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlSign) GetEnabledOk() (*bool, bool) {
	if o == nil || o.Enabled == nil {
		return nil, false
	}
	return o.Enabled, true
}

// HasEnabled returns a boolean if a field has been set.
func (o *CustconfAuthUrlSign) HasEnabled() bool {
	if o != nil && o.Enabled != nil {
		return true
	}

	return false
}

// SetEnabled gets a reference to the given bool and assigns it to the Enabled field.
func (o *CustconfAuthUrlSign) SetEnabled(v bool) {
	o.Enabled = &v
}

// GetMethodFilter returns the MethodFilter field value if set, zero value otherwise.
func (o *CustconfAuthUrlSign) GetMethodFilter() string {
	if o == nil || o.MethodFilter == nil {
		var ret string
		return ret
	}
	return *o.MethodFilter
}

// GetMethodFilterOk returns a tuple with the MethodFilter field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlSign) GetMethodFilterOk() (*string, bool) {
	if o == nil || o.MethodFilter == nil {
		return nil, false
	}
	return o.MethodFilter, true
}

// HasMethodFilter returns a boolean if a field has been set.
func (o *CustconfAuthUrlSign) HasMethodFilter() bool {
	if o != nil && o.MethodFilter != nil {
		return true
	}

	return false
}

// SetMethodFilter gets a reference to the given string and assigns it to the MethodFilter field.
func (o *CustconfAuthUrlSign) SetMethodFilter(v string) {
	o.MethodFilter = &v
}

// GetPathFilter returns the PathFilter field value if set, zero value otherwise.
func (o *CustconfAuthUrlSign) GetPathFilter() string {
	if o == nil || o.PathFilter == nil {
		var ret string
		return ret
	}
	return *o.PathFilter
}

// GetPathFilterOk returns a tuple with the PathFilter field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlSign) GetPathFilterOk() (*string, bool) {
	if o == nil || o.PathFilter == nil {
		return nil, false
	}
	return o.PathFilter, true
}

// HasPathFilter returns a boolean if a field has been set.
func (o *CustconfAuthUrlSign) HasPathFilter() bool {
	if o != nil && o.PathFilter != nil {
		return true
	}

	return false
}

// SetPathFilter gets a reference to the given string and assigns it to the PathFilter field.
func (o *CustconfAuthUrlSign) SetPathFilter(v string) {
	o.PathFilter = &v
}

// GetHeaderFilter returns the HeaderFilter field value if set, zero value otherwise.
func (o *CustconfAuthUrlSign) GetHeaderFilter() string {
	if o == nil || o.HeaderFilter == nil {
		var ret string
		return ret
	}
	return *o.HeaderFilter
}

// GetHeaderFilterOk returns a tuple with the HeaderFilter field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlSign) GetHeaderFilterOk() (*string, bool) {
	if o == nil || o.HeaderFilter == nil {
		return nil, false
	}
	return o.HeaderFilter, true
}

// HasHeaderFilter returns a boolean if a field has been set.
func (o *CustconfAuthUrlSign) HasHeaderFilter() bool {
	if o != nil && o.HeaderFilter != nil {
		return true
	}

	return false
}

// SetHeaderFilter gets a reference to the given string and assigns it to the HeaderFilter field.
func (o *CustconfAuthUrlSign) SetHeaderFilter(v string) {
	o.HeaderFilter = &v
}

func (o CustconfAuthUrlSign) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Id != nil {
		toSerialize["id"] = o.Id
	}
	if o.TokenField != nil {
		toSerialize["tokenField"] = o.TokenField
	}
	if o.IgnoreFieldsAfterToken != nil {
		toSerialize["ignoreFieldsAfterToken"] = o.IgnoreFieldsAfterToken
	}
	if o.PassPhraseField != nil {
		toSerialize["passPhraseField"] = o.PassPhraseField
	}
	if o.PassPhrase != nil {
		toSerialize["passPhrase"] = o.PassPhrase
	}
	if o.ExpiresField != nil {
		toSerialize["expiresField"] = o.ExpiresField
	}
	if o.IpAddressField != nil {
		toSerialize["ipAddressField"] = o.IpAddressField
	}
	if o.UriLengthField != nil {
		toSerialize["uriLengthField"] = o.UriLengthField
	}
	if o.UserAgentField != nil {
		toSerialize["userAgentField"] = o.UserAgentField
	}
	if o.Enabled != nil {
		toSerialize["enabled"] = o.Enabled
	}
	if o.MethodFilter != nil {
		toSerialize["methodFilter"] = o.MethodFilter
	}
	if o.PathFilter != nil {
		toSerialize["pathFilter"] = o.PathFilter
	}
	if o.HeaderFilter != nil {
		toSerialize["headerFilter"] = o.HeaderFilter
	}
	return json.Marshal(toSerialize)
}

type NullableCustconfAuthUrlSign struct {
	value *CustconfAuthUrlSign
	isSet bool
}

func (v NullableCustconfAuthUrlSign) Get() *CustconfAuthUrlSign {
	return v.value
}

func (v *NullableCustconfAuthUrlSign) Set(val *CustconfAuthUrlSign) {
	v.value = val
	v.isSet = true
}

func (v NullableCustconfAuthUrlSign) IsSet() bool {
	return v.isSet
}

func (v *NullableCustconfAuthUrlSign) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCustconfAuthUrlSign(val *CustconfAuthUrlSign) *NullableCustconfAuthUrlSign {
	return &NullableCustconfAuthUrlSign{value: val, isSet: true}
}

func (v NullableCustconfAuthUrlSign) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCustconfAuthUrlSign) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
