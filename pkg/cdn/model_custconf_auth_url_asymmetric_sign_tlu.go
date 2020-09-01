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
	"encoding/json"
)

// CustconfAuthUrlAsymmetricSignTlu struct for CustconfAuthUrlAsymmetricSignTlu
type CustconfAuthUrlAsymmetricSignTlu struct {
	// This is used by the API to perform conflict checking
	Id *string `json:"id,omitempty"`
	ExpireParameterName *string `json:"expireParameterName,omitempty"`
	KeyIdParameterName *string `json:"keyIdParameterName,omitempty"`
	AlgorithmIdParameterName *string `json:"algorithmIdParameterName,omitempty"`
	DigestParameterName *string `json:"digestParameterName,omitempty"`
	PublicKeyIdMap *map[string]string `json:"publicKeyIdMap,omitempty"`
	AlgorithmIdMap *map[string]CustconfAuthUrlAsymmetricSignTluAlgorithmIdMapEnumWrapperValue `json:"algorithmIdMap,omitempty"`
	Enabled *bool `json:"enabled,omitempty"`
	// String of values delimited by a ',' character.
	MethodFilter *string `json:"methodFilter,omitempty"`
	// String of values delimited by a ',' character.
	PathFilter *string `json:"pathFilter,omitempty"`
	// String of values delimited by a ',' character.
	HeaderFilter *string `json:"headerFilter,omitempty"`
}

// NewCustconfAuthUrlAsymmetricSignTlu instantiates a new CustconfAuthUrlAsymmetricSignTlu object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCustconfAuthUrlAsymmetricSignTlu() *CustconfAuthUrlAsymmetricSignTlu {
	this := CustconfAuthUrlAsymmetricSignTlu{}
	return &this
}

// NewCustconfAuthUrlAsymmetricSignTluWithDefaults instantiates a new CustconfAuthUrlAsymmetricSignTlu object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewCustconfAuthUrlAsymmetricSignTluWithDefaults() *CustconfAuthUrlAsymmetricSignTlu {
	this := CustconfAuthUrlAsymmetricSignTlu{}
	return &this
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetId() string {
	if o == nil || o.Id == nil {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetIdOk() (*string, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *CustconfAuthUrlAsymmetricSignTlu) SetId(v string) {
	o.Id = &v
}

// GetExpireParameterName returns the ExpireParameterName field value if set, zero value otherwise.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetExpireParameterName() string {
	if o == nil || o.ExpireParameterName == nil {
		var ret string
		return ret
	}
	return *o.ExpireParameterName
}

// GetExpireParameterNameOk returns a tuple with the ExpireParameterName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetExpireParameterNameOk() (*string, bool) {
	if o == nil || o.ExpireParameterName == nil {
		return nil, false
	}
	return o.ExpireParameterName, true
}

// HasExpireParameterName returns a boolean if a field has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) HasExpireParameterName() bool {
	if o != nil && o.ExpireParameterName != nil {
		return true
	}

	return false
}

// SetExpireParameterName gets a reference to the given string and assigns it to the ExpireParameterName field.
func (o *CustconfAuthUrlAsymmetricSignTlu) SetExpireParameterName(v string) {
	o.ExpireParameterName = &v
}

// GetKeyIdParameterName returns the KeyIdParameterName field value if set, zero value otherwise.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetKeyIdParameterName() string {
	if o == nil || o.KeyIdParameterName == nil {
		var ret string
		return ret
	}
	return *o.KeyIdParameterName
}

// GetKeyIdParameterNameOk returns a tuple with the KeyIdParameterName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetKeyIdParameterNameOk() (*string, bool) {
	if o == nil || o.KeyIdParameterName == nil {
		return nil, false
	}
	return o.KeyIdParameterName, true
}

// HasKeyIdParameterName returns a boolean if a field has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) HasKeyIdParameterName() bool {
	if o != nil && o.KeyIdParameterName != nil {
		return true
	}

	return false
}

// SetKeyIdParameterName gets a reference to the given string and assigns it to the KeyIdParameterName field.
func (o *CustconfAuthUrlAsymmetricSignTlu) SetKeyIdParameterName(v string) {
	o.KeyIdParameterName = &v
}

// GetAlgorithmIdParameterName returns the AlgorithmIdParameterName field value if set, zero value otherwise.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetAlgorithmIdParameterName() string {
	if o == nil || o.AlgorithmIdParameterName == nil {
		var ret string
		return ret
	}
	return *o.AlgorithmIdParameterName
}

// GetAlgorithmIdParameterNameOk returns a tuple with the AlgorithmIdParameterName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetAlgorithmIdParameterNameOk() (*string, bool) {
	if o == nil || o.AlgorithmIdParameterName == nil {
		return nil, false
	}
	return o.AlgorithmIdParameterName, true
}

// HasAlgorithmIdParameterName returns a boolean if a field has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) HasAlgorithmIdParameterName() bool {
	if o != nil && o.AlgorithmIdParameterName != nil {
		return true
	}

	return false
}

// SetAlgorithmIdParameterName gets a reference to the given string and assigns it to the AlgorithmIdParameterName field.
func (o *CustconfAuthUrlAsymmetricSignTlu) SetAlgorithmIdParameterName(v string) {
	o.AlgorithmIdParameterName = &v
}

// GetDigestParameterName returns the DigestParameterName field value if set, zero value otherwise.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetDigestParameterName() string {
	if o == nil || o.DigestParameterName == nil {
		var ret string
		return ret
	}
	return *o.DigestParameterName
}

// GetDigestParameterNameOk returns a tuple with the DigestParameterName field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetDigestParameterNameOk() (*string, bool) {
	if o == nil || o.DigestParameterName == nil {
		return nil, false
	}
	return o.DigestParameterName, true
}

// HasDigestParameterName returns a boolean if a field has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) HasDigestParameterName() bool {
	if o != nil && o.DigestParameterName != nil {
		return true
	}

	return false
}

// SetDigestParameterName gets a reference to the given string and assigns it to the DigestParameterName field.
func (o *CustconfAuthUrlAsymmetricSignTlu) SetDigestParameterName(v string) {
	o.DigestParameterName = &v
}

// GetPublicKeyIdMap returns the PublicKeyIdMap field value if set, zero value otherwise.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetPublicKeyIdMap() map[string]string {
	if o == nil || o.PublicKeyIdMap == nil {
		var ret map[string]string
		return ret
	}
	return *o.PublicKeyIdMap
}

// GetPublicKeyIdMapOk returns a tuple with the PublicKeyIdMap field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetPublicKeyIdMapOk() (*map[string]string, bool) {
	if o == nil || o.PublicKeyIdMap == nil {
		return nil, false
	}
	return o.PublicKeyIdMap, true
}

// HasPublicKeyIdMap returns a boolean if a field has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) HasPublicKeyIdMap() bool {
	if o != nil && o.PublicKeyIdMap != nil {
		return true
	}

	return false
}

// SetPublicKeyIdMap gets a reference to the given map[string]string and assigns it to the PublicKeyIdMap field.
func (o *CustconfAuthUrlAsymmetricSignTlu) SetPublicKeyIdMap(v map[string]string) {
	o.PublicKeyIdMap = &v
}

// GetAlgorithmIdMap returns the AlgorithmIdMap field value if set, zero value otherwise.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetAlgorithmIdMap() map[string]CustconfAuthUrlAsymmetricSignTluAlgorithmIdMapEnumWrapperValue {
	if o == nil || o.AlgorithmIdMap == nil {
		var ret map[string]CustconfAuthUrlAsymmetricSignTluAlgorithmIdMapEnumWrapperValue
		return ret
	}
	return *o.AlgorithmIdMap
}

// GetAlgorithmIdMapOk returns a tuple with the AlgorithmIdMap field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetAlgorithmIdMapOk() (*map[string]CustconfAuthUrlAsymmetricSignTluAlgorithmIdMapEnumWrapperValue, bool) {
	if o == nil || o.AlgorithmIdMap == nil {
		return nil, false
	}
	return o.AlgorithmIdMap, true
}

// HasAlgorithmIdMap returns a boolean if a field has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) HasAlgorithmIdMap() bool {
	if o != nil && o.AlgorithmIdMap != nil {
		return true
	}

	return false
}

// SetAlgorithmIdMap gets a reference to the given map[string]CustconfAuthUrlAsymmetricSignTluAlgorithmIdMapEnumWrapperValue and assigns it to the AlgorithmIdMap field.
func (o *CustconfAuthUrlAsymmetricSignTlu) SetAlgorithmIdMap(v map[string]CustconfAuthUrlAsymmetricSignTluAlgorithmIdMapEnumWrapperValue) {
	o.AlgorithmIdMap = &v
}

// GetEnabled returns the Enabled field value if set, zero value otherwise.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetEnabled() bool {
	if o == nil || o.Enabled == nil {
		var ret bool
		return ret
	}
	return *o.Enabled
}

// GetEnabledOk returns a tuple with the Enabled field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetEnabledOk() (*bool, bool) {
	if o == nil || o.Enabled == nil {
		return nil, false
	}
	return o.Enabled, true
}

// HasEnabled returns a boolean if a field has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) HasEnabled() bool {
	if o != nil && o.Enabled != nil {
		return true
	}

	return false
}

// SetEnabled gets a reference to the given bool and assigns it to the Enabled field.
func (o *CustconfAuthUrlAsymmetricSignTlu) SetEnabled(v bool) {
	o.Enabled = &v
}

// GetMethodFilter returns the MethodFilter field value if set, zero value otherwise.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetMethodFilter() string {
	if o == nil || o.MethodFilter == nil {
		var ret string
		return ret
	}
	return *o.MethodFilter
}

// GetMethodFilterOk returns a tuple with the MethodFilter field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetMethodFilterOk() (*string, bool) {
	if o == nil || o.MethodFilter == nil {
		return nil, false
	}
	return o.MethodFilter, true
}

// HasMethodFilter returns a boolean if a field has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) HasMethodFilter() bool {
	if o != nil && o.MethodFilter != nil {
		return true
	}

	return false
}

// SetMethodFilter gets a reference to the given string and assigns it to the MethodFilter field.
func (o *CustconfAuthUrlAsymmetricSignTlu) SetMethodFilter(v string) {
	o.MethodFilter = &v
}

// GetPathFilter returns the PathFilter field value if set, zero value otherwise.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetPathFilter() string {
	if o == nil || o.PathFilter == nil {
		var ret string
		return ret
	}
	return *o.PathFilter
}

// GetPathFilterOk returns a tuple with the PathFilter field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetPathFilterOk() (*string, bool) {
	if o == nil || o.PathFilter == nil {
		return nil, false
	}
	return o.PathFilter, true
}

// HasPathFilter returns a boolean if a field has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) HasPathFilter() bool {
	if o != nil && o.PathFilter != nil {
		return true
	}

	return false
}

// SetPathFilter gets a reference to the given string and assigns it to the PathFilter field.
func (o *CustconfAuthUrlAsymmetricSignTlu) SetPathFilter(v string) {
	o.PathFilter = &v
}

// GetHeaderFilter returns the HeaderFilter field value if set, zero value otherwise.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetHeaderFilter() string {
	if o == nil || o.HeaderFilter == nil {
		var ret string
		return ret
	}
	return *o.HeaderFilter
}

// GetHeaderFilterOk returns a tuple with the HeaderFilter field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) GetHeaderFilterOk() (*string, bool) {
	if o == nil || o.HeaderFilter == nil {
		return nil, false
	}
	return o.HeaderFilter, true
}

// HasHeaderFilter returns a boolean if a field has been set.
func (o *CustconfAuthUrlAsymmetricSignTlu) HasHeaderFilter() bool {
	if o != nil && o.HeaderFilter != nil {
		return true
	}

	return false
}

// SetHeaderFilter gets a reference to the given string and assigns it to the HeaderFilter field.
func (o *CustconfAuthUrlAsymmetricSignTlu) SetHeaderFilter(v string) {
	o.HeaderFilter = &v
}

func (o CustconfAuthUrlAsymmetricSignTlu) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Id != nil {
		toSerialize["id"] = o.Id
	}
	if o.ExpireParameterName != nil {
		toSerialize["expireParameterName"] = o.ExpireParameterName
	}
	if o.KeyIdParameterName != nil {
		toSerialize["keyIdParameterName"] = o.KeyIdParameterName
	}
	if o.AlgorithmIdParameterName != nil {
		toSerialize["algorithmIdParameterName"] = o.AlgorithmIdParameterName
	}
	if o.DigestParameterName != nil {
		toSerialize["digestParameterName"] = o.DigestParameterName
	}
	if o.PublicKeyIdMap != nil {
		toSerialize["publicKeyIdMap"] = o.PublicKeyIdMap
	}
	if o.AlgorithmIdMap != nil {
		toSerialize["algorithmIdMap"] = o.AlgorithmIdMap
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

type NullableCustconfAuthUrlAsymmetricSignTlu struct {
	value *CustconfAuthUrlAsymmetricSignTlu
	isSet bool
}

func (v NullableCustconfAuthUrlAsymmetricSignTlu) Get() *CustconfAuthUrlAsymmetricSignTlu {
	return v.value
}

func (v *NullableCustconfAuthUrlAsymmetricSignTlu) Set(val *CustconfAuthUrlAsymmetricSignTlu) {
	v.value = val
	v.isSet = true
}

func (v NullableCustconfAuthUrlAsymmetricSignTlu) IsSet() bool {
	return v.isSet
}

func (v *NullableCustconfAuthUrlAsymmetricSignTlu) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableCustconfAuthUrlAsymmetricSignTlu(val *CustconfAuthUrlAsymmetricSignTlu) *NullableCustconfAuthUrlAsymmetricSignTlu {
	return &NullableCustconfAuthUrlAsymmetricSignTlu{value: val, isSet: true}
}

func (v NullableCustconfAuthUrlAsymmetricSignTlu) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableCustconfAuthUrlAsymmetricSignTlu) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
