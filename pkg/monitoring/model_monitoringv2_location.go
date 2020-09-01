/*
 * Monitoring
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package monitoring

import (
	"encoding/json"
)

// Monitoringv2Location A location which performs monitoring checks.
type Monitoringv2Location struct {
	// A location's unique identifier
	Id *string `json:"id,omitempty"`
	// A location's name
	Name *string `json:"name,omitempty"`
	// A location's city
	City *string `json:"city,omitempty"`
	// A location's city, expressed as an IATA airport code
	CityCode *string `json:"cityCode,omitempty"`
	// A location's country
	Country *string `json:"country,omitempty"`
	// A location's ISO-3166-1 alpha-2 country code
	CountryCode *string `json:"countryCode,omitempty"`
	// A location's network provider
	Provider *string `json:"provider,omitempty"`
	// The IP addresses of a location  The IP addresses where monitoring checks originate from.
	IpAddresses *[]string `json:"ipAddresses,omitempty"`
	// Whether or not a location supports IPv4 monitoring checks.
	HasIpv4 *bool `json:"hasIpv4,omitempty"`
	// Whether or not a location supports IPv6 monitoring checks.
	HasIpv6 *bool `json:"hasIpv6,omitempty"`
}

// NewMonitoringv2Location instantiates a new Monitoringv2Location object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewMonitoringv2Location() *Monitoringv2Location {
	this := Monitoringv2Location{}
	return &this
}

// NewMonitoringv2LocationWithDefaults instantiates a new Monitoringv2Location object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewMonitoringv2LocationWithDefaults() *Monitoringv2Location {
	this := Monitoringv2Location{}
	return &this
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *Monitoringv2Location) GetId() string {
	if o == nil || o.Id == nil {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Monitoringv2Location) GetIdOk() (*string, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *Monitoringv2Location) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *Monitoringv2Location) SetId(v string) {
	o.Id = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *Monitoringv2Location) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Monitoringv2Location) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *Monitoringv2Location) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *Monitoringv2Location) SetName(v string) {
	o.Name = &v
}

// GetCity returns the City field value if set, zero value otherwise.
func (o *Monitoringv2Location) GetCity() string {
	if o == nil || o.City == nil {
		var ret string
		return ret
	}
	return *o.City
}

// GetCityOk returns a tuple with the City field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Monitoringv2Location) GetCityOk() (*string, bool) {
	if o == nil || o.City == nil {
		return nil, false
	}
	return o.City, true
}

// HasCity returns a boolean if a field has been set.
func (o *Monitoringv2Location) HasCity() bool {
	if o != nil && o.City != nil {
		return true
	}

	return false
}

// SetCity gets a reference to the given string and assigns it to the City field.
func (o *Monitoringv2Location) SetCity(v string) {
	o.City = &v
}

// GetCityCode returns the CityCode field value if set, zero value otherwise.
func (o *Monitoringv2Location) GetCityCode() string {
	if o == nil || o.CityCode == nil {
		var ret string
		return ret
	}
	return *o.CityCode
}

// GetCityCodeOk returns a tuple with the CityCode field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Monitoringv2Location) GetCityCodeOk() (*string, bool) {
	if o == nil || o.CityCode == nil {
		return nil, false
	}
	return o.CityCode, true
}

// HasCityCode returns a boolean if a field has been set.
func (o *Monitoringv2Location) HasCityCode() bool {
	if o != nil && o.CityCode != nil {
		return true
	}

	return false
}

// SetCityCode gets a reference to the given string and assigns it to the CityCode field.
func (o *Monitoringv2Location) SetCityCode(v string) {
	o.CityCode = &v
}

// GetCountry returns the Country field value if set, zero value otherwise.
func (o *Monitoringv2Location) GetCountry() string {
	if o == nil || o.Country == nil {
		var ret string
		return ret
	}
	return *o.Country
}

// GetCountryOk returns a tuple with the Country field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Monitoringv2Location) GetCountryOk() (*string, bool) {
	if o == nil || o.Country == nil {
		return nil, false
	}
	return o.Country, true
}

// HasCountry returns a boolean if a field has been set.
func (o *Monitoringv2Location) HasCountry() bool {
	if o != nil && o.Country != nil {
		return true
	}

	return false
}

// SetCountry gets a reference to the given string and assigns it to the Country field.
func (o *Monitoringv2Location) SetCountry(v string) {
	o.Country = &v
}

// GetCountryCode returns the CountryCode field value if set, zero value otherwise.
func (o *Monitoringv2Location) GetCountryCode() string {
	if o == nil || o.CountryCode == nil {
		var ret string
		return ret
	}
	return *o.CountryCode
}

// GetCountryCodeOk returns a tuple with the CountryCode field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Monitoringv2Location) GetCountryCodeOk() (*string, bool) {
	if o == nil || o.CountryCode == nil {
		return nil, false
	}
	return o.CountryCode, true
}

// HasCountryCode returns a boolean if a field has been set.
func (o *Monitoringv2Location) HasCountryCode() bool {
	if o != nil && o.CountryCode != nil {
		return true
	}

	return false
}

// SetCountryCode gets a reference to the given string and assigns it to the CountryCode field.
func (o *Monitoringv2Location) SetCountryCode(v string) {
	o.CountryCode = &v
}

// GetProvider returns the Provider field value if set, zero value otherwise.
func (o *Monitoringv2Location) GetProvider() string {
	if o == nil || o.Provider == nil {
		var ret string
		return ret
	}
	return *o.Provider
}

// GetProviderOk returns a tuple with the Provider field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Monitoringv2Location) GetProviderOk() (*string, bool) {
	if o == nil || o.Provider == nil {
		return nil, false
	}
	return o.Provider, true
}

// HasProvider returns a boolean if a field has been set.
func (o *Monitoringv2Location) HasProvider() bool {
	if o != nil && o.Provider != nil {
		return true
	}

	return false
}

// SetProvider gets a reference to the given string and assigns it to the Provider field.
func (o *Monitoringv2Location) SetProvider(v string) {
	o.Provider = &v
}

// GetIpAddresses returns the IpAddresses field value if set, zero value otherwise.
func (o *Monitoringv2Location) GetIpAddresses() []string {
	if o == nil || o.IpAddresses == nil {
		var ret []string
		return ret
	}
	return *o.IpAddresses
}

// GetIpAddressesOk returns a tuple with the IpAddresses field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Monitoringv2Location) GetIpAddressesOk() (*[]string, bool) {
	if o == nil || o.IpAddresses == nil {
		return nil, false
	}
	return o.IpAddresses, true
}

// HasIpAddresses returns a boolean if a field has been set.
func (o *Monitoringv2Location) HasIpAddresses() bool {
	if o != nil && o.IpAddresses != nil {
		return true
	}

	return false
}

// SetIpAddresses gets a reference to the given []string and assigns it to the IpAddresses field.
func (o *Monitoringv2Location) SetIpAddresses(v []string) {
	o.IpAddresses = &v
}

// GetHasIpv4 returns the HasIpv4 field value if set, zero value otherwise.
func (o *Monitoringv2Location) GetHasIpv4() bool {
	if o == nil || o.HasIpv4 == nil {
		var ret bool
		return ret
	}
	return *o.HasIpv4
}

// GetHasIpv4Ok returns a tuple with the HasIpv4 field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Monitoringv2Location) GetHasIpv4Ok() (*bool, bool) {
	if o == nil || o.HasIpv4 == nil {
		return nil, false
	}
	return o.HasIpv4, true
}

// HasHasIpv4 returns a boolean if a field has been set.
func (o *Monitoringv2Location) HasHasIpv4() bool {
	if o != nil && o.HasIpv4 != nil {
		return true
	}

	return false
}

// SetHasIpv4 gets a reference to the given bool and assigns it to the HasIpv4 field.
func (o *Monitoringv2Location) SetHasIpv4(v bool) {
	o.HasIpv4 = &v
}

// GetHasIpv6 returns the HasIpv6 field value if set, zero value otherwise.
func (o *Monitoringv2Location) GetHasIpv6() bool {
	if o == nil || o.HasIpv6 == nil {
		var ret bool
		return ret
	}
	return *o.HasIpv6
}

// GetHasIpv6Ok returns a tuple with the HasIpv6 field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Monitoringv2Location) GetHasIpv6Ok() (*bool, bool) {
	if o == nil || o.HasIpv6 == nil {
		return nil, false
	}
	return o.HasIpv6, true
}

// HasHasIpv6 returns a boolean if a field has been set.
func (o *Monitoringv2Location) HasHasIpv6() bool {
	if o != nil && o.HasIpv6 != nil {
		return true
	}

	return false
}

// SetHasIpv6 gets a reference to the given bool and assigns it to the HasIpv6 field.
func (o *Monitoringv2Location) SetHasIpv6(v bool) {
	o.HasIpv6 = &v
}

func (o Monitoringv2Location) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Id != nil {
		toSerialize["id"] = o.Id
	}
	if o.Name != nil {
		toSerialize["name"] = o.Name
	}
	if o.City != nil {
		toSerialize["city"] = o.City
	}
	if o.CityCode != nil {
		toSerialize["cityCode"] = o.CityCode
	}
	if o.Country != nil {
		toSerialize["country"] = o.Country
	}
	if o.CountryCode != nil {
		toSerialize["countryCode"] = o.CountryCode
	}
	if o.Provider != nil {
		toSerialize["provider"] = o.Provider
	}
	if o.IpAddresses != nil {
		toSerialize["ipAddresses"] = o.IpAddresses
	}
	if o.HasIpv4 != nil {
		toSerialize["hasIpv4"] = o.HasIpv4
	}
	if o.HasIpv6 != nil {
		toSerialize["hasIpv6"] = o.HasIpv6
	}
	return json.Marshal(toSerialize)
}

type NullableMonitoringv2Location struct {
	value *Monitoringv2Location
	isSet bool
}

func (v NullableMonitoringv2Location) Get() *Monitoringv2Location {
	return v.value
}

func (v *NullableMonitoringv2Location) Set(val *Monitoringv2Location) {
	v.value = val
	v.isSet = true
}

func (v NullableMonitoringv2Location) IsSet() bool {
	return v.isSet
}

func (v *NullableMonitoringv2Location) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableMonitoringv2Location(val *Monitoringv2Location) *NullableMonitoringv2Location {
	return &NullableMonitoringv2Location{value: val, isSet: true}
}

func (v NullableMonitoringv2Location) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableMonitoringv2Location) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
