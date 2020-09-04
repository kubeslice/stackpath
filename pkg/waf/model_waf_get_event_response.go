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

// WafGetEventResponse A response from a request to retrieve a single WAF event
type WafGetEventResponse struct {
	Event *WafEvent `json:"event,omitempty"`
}

// NewWafGetEventResponse instantiates a new WafGetEventResponse object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewWafGetEventResponse() *WafGetEventResponse {
	this := WafGetEventResponse{}
	return &this
}

// NewWafGetEventResponseWithDefaults instantiates a new WafGetEventResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewWafGetEventResponseWithDefaults() *WafGetEventResponse {
	this := WafGetEventResponse{}
	return &this
}

// GetEvent returns the Event field value if set, zero value otherwise.
func (o *WafGetEventResponse) GetEvent() WafEvent {
	if o == nil || o.Event == nil {
		var ret WafEvent
		return ret
	}
	return *o.Event
}

// GetEventOk returns a tuple with the Event field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *WafGetEventResponse) GetEventOk() (*WafEvent, bool) {
	if o == nil || o.Event == nil {
		return nil, false
	}
	return o.Event, true
}

// HasEvent returns a boolean if a field has been set.
func (o *WafGetEventResponse) HasEvent() bool {
	if o != nil && o.Event != nil {
		return true
	}

	return false
}

// SetEvent gets a reference to the given WafEvent and assigns it to the Event field.
func (o *WafGetEventResponse) SetEvent(v WafEvent) {
	o.Event = &v
}

func (o WafGetEventResponse) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Event != nil {
		toSerialize["event"] = o.Event
	}
	return json.Marshal(toSerialize)
}

type NullableWafGetEventResponse struct {
	value *WafGetEventResponse
	isSet bool
}

func (v NullableWafGetEventResponse) Get() *WafGetEventResponse {
	return v.value
}

func (v *NullableWafGetEventResponse) Set(val *WafGetEventResponse) {
	v.value = val
	v.isSet = true
}

func (v NullableWafGetEventResponse) IsSet() bool {
	return v.isSet
}

func (v *NullableWafGetEventResponse) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableWafGetEventResponse(val *WafGetEventResponse) *NullableWafGetEventResponse {
	return &NullableWafGetEventResponse{value: val, isSet: true}
}

func (v NullableWafGetEventResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableWafGetEventResponse) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
