/*
 * Edge Compute
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute

import (
	"encoding/json"
)

// V1Probe A health check probe against a workload instance to determine if it is alive or ready to receive traffic
type V1Probe struct {
	HttpGet *V1HTTPGetAction `json:"httpGet,omitempty"`
	TcpSocket *V1TCPSocketAction `json:"tcpSocket,omitempty"`
	// The number of seconds after a workload instance has started before liveness probes are initiated
	InitialDelaySeconds *int32 `json:"initialDelaySeconds,omitempty"`
	// The number of seconds after which a probe times out  Defaults to 1 second. Minimum value is 1.
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`
	// How often, in seconds, to perform a probe  Default to 10 seconds. Minimum value is 1.
	PeriodSeconds *int32 `json:"periodSeconds,omitempty"`
	// The minimum consecutive successes for a probe to be considered successful after having failed  Defaults to 1. Must be 1 for liveness. Minimum value is 1.
	SuccessThreshold *int32 `json:"successThreshold,omitempty"`
	// The minimum consecutive failures for a probe to be considered failed after having succeeded  Defaults to 3. Minimum value is 1.
	FailureThreshold *int32 `json:"failureThreshold,omitempty"`
}

// NewV1Probe instantiates a new V1Probe object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewV1Probe() *V1Probe {
	this := V1Probe{}
	return &this
}

// NewV1ProbeWithDefaults instantiates a new V1Probe object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewV1ProbeWithDefaults() *V1Probe {
	this := V1Probe{}
	return &this
}

// GetHttpGet returns the HttpGet field value if set, zero value otherwise.
func (o *V1Probe) GetHttpGet() V1HTTPGetAction {
	if o == nil || o.HttpGet == nil {
		var ret V1HTTPGetAction
		return ret
	}
	return *o.HttpGet
}

// GetHttpGetOk returns a tuple with the HttpGet field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Probe) GetHttpGetOk() (*V1HTTPGetAction, bool) {
	if o == nil || o.HttpGet == nil {
		return nil, false
	}
	return o.HttpGet, true
}

// HasHttpGet returns a boolean if a field has been set.
func (o *V1Probe) HasHttpGet() bool {
	if o != nil && o.HttpGet != nil {
		return true
	}

	return false
}

// SetHttpGet gets a reference to the given V1HTTPGetAction and assigns it to the HttpGet field.
func (o *V1Probe) SetHttpGet(v V1HTTPGetAction) {
	o.HttpGet = &v
}

// GetTcpSocket returns the TcpSocket field value if set, zero value otherwise.
func (o *V1Probe) GetTcpSocket() V1TCPSocketAction {
	if o == nil || o.TcpSocket == nil {
		var ret V1TCPSocketAction
		return ret
	}
	return *o.TcpSocket
}

// GetTcpSocketOk returns a tuple with the TcpSocket field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Probe) GetTcpSocketOk() (*V1TCPSocketAction, bool) {
	if o == nil || o.TcpSocket == nil {
		return nil, false
	}
	return o.TcpSocket, true
}

// HasTcpSocket returns a boolean if a field has been set.
func (o *V1Probe) HasTcpSocket() bool {
	if o != nil && o.TcpSocket != nil {
		return true
	}

	return false
}

// SetTcpSocket gets a reference to the given V1TCPSocketAction and assigns it to the TcpSocket field.
func (o *V1Probe) SetTcpSocket(v V1TCPSocketAction) {
	o.TcpSocket = &v
}

// GetInitialDelaySeconds returns the InitialDelaySeconds field value if set, zero value otherwise.
func (o *V1Probe) GetInitialDelaySeconds() int32 {
	if o == nil || o.InitialDelaySeconds == nil {
		var ret int32
		return ret
	}
	return *o.InitialDelaySeconds
}

// GetInitialDelaySecondsOk returns a tuple with the InitialDelaySeconds field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Probe) GetInitialDelaySecondsOk() (*int32, bool) {
	if o == nil || o.InitialDelaySeconds == nil {
		return nil, false
	}
	return o.InitialDelaySeconds, true
}

// HasInitialDelaySeconds returns a boolean if a field has been set.
func (o *V1Probe) HasInitialDelaySeconds() bool {
	if o != nil && o.InitialDelaySeconds != nil {
		return true
	}

	return false
}

// SetInitialDelaySeconds gets a reference to the given int32 and assigns it to the InitialDelaySeconds field.
func (o *V1Probe) SetInitialDelaySeconds(v int32) {
	o.InitialDelaySeconds = &v
}

// GetTimeoutSeconds returns the TimeoutSeconds field value if set, zero value otherwise.
func (o *V1Probe) GetTimeoutSeconds() int32 {
	if o == nil || o.TimeoutSeconds == nil {
		var ret int32
		return ret
	}
	return *o.TimeoutSeconds
}

// GetTimeoutSecondsOk returns a tuple with the TimeoutSeconds field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Probe) GetTimeoutSecondsOk() (*int32, bool) {
	if o == nil || o.TimeoutSeconds == nil {
		return nil, false
	}
	return o.TimeoutSeconds, true
}

// HasTimeoutSeconds returns a boolean if a field has been set.
func (o *V1Probe) HasTimeoutSeconds() bool {
	if o != nil && o.TimeoutSeconds != nil {
		return true
	}

	return false
}

// SetTimeoutSeconds gets a reference to the given int32 and assigns it to the TimeoutSeconds field.
func (o *V1Probe) SetTimeoutSeconds(v int32) {
	o.TimeoutSeconds = &v
}

// GetPeriodSeconds returns the PeriodSeconds field value if set, zero value otherwise.
func (o *V1Probe) GetPeriodSeconds() int32 {
	if o == nil || o.PeriodSeconds == nil {
		var ret int32
		return ret
	}
	return *o.PeriodSeconds
}

// GetPeriodSecondsOk returns a tuple with the PeriodSeconds field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Probe) GetPeriodSecondsOk() (*int32, bool) {
	if o == nil || o.PeriodSeconds == nil {
		return nil, false
	}
	return o.PeriodSeconds, true
}

// HasPeriodSeconds returns a boolean if a field has been set.
func (o *V1Probe) HasPeriodSeconds() bool {
	if o != nil && o.PeriodSeconds != nil {
		return true
	}

	return false
}

// SetPeriodSeconds gets a reference to the given int32 and assigns it to the PeriodSeconds field.
func (o *V1Probe) SetPeriodSeconds(v int32) {
	o.PeriodSeconds = &v
}

// GetSuccessThreshold returns the SuccessThreshold field value if set, zero value otherwise.
func (o *V1Probe) GetSuccessThreshold() int32 {
	if o == nil || o.SuccessThreshold == nil {
		var ret int32
		return ret
	}
	return *o.SuccessThreshold
}

// GetSuccessThresholdOk returns a tuple with the SuccessThreshold field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Probe) GetSuccessThresholdOk() (*int32, bool) {
	if o == nil || o.SuccessThreshold == nil {
		return nil, false
	}
	return o.SuccessThreshold, true
}

// HasSuccessThreshold returns a boolean if a field has been set.
func (o *V1Probe) HasSuccessThreshold() bool {
	if o != nil && o.SuccessThreshold != nil {
		return true
	}

	return false
}

// SetSuccessThreshold gets a reference to the given int32 and assigns it to the SuccessThreshold field.
func (o *V1Probe) SetSuccessThreshold(v int32) {
	o.SuccessThreshold = &v
}

// GetFailureThreshold returns the FailureThreshold field value if set, zero value otherwise.
func (o *V1Probe) GetFailureThreshold() int32 {
	if o == nil || o.FailureThreshold == nil {
		var ret int32
		return ret
	}
	return *o.FailureThreshold
}

// GetFailureThresholdOk returns a tuple with the FailureThreshold field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1Probe) GetFailureThresholdOk() (*int32, bool) {
	if o == nil || o.FailureThreshold == nil {
		return nil, false
	}
	return o.FailureThreshold, true
}

// HasFailureThreshold returns a boolean if a field has been set.
func (o *V1Probe) HasFailureThreshold() bool {
	if o != nil && o.FailureThreshold != nil {
		return true
	}

	return false
}

// SetFailureThreshold gets a reference to the given int32 and assigns it to the FailureThreshold field.
func (o *V1Probe) SetFailureThreshold(v int32) {
	o.FailureThreshold = &v
}

func (o V1Probe) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.HttpGet != nil {
		toSerialize["httpGet"] = o.HttpGet
	}
	if o.TcpSocket != nil {
		toSerialize["tcpSocket"] = o.TcpSocket
	}
	if o.InitialDelaySeconds != nil {
		toSerialize["initialDelaySeconds"] = o.InitialDelaySeconds
	}
	if o.TimeoutSeconds != nil {
		toSerialize["timeoutSeconds"] = o.TimeoutSeconds
	}
	if o.PeriodSeconds != nil {
		toSerialize["periodSeconds"] = o.PeriodSeconds
	}
	if o.SuccessThreshold != nil {
		toSerialize["successThreshold"] = o.SuccessThreshold
	}
	if o.FailureThreshold != nil {
		toSerialize["failureThreshold"] = o.FailureThreshold
	}
	return json.Marshal(toSerialize)
}

type NullableV1Probe struct {
	value *V1Probe
	isSet bool
}

func (v NullableV1Probe) Get() *V1Probe {
	return v.value
}

func (v *NullableV1Probe) Set(val *V1Probe) {
	v.value = val
	v.isSet = true
}

func (v NullableV1Probe) IsSet() bool {
	return v.isSet
}

func (v *NullableV1Probe) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableV1Probe(val *V1Probe) *NullableV1Probe {
	return &NullableV1Probe{value: val, isSet: true}
}

func (v NullableV1Probe) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableV1Probe) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
