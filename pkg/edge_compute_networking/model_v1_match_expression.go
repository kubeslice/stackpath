/*
 * Edge Compute Networking
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute_networking

import (
	"encoding/json"
)

// V1MatchExpression An expression to match selectors against a set of values
type V1MatchExpression struct {
	// The name of the selector to perform a match against
	Key *string `json:"key,omitempty"`
	// The operation to perform to match a selector  Valid values are \"in\" with support for more possible in the future
	Operator *string `json:"operator,omitempty"`
	// The values to match in the selector
	Values *[]string `json:"values,omitempty"`
}

// NewV1MatchExpression instantiates a new V1MatchExpression object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewV1MatchExpression() *V1MatchExpression {
	this := V1MatchExpression{}
	return &this
}

// NewV1MatchExpressionWithDefaults instantiates a new V1MatchExpression object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewV1MatchExpressionWithDefaults() *V1MatchExpression {
	this := V1MatchExpression{}
	return &this
}

// GetKey returns the Key field value if set, zero value otherwise.
func (o *V1MatchExpression) GetKey() string {
	if o == nil || o.Key == nil {
		var ret string
		return ret
	}
	return *o.Key
}

// GetKeyOk returns a tuple with the Key field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1MatchExpression) GetKeyOk() (*string, bool) {
	if o == nil || o.Key == nil {
		return nil, false
	}
	return o.Key, true
}

// HasKey returns a boolean if a field has been set.
func (o *V1MatchExpression) HasKey() bool {
	if o != nil && o.Key != nil {
		return true
	}

	return false
}

// SetKey gets a reference to the given string and assigns it to the Key field.
func (o *V1MatchExpression) SetKey(v string) {
	o.Key = &v
}

// GetOperator returns the Operator field value if set, zero value otherwise.
func (o *V1MatchExpression) GetOperator() string {
	if o == nil || o.Operator == nil {
		var ret string
		return ret
	}
	return *o.Operator
}

// GetOperatorOk returns a tuple with the Operator field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1MatchExpression) GetOperatorOk() (*string, bool) {
	if o == nil || o.Operator == nil {
		return nil, false
	}
	return o.Operator, true
}

// HasOperator returns a boolean if a field has been set.
func (o *V1MatchExpression) HasOperator() bool {
	if o != nil && o.Operator != nil {
		return true
	}

	return false
}

// SetOperator gets a reference to the given string and assigns it to the Operator field.
func (o *V1MatchExpression) SetOperator(v string) {
	o.Operator = &v
}

// GetValues returns the Values field value if set, zero value otherwise.
func (o *V1MatchExpression) GetValues() []string {
	if o == nil || o.Values == nil {
		var ret []string
		return ret
	}
	return *o.Values
}

// GetValuesOk returns a tuple with the Values field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *V1MatchExpression) GetValuesOk() (*[]string, bool) {
	if o == nil || o.Values == nil {
		return nil, false
	}
	return o.Values, true
}

// HasValues returns a boolean if a field has been set.
func (o *V1MatchExpression) HasValues() bool {
	if o != nil && o.Values != nil {
		return true
	}

	return false
}

// SetValues gets a reference to the given []string and assigns it to the Values field.
func (o *V1MatchExpression) SetValues(v []string) {
	o.Values = &v
}

func (o V1MatchExpression) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Key != nil {
		toSerialize["key"] = o.Key
	}
	if o.Operator != nil {
		toSerialize["operator"] = o.Operator
	}
	if o.Values != nil {
		toSerialize["values"] = o.Values
	}
	return json.Marshal(toSerialize)
}

type NullableV1MatchExpression struct {
	value *V1MatchExpression
	isSet bool
}

func (v NullableV1MatchExpression) Get() *V1MatchExpression {
	return v.value
}

func (v *NullableV1MatchExpression) Set(val *V1MatchExpression) {
	v.value = val
	v.isSet = true
}

func (v NullableV1MatchExpression) IsSet() bool {
	return v.isSet
}

func (v *NullableV1MatchExpression) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableV1MatchExpression(val *V1MatchExpression) *NullableV1MatchExpression {
	return &NullableV1MatchExpression{value: val, isSet: true}
}

func (v NullableV1MatchExpression) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableV1MatchExpression) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
