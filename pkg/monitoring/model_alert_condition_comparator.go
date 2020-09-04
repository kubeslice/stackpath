/*
 * Monitoring
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package monitoring
// AlertConditionComparator How to compare the alert condition metric to the value.   - EQUAL: The metric equals the value.  - NOT_EQUAL: The metric does not equal the value.  - GREATER_THAN: The metric is greater than the value.  - GREATER_THAN_EQUAL_TO: The metric is greater than or equal to the value.  - LESS_THAN: The metric is less than the value.  - LESS_THAN_EQUAL_TO: The metric is less than or equal to the value.  - DOES_EXIST: The value of the metric exists.  - DOES_NOT_EXIST: The value of the metric does not exist.  - REGEX: A result is produced when the metric is applied to the regular expression value.  - DOES_NOT_REGEX: No result is produced when the metric is applied to the regular expression value.  - CONTAINS: The metric contains the value.  - DOES_NOT_CONTAIN: The metric does not contain the value.
type AlertConditionComparator string

// List of AlertConditionComparator
const (
	ALERTCONDITIONCOMPARATOR_EQUAL AlertConditionComparator = "EQUAL"
	ALERTCONDITIONCOMPARATOR_NOT_EQUAL AlertConditionComparator = "NOT_EQUAL"
	ALERTCONDITIONCOMPARATOR_GREATER_THAN AlertConditionComparator = "GREATER_THAN"
	ALERTCONDITIONCOMPARATOR_GREATER_THAN_EQUAL_TO AlertConditionComparator = "GREATER_THAN_EQUAL_TO"
	ALERTCONDITIONCOMPARATOR_LESS_THAN AlertConditionComparator = "LESS_THAN"
	ALERTCONDITIONCOMPARATOR_LESS_THAN_EQUAL_TO AlertConditionComparator = "LESS_THAN_EQUAL_TO"
	ALERTCONDITIONCOMPARATOR_DOES_EXIST AlertConditionComparator = "DOES_EXIST"
	ALERTCONDITIONCOMPARATOR_DOES_NOT_EXIST AlertConditionComparator = "DOES_NOT_EXIST"
	ALERTCONDITIONCOMPARATOR_REGEX AlertConditionComparator = "REGEX"
	ALERTCONDITIONCOMPARATOR_DOES_NOT_REGEX AlertConditionComparator = "DOES_NOT_REGEX"
	ALERTCONDITIONCOMPARATOR_CONTAINS AlertConditionComparator = "CONTAINS"
	ALERTCONDITIONCOMPARATOR_DOES_NOT_CONTAIN AlertConditionComparator = "DOES_NOT_CONTAIN"
)
