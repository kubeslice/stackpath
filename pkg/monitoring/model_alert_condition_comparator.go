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
	EQUAL AlertConditionComparator = "EQUAL"
	NOT_EQUAL AlertConditionComparator = "NOT_EQUAL"
	GREATER_THAN AlertConditionComparator = "GREATER_THAN"
	GREATER_THAN_EQUAL_TO AlertConditionComparator = "GREATER_THAN_EQUAL_TO"
	LESS_THAN AlertConditionComparator = "LESS_THAN"
	LESS_THAN_EQUAL_TO AlertConditionComparator = "LESS_THAN_EQUAL_TO"
	DOES_EXIST AlertConditionComparator = "DOES_EXIST"
	DOES_NOT_EXIST AlertConditionComparator = "DOES_NOT_EXIST"
	REGEX AlertConditionComparator = "REGEX"
	DOES_NOT_REGEX AlertConditionComparator = "DOES_NOT_REGEX"
	CONTAINS AlertConditionComparator = "CONTAINS"
	DOES_NOT_CONTAIN AlertConditionComparator = "DOES_NOT_CONTAIN"
)
