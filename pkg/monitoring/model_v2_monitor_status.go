/*
 * Monitoring
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package monitoring
// V2MonitorStatus The status of a monitor  - UNKNOWN: Unable to determine the status of the service being monitored. This is likely due to a new monitor that has not been checked yet.  - UP: The status of the service being monitored is up.  - DOWN: The status of the service being monitored is down.  - SLOW: The status of the service being monitored is slow. A service with a slow status means the service is up but responses are taking longer than 500 milliseconds.
type V2MonitorStatus string

// List of v2MonitorStatus
const (
	UNKNOWN V2MonitorStatus = "UNKNOWN"
	UP V2MonitorStatus = "UP"
	DOWN V2MonitorStatus = "DOWN"
	SLOW V2MonitorStatus = "SLOW"
)
