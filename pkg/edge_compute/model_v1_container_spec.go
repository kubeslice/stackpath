/*
 * Edge Compute
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute
// V1ContainerSpec The specification for the desired state of a container in a workload
type V1ContainerSpec struct {
	// The location of a Docker image to run as a container
	Image string `json:"image,omitempty"`
	// The commands that start a container
	Command []string `json:"command,omitempty"`
	// A string to environment variable key/value pair
	Env map[string]V1EnvironmentVariable `json:"env,omitempty"`
	// A string to network port key/value pair
	Ports map[string]V1InstancePort `json:"ports,omitempty"`
	LivenessProbe V1Probe `json:"livenessProbe,omitempty"`
	ReadinessProbe V1Probe `json:"readinessProbe,omitempty"`
	Resources V1ResourceRequirements `json:"resources,omitempty"`
	// Volumes to mount in the container
	VolumeMounts []V1InstanceVolumeMount `json:"volumeMounts,omitempty"`
}
