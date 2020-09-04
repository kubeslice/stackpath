/*
 * Edge Compute
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package edge_compute
// V1ContainerStatusContainerPhase Which phase of runtime a container is currently in  - CONTAINER_PHASE_UNSPECIFIED: The container has not reported a state back or StackPath is unable to determine the container's state  - STARTING: The container is starting up  - RUNNING: The container is running  - FAILED: The container has terminated due to a failure  - STOPPED: The container was terminated by the user
type V1ContainerStatusContainerPhase string

// List of v1ContainerStatusContainerPhase
const (
	V1CONTAINERSTATUSCONTAINERPHASE_CONTAINER_PHASE_UNSPECIFIED V1ContainerStatusContainerPhase = "CONTAINER_PHASE_UNSPECIFIED"
	V1CONTAINERSTATUSCONTAINERPHASE_STARTING V1ContainerStatusContainerPhase = "STARTING"
	V1CONTAINERSTATUSCONTAINERPHASE_RUNNING V1ContainerStatusContainerPhase = "RUNNING"
	V1CONTAINERSTATUSCONTAINERPHASE_FAILED V1ContainerStatusContainerPhase = "FAILED"
	V1CONTAINERSTATUSCONTAINERPHASE_STOPPED V1ContainerStatusContainerPhase = "STOPPED"
)
