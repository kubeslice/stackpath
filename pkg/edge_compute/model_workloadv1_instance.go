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
	"time"
)

// Workloadv1Instance An instance of a workload deployment
type Workloadv1Instance struct {
	// The ID of the stack that an instance belongs to
	StackId *string `json:"stackId,omitempty"`
	// The ID of the workload that an instance belongs to
	WorkloadId *string `json:"workloadId,omitempty"`
	// An instance's unique identifier
	Id *string `json:"id,omitempty"`
	// An instance's name  Instance names are generated from their corresponsing workload's slug, followed by a unique hash
	Name *string `json:"name,omitempty"`
	Metadata *V1Metadata `json:"metadata,omitempty"`
	Location *Workloadv1Location `json:"location,omitempty"`
	Phase *Workloadv1InstanceInstancePhase `json:"phase,omitempty"`
	// An instance's IP address
	IpAddress *string `json:"ipAddress,omitempty"`
	// An instance's publicly accessible IP address
	ExternalIpAddress *string `json:"externalIpAddress,omitempty"`
	// The date an instance was created
	CreatedAt *time.Time `json:"createdAt,omitempty"`
	// The date an instance was started
	StartedAt *time.Time `json:"startedAt,omitempty"`
	// The date an instance was deleted
	DeletedAt *time.Time `json:"deletedAt,omitempty"`
	// An instance's network interfaces
	NetworkInterfaces *[]Workloadv1NetworkInterfaceStatus `json:"networkInterfaces,omitempty"`
	Resources *V1ResourceRequirements `json:"resources,omitempty"`
	// A string to container configuration key/value pair
	Containers *map[string]V1ContainerSpec `json:"containers,omitempty"`
	// Status of the containers running within the workload instance
	ContainerStatuses *[]V1ContainerStatus `json:"containerStatuses,omitempty"`
	// A string to virtual machine configuration key/value pair
	VirtualMachines *map[string]V1VirtualMachineSpec `json:"virtualMachines,omitempty"`
	// The status of the virtual machines running within the workload instance
	VirtualMachineStatuses *[]V1VirtualMachineStatus `json:"virtualMachineStatuses,omitempty"`
	// A short reason that explains why an instance is in a phase
	Reason *string `json:"reason,omitempty"`
	// A longer message that provides more detail on why an instance is in a phase
	Message *string `json:"message,omitempty"`
	// The date an instance was scheduled
	ScheduledAt *time.Time `json:"scheduledAt,omitempty"`
}

// NewWorkloadv1Instance instantiates a new Workloadv1Instance object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewWorkloadv1Instance() *Workloadv1Instance {
	this := Workloadv1Instance{}
	var phase Workloadv1InstanceInstancePhase = "INSTANCE_PHASE_UNSPECIFIED"
	this.Phase = &phase
	return &this
}

// NewWorkloadv1InstanceWithDefaults instantiates a new Workloadv1Instance object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewWorkloadv1InstanceWithDefaults() *Workloadv1Instance {
	this := Workloadv1Instance{}
	var phase Workloadv1InstanceInstancePhase = "INSTANCE_PHASE_UNSPECIFIED"
	this.Phase = &phase
	return &this
}

// GetStackId returns the StackId field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetStackId() string {
	if o == nil || o.StackId == nil {
		var ret string
		return ret
	}
	return *o.StackId
}

// GetStackIdOk returns a tuple with the StackId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetStackIdOk() (*string, bool) {
	if o == nil || o.StackId == nil {
		return nil, false
	}
	return o.StackId, true
}

// HasStackId returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasStackId() bool {
	if o != nil && o.StackId != nil {
		return true
	}

	return false
}

// SetStackId gets a reference to the given string and assigns it to the StackId field.
func (o *Workloadv1Instance) SetStackId(v string) {
	o.StackId = &v
}

// GetWorkloadId returns the WorkloadId field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetWorkloadId() string {
	if o == nil || o.WorkloadId == nil {
		var ret string
		return ret
	}
	return *o.WorkloadId
}

// GetWorkloadIdOk returns a tuple with the WorkloadId field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetWorkloadIdOk() (*string, bool) {
	if o == nil || o.WorkloadId == nil {
		return nil, false
	}
	return o.WorkloadId, true
}

// HasWorkloadId returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasWorkloadId() bool {
	if o != nil && o.WorkloadId != nil {
		return true
	}

	return false
}

// SetWorkloadId gets a reference to the given string and assigns it to the WorkloadId field.
func (o *Workloadv1Instance) SetWorkloadId(v string) {
	o.WorkloadId = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetId() string {
	if o == nil || o.Id == nil {
		var ret string
		return ret
	}
	return *o.Id
}

// GetIdOk returns a tuple with the Id field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetIdOk() (*string, bool) {
	if o == nil || o.Id == nil {
		return nil, false
	}
	return o.Id, true
}

// HasId returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasId() bool {
	if o != nil && o.Id != nil {
		return true
	}

	return false
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *Workloadv1Instance) SetId(v string) {
	o.Id = &v
}

// GetName returns the Name field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetName() string {
	if o == nil || o.Name == nil {
		var ret string
		return ret
	}
	return *o.Name
}

// GetNameOk returns a tuple with the Name field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetNameOk() (*string, bool) {
	if o == nil || o.Name == nil {
		return nil, false
	}
	return o.Name, true
}

// HasName returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasName() bool {
	if o != nil && o.Name != nil {
		return true
	}

	return false
}

// SetName gets a reference to the given string and assigns it to the Name field.
func (o *Workloadv1Instance) SetName(v string) {
	o.Name = &v
}

// GetMetadata returns the Metadata field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetMetadata() V1Metadata {
	if o == nil || o.Metadata == nil {
		var ret V1Metadata
		return ret
	}
	return *o.Metadata
}

// GetMetadataOk returns a tuple with the Metadata field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetMetadataOk() (*V1Metadata, bool) {
	if o == nil || o.Metadata == nil {
		return nil, false
	}
	return o.Metadata, true
}

// HasMetadata returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasMetadata() bool {
	if o != nil && o.Metadata != nil {
		return true
	}

	return false
}

// SetMetadata gets a reference to the given V1Metadata and assigns it to the Metadata field.
func (o *Workloadv1Instance) SetMetadata(v V1Metadata) {
	o.Metadata = &v
}

// GetLocation returns the Location field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetLocation() Workloadv1Location {
	if o == nil || o.Location == nil {
		var ret Workloadv1Location
		return ret
	}
	return *o.Location
}

// GetLocationOk returns a tuple with the Location field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetLocationOk() (*Workloadv1Location, bool) {
	if o == nil || o.Location == nil {
		return nil, false
	}
	return o.Location, true
}

// HasLocation returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasLocation() bool {
	if o != nil && o.Location != nil {
		return true
	}

	return false
}

// SetLocation gets a reference to the given Workloadv1Location and assigns it to the Location field.
func (o *Workloadv1Instance) SetLocation(v Workloadv1Location) {
	o.Location = &v
}

// GetPhase returns the Phase field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetPhase() Workloadv1InstanceInstancePhase {
	if o == nil || o.Phase == nil {
		var ret Workloadv1InstanceInstancePhase
		return ret
	}
	return *o.Phase
}

// GetPhaseOk returns a tuple with the Phase field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetPhaseOk() (*Workloadv1InstanceInstancePhase, bool) {
	if o == nil || o.Phase == nil {
		return nil, false
	}
	return o.Phase, true
}

// HasPhase returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasPhase() bool {
	if o != nil && o.Phase != nil {
		return true
	}

	return false
}

// SetPhase gets a reference to the given Workloadv1InstanceInstancePhase and assigns it to the Phase field.
func (o *Workloadv1Instance) SetPhase(v Workloadv1InstanceInstancePhase) {
	o.Phase = &v
}

// GetIpAddress returns the IpAddress field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetIpAddress() string {
	if o == nil || o.IpAddress == nil {
		var ret string
		return ret
	}
	return *o.IpAddress
}

// GetIpAddressOk returns a tuple with the IpAddress field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetIpAddressOk() (*string, bool) {
	if o == nil || o.IpAddress == nil {
		return nil, false
	}
	return o.IpAddress, true
}

// HasIpAddress returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasIpAddress() bool {
	if o != nil && o.IpAddress != nil {
		return true
	}

	return false
}

// SetIpAddress gets a reference to the given string and assigns it to the IpAddress field.
func (o *Workloadv1Instance) SetIpAddress(v string) {
	o.IpAddress = &v
}

// GetExternalIpAddress returns the ExternalIpAddress field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetExternalIpAddress() string {
	if o == nil || o.ExternalIpAddress == nil {
		var ret string
		return ret
	}
	return *o.ExternalIpAddress
}

// GetExternalIpAddressOk returns a tuple with the ExternalIpAddress field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetExternalIpAddressOk() (*string, bool) {
	if o == nil || o.ExternalIpAddress == nil {
		return nil, false
	}
	return o.ExternalIpAddress, true
}

// HasExternalIpAddress returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasExternalIpAddress() bool {
	if o != nil && o.ExternalIpAddress != nil {
		return true
	}

	return false
}

// SetExternalIpAddress gets a reference to the given string and assigns it to the ExternalIpAddress field.
func (o *Workloadv1Instance) SetExternalIpAddress(v string) {
	o.ExternalIpAddress = &v
}

// GetCreatedAt returns the CreatedAt field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetCreatedAt() time.Time {
	if o == nil || o.CreatedAt == nil {
		var ret time.Time
		return ret
	}
	return *o.CreatedAt
}

// GetCreatedAtOk returns a tuple with the CreatedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetCreatedAtOk() (*time.Time, bool) {
	if o == nil || o.CreatedAt == nil {
		return nil, false
	}
	return o.CreatedAt, true
}

// HasCreatedAt returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasCreatedAt() bool {
	if o != nil && o.CreatedAt != nil {
		return true
	}

	return false
}

// SetCreatedAt gets a reference to the given time.Time and assigns it to the CreatedAt field.
func (o *Workloadv1Instance) SetCreatedAt(v time.Time) {
	o.CreatedAt = &v
}

// GetStartedAt returns the StartedAt field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetStartedAt() time.Time {
	if o == nil || o.StartedAt == nil {
		var ret time.Time
		return ret
	}
	return *o.StartedAt
}

// GetStartedAtOk returns a tuple with the StartedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetStartedAtOk() (*time.Time, bool) {
	if o == nil || o.StartedAt == nil {
		return nil, false
	}
	return o.StartedAt, true
}

// HasStartedAt returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasStartedAt() bool {
	if o != nil && o.StartedAt != nil {
		return true
	}

	return false
}

// SetStartedAt gets a reference to the given time.Time and assigns it to the StartedAt field.
func (o *Workloadv1Instance) SetStartedAt(v time.Time) {
	o.StartedAt = &v
}

// GetDeletedAt returns the DeletedAt field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetDeletedAt() time.Time {
	if o == nil || o.DeletedAt == nil {
		var ret time.Time
		return ret
	}
	return *o.DeletedAt
}

// GetDeletedAtOk returns a tuple with the DeletedAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetDeletedAtOk() (*time.Time, bool) {
	if o == nil || o.DeletedAt == nil {
		return nil, false
	}
	return o.DeletedAt, true
}

// HasDeletedAt returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasDeletedAt() bool {
	if o != nil && o.DeletedAt != nil {
		return true
	}

	return false
}

// SetDeletedAt gets a reference to the given time.Time and assigns it to the DeletedAt field.
func (o *Workloadv1Instance) SetDeletedAt(v time.Time) {
	o.DeletedAt = &v
}

// GetNetworkInterfaces returns the NetworkInterfaces field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetNetworkInterfaces() []Workloadv1NetworkInterfaceStatus {
	if o == nil || o.NetworkInterfaces == nil {
		var ret []Workloadv1NetworkInterfaceStatus
		return ret
	}
	return *o.NetworkInterfaces
}

// GetNetworkInterfacesOk returns a tuple with the NetworkInterfaces field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetNetworkInterfacesOk() (*[]Workloadv1NetworkInterfaceStatus, bool) {
	if o == nil || o.NetworkInterfaces == nil {
		return nil, false
	}
	return o.NetworkInterfaces, true
}

// HasNetworkInterfaces returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasNetworkInterfaces() bool {
	if o != nil && o.NetworkInterfaces != nil {
		return true
	}

	return false
}

// SetNetworkInterfaces gets a reference to the given []Workloadv1NetworkInterfaceStatus and assigns it to the NetworkInterfaces field.
func (o *Workloadv1Instance) SetNetworkInterfaces(v []Workloadv1NetworkInterfaceStatus) {
	o.NetworkInterfaces = &v
}

// GetResources returns the Resources field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetResources() V1ResourceRequirements {
	if o == nil || o.Resources == nil {
		var ret V1ResourceRequirements
		return ret
	}
	return *o.Resources
}

// GetResourcesOk returns a tuple with the Resources field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetResourcesOk() (*V1ResourceRequirements, bool) {
	if o == nil || o.Resources == nil {
		return nil, false
	}
	return o.Resources, true
}

// HasResources returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasResources() bool {
	if o != nil && o.Resources != nil {
		return true
	}

	return false
}

// SetResources gets a reference to the given V1ResourceRequirements and assigns it to the Resources field.
func (o *Workloadv1Instance) SetResources(v V1ResourceRequirements) {
	o.Resources = &v
}

// GetContainers returns the Containers field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetContainers() map[string]V1ContainerSpec {
	if o == nil || o.Containers == nil {
		var ret map[string]V1ContainerSpec
		return ret
	}
	return *o.Containers
}

// GetContainersOk returns a tuple with the Containers field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetContainersOk() (*map[string]V1ContainerSpec, bool) {
	if o == nil || o.Containers == nil {
		return nil, false
	}
	return o.Containers, true
}

// HasContainers returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasContainers() bool {
	if o != nil && o.Containers != nil {
		return true
	}

	return false
}

// SetContainers gets a reference to the given map[string]V1ContainerSpec and assigns it to the Containers field.
func (o *Workloadv1Instance) SetContainers(v map[string]V1ContainerSpec) {
	o.Containers = &v
}

// GetContainerStatuses returns the ContainerStatuses field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetContainerStatuses() []V1ContainerStatus {
	if o == nil || o.ContainerStatuses == nil {
		var ret []V1ContainerStatus
		return ret
	}
	return *o.ContainerStatuses
}

// GetContainerStatusesOk returns a tuple with the ContainerStatuses field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetContainerStatusesOk() (*[]V1ContainerStatus, bool) {
	if o == nil || o.ContainerStatuses == nil {
		return nil, false
	}
	return o.ContainerStatuses, true
}

// HasContainerStatuses returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasContainerStatuses() bool {
	if o != nil && o.ContainerStatuses != nil {
		return true
	}

	return false
}

// SetContainerStatuses gets a reference to the given []V1ContainerStatus and assigns it to the ContainerStatuses field.
func (o *Workloadv1Instance) SetContainerStatuses(v []V1ContainerStatus) {
	o.ContainerStatuses = &v
}

// GetVirtualMachines returns the VirtualMachines field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetVirtualMachines() map[string]V1VirtualMachineSpec {
	if o == nil || o.VirtualMachines == nil {
		var ret map[string]V1VirtualMachineSpec
		return ret
	}
	return *o.VirtualMachines
}

// GetVirtualMachinesOk returns a tuple with the VirtualMachines field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetVirtualMachinesOk() (*map[string]V1VirtualMachineSpec, bool) {
	if o == nil || o.VirtualMachines == nil {
		return nil, false
	}
	return o.VirtualMachines, true
}

// HasVirtualMachines returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasVirtualMachines() bool {
	if o != nil && o.VirtualMachines != nil {
		return true
	}

	return false
}

// SetVirtualMachines gets a reference to the given map[string]V1VirtualMachineSpec and assigns it to the VirtualMachines field.
func (o *Workloadv1Instance) SetVirtualMachines(v map[string]V1VirtualMachineSpec) {
	o.VirtualMachines = &v
}

// GetVirtualMachineStatuses returns the VirtualMachineStatuses field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetVirtualMachineStatuses() []V1VirtualMachineStatus {
	if o == nil || o.VirtualMachineStatuses == nil {
		var ret []V1VirtualMachineStatus
		return ret
	}
	return *o.VirtualMachineStatuses
}

// GetVirtualMachineStatusesOk returns a tuple with the VirtualMachineStatuses field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetVirtualMachineStatusesOk() (*[]V1VirtualMachineStatus, bool) {
	if o == nil || o.VirtualMachineStatuses == nil {
		return nil, false
	}
	return o.VirtualMachineStatuses, true
}

// HasVirtualMachineStatuses returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasVirtualMachineStatuses() bool {
	if o != nil && o.VirtualMachineStatuses != nil {
		return true
	}

	return false
}

// SetVirtualMachineStatuses gets a reference to the given []V1VirtualMachineStatus and assigns it to the VirtualMachineStatuses field.
func (o *Workloadv1Instance) SetVirtualMachineStatuses(v []V1VirtualMachineStatus) {
	o.VirtualMachineStatuses = &v
}

// GetReason returns the Reason field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetReason() string {
	if o == nil || o.Reason == nil {
		var ret string
		return ret
	}
	return *o.Reason
}

// GetReasonOk returns a tuple with the Reason field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetReasonOk() (*string, bool) {
	if o == nil || o.Reason == nil {
		return nil, false
	}
	return o.Reason, true
}

// HasReason returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasReason() bool {
	if o != nil && o.Reason != nil {
		return true
	}

	return false
}

// SetReason gets a reference to the given string and assigns it to the Reason field.
func (o *Workloadv1Instance) SetReason(v string) {
	o.Reason = &v
}

// GetMessage returns the Message field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetMessage() string {
	if o == nil || o.Message == nil {
		var ret string
		return ret
	}
	return *o.Message
}

// GetMessageOk returns a tuple with the Message field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetMessageOk() (*string, bool) {
	if o == nil || o.Message == nil {
		return nil, false
	}
	return o.Message, true
}

// HasMessage returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasMessage() bool {
	if o != nil && o.Message != nil {
		return true
	}

	return false
}

// SetMessage gets a reference to the given string and assigns it to the Message field.
func (o *Workloadv1Instance) SetMessage(v string) {
	o.Message = &v
}

// GetScheduledAt returns the ScheduledAt field value if set, zero value otherwise.
func (o *Workloadv1Instance) GetScheduledAt() time.Time {
	if o == nil || o.ScheduledAt == nil {
		var ret time.Time
		return ret
	}
	return *o.ScheduledAt
}

// GetScheduledAtOk returns a tuple with the ScheduledAt field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *Workloadv1Instance) GetScheduledAtOk() (*time.Time, bool) {
	if o == nil || o.ScheduledAt == nil {
		return nil, false
	}
	return o.ScheduledAt, true
}

// HasScheduledAt returns a boolean if a field has been set.
func (o *Workloadv1Instance) HasScheduledAt() bool {
	if o != nil && o.ScheduledAt != nil {
		return true
	}

	return false
}

// SetScheduledAt gets a reference to the given time.Time and assigns it to the ScheduledAt field.
func (o *Workloadv1Instance) SetScheduledAt(v time.Time) {
	o.ScheduledAt = &v
}

func (o Workloadv1Instance) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.StackId != nil {
		toSerialize["stackId"] = o.StackId
	}
	if o.WorkloadId != nil {
		toSerialize["workloadId"] = o.WorkloadId
	}
	if o.Id != nil {
		toSerialize["id"] = o.Id
	}
	if o.Name != nil {
		toSerialize["name"] = o.Name
	}
	if o.Metadata != nil {
		toSerialize["metadata"] = o.Metadata
	}
	if o.Location != nil {
		toSerialize["location"] = o.Location
	}
	if o.Phase != nil {
		toSerialize["phase"] = o.Phase
	}
	if o.IpAddress != nil {
		toSerialize["ipAddress"] = o.IpAddress
	}
	if o.ExternalIpAddress != nil {
		toSerialize["externalIpAddress"] = o.ExternalIpAddress
	}
	if o.CreatedAt != nil {
		toSerialize["createdAt"] = o.CreatedAt
	}
	if o.StartedAt != nil {
		toSerialize["startedAt"] = o.StartedAt
	}
	if o.DeletedAt != nil {
		toSerialize["deletedAt"] = o.DeletedAt
	}
	if o.NetworkInterfaces != nil {
		toSerialize["networkInterfaces"] = o.NetworkInterfaces
	}
	if o.Resources != nil {
		toSerialize["resources"] = o.Resources
	}
	if o.Containers != nil {
		toSerialize["containers"] = o.Containers
	}
	if o.ContainerStatuses != nil {
		toSerialize["containerStatuses"] = o.ContainerStatuses
	}
	if o.VirtualMachines != nil {
		toSerialize["virtualMachines"] = o.VirtualMachines
	}
	if o.VirtualMachineStatuses != nil {
		toSerialize["virtualMachineStatuses"] = o.VirtualMachineStatuses
	}
	if o.Reason != nil {
		toSerialize["reason"] = o.Reason
	}
	if o.Message != nil {
		toSerialize["message"] = o.Message
	}
	if o.ScheduledAt != nil {
		toSerialize["scheduledAt"] = o.ScheduledAt
	}
	return json.Marshal(toSerialize)
}

type NullableWorkloadv1Instance struct {
	value *Workloadv1Instance
	isSet bool
}

func (v NullableWorkloadv1Instance) Get() *Workloadv1Instance {
	return v.value
}

func (v *NullableWorkloadv1Instance) Set(val *Workloadv1Instance) {
	v.value = val
	v.isSet = true
}

func (v NullableWorkloadv1Instance) IsSet() bool {
	return v.isSet
}

func (v *NullableWorkloadv1Instance) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableWorkloadv1Instance(val *Workloadv1Instance) *NullableWorkloadv1Instance {
	return &NullableWorkloadv1Instance{value: val, isSet: true}
}

func (v NullableWorkloadv1Instance) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableWorkloadv1Instance) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
