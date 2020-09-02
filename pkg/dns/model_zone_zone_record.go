/*
 * DNS
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package dns
import (
	"time"
)
// ZoneZoneRecord A DNS zone's resource record  A zone record describes an individual piece of DNS functionality in a DNS zone.
type ZoneZoneRecord struct {
	// A zone record's unique ID
	Id string `json:"id,omitempty"`
	// The ID of the zone that a zone record belongs to
	ZoneId string `json:"zoneId,omitempty"`
	// A zone record's name  Use the value \"@\" to denote current root domain name.
	Name string `json:"name,omitempty"`
	// A zone record's type  Zone record types describe the zone record's behavior. For instance, a zone record's type can say that the record is a name to IP address value, a name alias, or which mail exchanger is responsible for the domain. See https://support.stackpath.com/hc/en-us/articles/360001085563-What-DNS-record-types-does-StackPath-support for more information.
	Type string `json:"type,omitempty"`
	// A zone record's class code  This is typically \"IN\" for Internet related resource records.
	Class string `json:"class,omitempty"`
	// A zone record's time to live  A record's TTL is the number of seconds that the record should be cached by DNS resolvers. Use lower TTL values if you expect zone records to change often. Use higher TTL values for records that won't change to prevent extra DNS lookups by clients.
	Ttl int32 `json:"ttl,omitempty"`
	// A zone record's value  Expected data formats can vary depending on the zone record's type.
	Data string `json:"data,omitempty"`
	// A zone record's priority  A resource record is replicated in StackPath's DNS infrastructure the number of times of the record's weight, giving it a more likely response to queries if a zone has records with the same name and type.
	Weight int32 `json:"weight,omitempty"`
	// A key/value pair of user-defined labels for a zone record  Zone record labels are not processed by StackPath and are solely used for users to organize their DNS zones.
	Labels map[string]string `json:"labels,omitempty"`
	// The date a zone record was created
	Created time.Time `json:"created,omitempty"`
	// The date a zone record was last updated
	Updated time.Time `json:"updated,omitempty"`
}
