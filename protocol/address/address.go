// Package address defines the structure of a device address.
package address

import "fmt"

// DeviceID represents a unique device identifier.
type DeviceID uint32

// Address represents a unique address used by the protocol.
type Address struct {
	Name     string
	DeviceID DeviceID
}

func (a Address) String() string {
	return fmt.Sprintf("%s.%d", a.Name, a.DeviceID)
}
