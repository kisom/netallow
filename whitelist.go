// Package whitelist implements IP whitelisting for various types
// of connections.
package whitelist

import (
	"net"
	"sync"
)

// A Whitelist stores a list of permitted IP addresses, and handles
// concurrency as needed.
type Whitelist interface {
	Permitted(net.IP) bool
	Add(net.IP)
	Remove(net.IP)
}

// A BasicWhitelist is a basic map-backed whitelister that uses an
// RWMutex for conccurency. IPv4 addresses are treated differently
// than an IPv6 address; namely, the IPv4 localhost will not match
// the IPv6 localhost.
type BasicWhitelist struct {
	sync.RWMutex
	ipList map[string]bool
}

// Permitted returns true if the IP has been whitelisted.
func (wl *BasicWhitelist) Permitted(ip net.IP) bool {
	wl.RLock()
	defer wl.RUnlock()
	return wl.ipList[ip.String()]
}

// Add whitelists an IP.
func (wl *BasicWhitelist) Add(ip net.IP) {
	wl.Lock()
	defer wl.Unlock()
	wl.ipList[ip.String()] = true
}

// Remove clears the IP from the whitelist.
func (wl *BasicWhitelist) Remove(ip net.IP) {
	wl.Lock()
	defer wl.Unlock()
	delete(wl.ipList, ip.String())
}

func NewBasic() *BasicWhitelist {
	return &BasicWhitelist{
		ipList: map[string]bool{},
	}
}
