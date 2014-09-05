// Package whitelist implements IP whitelisting for various types
// of connections.
package whitelist

import (
	"errors"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
)

// An ACL stores a list of permitted IP addresses, and handles
// concurrency as needed.
type ACL interface {
	// Permitted takes an IP address, and returns true if the
	// IP address is whitelisted (e.g. permitted access).
	Permitted(net.IP) bool

	// Add takes an IP address and adds it to the whitelist so
	// that it is now permitted.
	Add(net.IP)

	// Remove takes an IP address and drops it from the whitelist
	// so that it is no longer permitted.
	Remove(net.IP)
}

func validIP(ip net.IP) bool {
	if len(ip) == 4 {
		return true
	}

	if len(ip) == 16 {
		return true
	}

	return false
}

// Basic implements a basic map-backed whitelister that uses an
// RWMutex for conccurency. IPv4 addresses are treated differently
// than an IPv6 address; namely, the IPv4 localhost will not match
// the IPv6 localhost.
type Basic struct {
	lock   sync.RWMutex
	ipList map[string]bool
}

// Permitted returns true if the IP has been whitelisted.
func (wl *Basic) Permitted(ip net.IP) bool {
	if !validIP(ip) {
		return false
	}

	wl.lock.RLock()
	defer wl.lock.RUnlock()
	return wl.ipList[ip.String()]
}

// Add whitelists an IP.
func (wl *Basic) Add(ip net.IP) {
	if !validIP(ip) {
		return
	}

	wl.lock.Lock()
	defer wl.lock.Unlock()
	wl.ipList[ip.String()] = true
}

// Remove clears the IP from the whitelist.
func (wl *Basic) Remove(ip net.IP) {
	if !validIP(ip) {
		return
	}

	wl.lock.Lock()
	defer wl.lock.Unlock()
	delete(wl.ipList, ip.String())
}

// NewBasic returns a new initialised basic whitelist.
func NewBasic() *Basic {
	return &Basic{
		ipList: map[string]bool{},
	}
}

// DumpBasic returns a whitelist as a byte slice where each IP is on
// its own line.
func DumpBasic(wl *Basic) []byte {
	wl.lock.RLock()
	defer wl.lock.RUnlock()

	var addrs = make([]string, 0, len(wl.ipList))
	for ip := range wl.ipList {
		addrs = append(addrs, ip)
	}

	sort.Strings(addrs)

	addrList := strings.Join(addrs, "\n")
	return []byte(addrList)
}

// LoadBasic loads a whitelist from a byteslice.
func LoadBasic(in []byte) (*Basic, error) {
	wl := NewBasic()
	addrs := strings.Split(string(in), "\n")

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, errors.New("whitelist: invalid address")
		}
		wl.Add(ip)
	}
	return wl, nil
}

// Stub allows whitelisting to be added into a system's flow
// without doing anything yet. All operations result in warning log
// messages being printed to stderr. There is no mechanism for
// squelching these messages short of modifying the log package's
// default logger.
type Stub struct{}

// Permitted always returns true, but prints a warning message alerting
// that whitelisting is stubbed.
func (wl *Stub) Permitted(ip net.IP) bool {
	log.Printf("WARNING: whitelist check for %s but whitelisting is stubbed", ip)
	return true
}

// Add prints a warning message about whitelisting being stubbed.
func (wl *Stub) Add(ip net.IP) {
	log.Printf("WARNING: IP %s added to whitelist but whitelisting is stubbed", ip)
}

// Remove prints a warning message about whitelisting being stubbed.
func (wl *Stub) Remove(ip net.IP) {
	log.Printf("WARNING: IP %s removed from whitelist but whitelisting is stubbed", ip)
}

// NewStub returns a new stubbed whitelister.
func NewStub() *Stub {
	log.Println("WARNING: whitelisting is being stubbed")
	return &Stub{}
}
