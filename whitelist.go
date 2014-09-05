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

// A Whitelist stores a list of permitted IP addresses, and handles
// concurrency as needed.
type Whitelist interface {
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
	if ip == nil {
		return false
	}

	wl.RLock()
	defer wl.RUnlock()
	return wl.ipList[ip.String()]
}

// Add whitelists an IP.
func (wl *BasicWhitelist) Add(ip net.IP) {
	if ip == nil {
		return
	}

	wl.Lock()
	defer wl.Unlock()
	wl.ipList[ip.String()] = true
}

// Remove clears the IP from the whitelist.
func (wl *BasicWhitelist) Remove(ip net.IP) {
	if ip == nil {
		return
	}

	wl.Lock()
	defer wl.Unlock()
	delete(wl.ipList, ip.String())
}

// NewBasic returns a new initialised basic whitelist.
func NewBasic() *BasicWhitelist {
	return &BasicWhitelist{
		ipList: map[string]bool{},
	}
}

// DumpBasic returns a whitelist as a byte slice where each IP is on
// its own line.
func DumpBasic(wl *BasicWhitelist) []byte {
	wl.RLock()
	defer wl.RUnlock()

	var addrs []string
	for ip := range wl.ipList {
		addrs = append(addrs, ip)
	}

	sort.Strings(addrs)

	addrList := strings.Join(addrs, "\n")
	return []byte(addrList)
}

// LoadBasic loads a whitelist from a byteslice.
func LoadBasic(in []byte) (*BasicWhitelist, error) {
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

// StubWhitelist allows whitelisting to be added into a system's flow
// without doing anything yet. All operations result in warning log
// messages being printed to stderr. There is no mechanism for
// squelching these messages short of modifying the log package's
// default logger.
type StubWhitelist struct{}

// Permitted always returns true, but prints a warning message alerting
// that whitelisting is stubbed.
func (wl *StubWhitelist) Permitted(ip net.IP) bool {
	log.Printf("WARNING: whitelist check for %s but whitelisting is stubbed", ip)
	return true
}

// Add prints a warning message about whitelisting being stubbed.
func (wl *StubWhitelist) Add(ip net.IP) {
	log.Printf("WARNING: IP %s added to whitelist but whitelisting is stubbed", ip)
}

// Remove prints a warning message about whitelisting being stubbed.
func (wl *StubWhitelist) Remove(ip net.IP) {
	log.Printf("WARNING: IP %s removed from whitelist but whitelisting is stubbed", ip)
}

// NewStub returns a new stubbed whitelister.
func NewStub() *StubWhitelist {
	log.Println("WARNING: whitelisting is being stubbed")
	return &StubWhitelist{}
}
