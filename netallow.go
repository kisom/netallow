// Package netallow implements IP access control lists (ACLS) for various
// types of connections. Two types of ACLs are supported: host-based and
// network-based.
package netallow

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
	// IP address is permitted access.
	Permitted(net.IP) bool
}

// A HostACL stores a list of permitted hosts.
type HostACL interface {
	ACL

	// Add takes an IP address and adds it to the allowed so
	// that it is now permitted.
	Add(net.IP)

	// Remove takes an IP address and drops it from the allowed
	// so that it is no longer permitted.
	Remove(net.IP)
}

// validIP takes an IP address (which is implemented as a byte slice)
// and ensures that it is a possible address. Right now, this means
// just doing length checks.
func validIP(ip net.IP) bool {
	if len(ip) == 4 {
		return true
	}

	if len(ip) == 16 {
		return true
	}

	return false
}

// Basic implements a basic map-backed ACL that uses an RWMutex for
// concurrency. IPv4 addresses are treated differently than an IPv6
// address; namely, the IPv4 localhost will not match the IPv6 localhost.
type Basic struct {
	lock    *sync.Mutex
	allowed map[string]bool
}

// Permitted returns true if the IP is allowed access.
func (acl *Basic) Permitted(ip net.IP) bool {
	if !validIP(ip) {
		return false
	}

	acl.lock.Lock()
	permitted := acl.allowed[ip.String()]
	acl.lock.Unlock()
	return permitted
}

// Add will permit access to the IP.
func (acl *Basic) Add(ip net.IP) {
	if !validIP(ip) {
		return
	}

	acl.lock.Lock()
	defer acl.lock.Unlock()
	acl.allowed[ip.String()] = true
}

// Remove removes access by the ip.
func (acl *Basic) Remove(ip net.IP) {
	if !validIP(ip) {
		return
	}

	acl.lock.Lock()
	defer acl.lock.Unlock()
	delete(acl.allowed, ip.String())
}

// NewBasic returns a new initialised basic ACL allowed.
func NewBasic() *Basic {
	return &Basic{
		lock:    new(sync.Mutex),
		allowed: map[string]bool{},
	}
}

// MarshalJSON serialises a host allowed to a comma-separated list of
// hosts, implementing the json.Marshaler interface.
func (acl *Basic) MarshalJSON() ([]byte, error) {
	acl.lock.Lock()
	defer acl.lock.Unlock()
	var ss = make([]string, 0, len(acl.allowed))
	for ip := range acl.allowed {
		ss = append(ss, ip)
	}

	out := []byte(`"` + strings.Join(ss, ",") + `"`)
	return out, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface for host
// ACLs, taking a comma-separated string of hosts.
func (acl *Basic) UnmarshalJSON(in []byte) error {
	if in[0] != '"' || in[len(in)-1] != '"' {
		return errors.New("allowed: invalid allowed")
	}

	if acl.lock == nil {
		acl.lock = new(sync.Mutex)
	}

	acl.lock.Lock()
	defer acl.lock.Unlock()

	netString := strings.TrimSpace(string(in[1 : len(in)-1]))
	nets := strings.Split(netString, ",")

	acl.allowed = map[string]bool{}
	for i := range nets {
		addr := strings.TrimSpace(nets[i])
		if addr == "" {
			continue
		}

		ip := net.ParseIP(addr)
		if ip == nil {
			acl.allowed = nil
			return errors.New("netallow: invalid IP address " + addr)
		}
		acl.allowed[addr] = true
	}

	return nil
}

// DumpBasic returns a allowed as a byte slice where each IP is on
// its own line.
func DumpBasic(acl *Basic) []byte {
	acl.lock.Lock()
	defer acl.lock.Unlock()

	var addrs = make([]string, 0, len(acl.allowed))
	for ip := range acl.allowed {
		addrs = append(addrs, ip)
	}

	sort.Strings(addrs)

	addrList := strings.Join(addrs, "\n")
	return []byte(addrList)
}

// LoadBasic loads a allowed from a byteslice.
func LoadBasic(in []byte) (*Basic, error) {
	acl := NewBasic()
	addrs := strings.Split(string(in), "\n")

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, errors.New("netallow: invalid address")
		}
		acl.Add(ip)
	}
	return acl, nil
}

// HostStub allows host ACLs to be added into a system's flow
// without doing anything yet. All operations result in warning log
// messages being printed to stderr. There is no mechanism for
// squelching these messages short of modifying the log package's
// default logger.
type HostStub struct{}

// Permitted always returns true, but prints a warning message alerting
// that ACL checks are stubbed.
func (hs HostStub) Permitted(ip net.IP) bool {
	log.Printf("WARNING: netallow check for %s but the list is stubbed", ip)
	return true
}

// Add prints a warning message about ACL checks being stubbed.
func (hs HostStub) Add(ip net.IP) {
	log.Printf("WARNING: netallow check for %s but the list is stubbed", ip)
}

// Remove prints a warning message about ACL checks being stubbed.
func (hs HostStub) Remove(ip net.IP) {
	log.Printf("WARNING: netallow check for %s but the list is stubbed", ip)
}

// NewHostStub returns a new stubbed host ACL.
func NewHostStub() HostStub {
	log.Println("WARNING: netallow ACL is being stubbed")
	return HostStub{}
}
