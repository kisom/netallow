package netallow

// This file contains a variant of the ACL that operates on
// netblocks. It will mimic as much of the code in netallow.go
// that is needed to support network ACLs.

import (
	"errors"
	"log"
	"net"
	"strings"
	"sync"
)

// A NetACL stores a list of permitted IP networks.
type NetACL interface {
	ACL

	// Add takes an IP network and adds it to the ACL so
	// that it is now permitted.
	Add(*net.IPNet)

	// Remove takes an IP network and drops it from the ACL
	// so that it is no longer permitted.
	Remove(*net.IPNet)
}

// BasicNet implements a basic map-backed network allowed using
// locks for concurrency. It must be initialised with one of the
// constructor functions. This particular implementation is
// unoptimised and will not scale.
type BasicNet struct {
	lock    *sync.Mutex
	allowed []*net.IPNet
}

// Permitted returns true if the IP is permitted.
func (acl *BasicNet) Permitted(ip net.IP) bool {
	if !validIP(ip) { // see netallow.go for this function
		return false
	}

	acl.lock.Lock()
	defer acl.lock.Unlock()
	for i := range acl.allowed {
		if acl.allowed[i].Contains(ip) {
			return true
		}
	}
	return false
}

// BUG(kyle): overlapping networks aren't detected.

// Add adds a new network to the ACL. Caveat: overlapping
// networks won't be detected.
func (acl *BasicNet) Add(n *net.IPNet) {
	if n == nil {
		return
	}

	acl.lock.Lock()
	defer acl.lock.Unlock()
	acl.allowed = append(acl.allowed, n)
}

// Remove removes a network from the ACL.
func (acl *BasicNet) Remove(n *net.IPNet) {
	if n == nil {
		return
	}

	index := -1
	acl.lock.Lock()
	defer acl.lock.Unlock()
	for i := range acl.allowed {
		if acl.allowed[i].String() == n.String() {
			index = i
			break
		}
	}

	if index == -1 {
		return
	}

	acl.allowed = append(acl.allowed[:index], acl.allowed[index+1:]...)
}

// NewBasicNet constructs a new basic network-based ACL.
func NewBasicNet() *BasicNet {
	return &BasicNet{
		lock: new(sync.Mutex),
	}
}

// MarshalJSON serialises a network allowed to a comma-separated
// list of networks.
func (acl *BasicNet) MarshalJSON() ([]byte, error) {
	var ss = make([]string, 0, len(acl.allowed))
	for i := range acl.allowed {
		ss = append(ss, acl.allowed[i].String())
	}

	out := []byte(`"` + strings.Join(ss, ",") + `"`)
	return out, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface for network
// ACLs, taking a comma-separated string of networks.
func (acl *BasicNet) UnmarshalJSON(in []byte) error {
	if in[0] != '"' || in[len(in)-1] != '"' {
		return errors.New("allowed: invalid allowed")
	}

	if acl.lock == nil {
		acl.lock = new(sync.Mutex)
	}

	acl.lock.Lock()
	defer acl.lock.Unlock()

	var err error
	netString := strings.TrimSpace(string(in[1 : len(in)-1]))
	nets := strings.Split(netString, ",")
	acl.allowed = make([]*net.IPNet, len(nets))
	for i := range nets {
		addr := strings.TrimSpace(nets[i])
		if addr == "" {
			continue
		}
		_, acl.allowed[i], err = net.ParseCIDR(addr)
		if err != nil {
			acl.allowed = nil
			return err
		}
	}

	return nil
}

// NetStub allows network ACLs to be added into a system's
// flow without doing anything yet. All operations result in warning
// log messages being printed to stderr. There is no mechanism for
// squelching these messages short of modifying the log package's
// default logger.
type NetStub struct{}

// Permitted always returns true, but prints a warning message alerting
// that ACL checks are stubbed.
func (acl NetStub) Permitted(ip net.IP) bool {
	log.Printf("WARNING: allowed check for %s but ACL is stubbed", ip)
	return true
}

// Add prints a warning message about ACL being stubbed.
func (acl NetStub) Add(ip *net.IPNet) {
	log.Printf("WARNING: IP network %s added to allowed but ACL is stubbed", ip)
}

// Remove prints a warning message about ACL being stubbed.
func (acl NetStub) Remove(ip *net.IPNet) {
	log.Printf("WARNING: IP network %s removed from allowed but ACL is stubbed", ip)
}

// NewNetStub returns a new stubbed network ACL.
func NewNetStub() NetStub {
	log.Println("WARNING: ACL is being stubbed")
	return NetStub{}
}
