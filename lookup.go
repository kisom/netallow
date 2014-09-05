package whitelist

import (
	"errors"
	"net"
	"net/http"
)

// A Lookup is a means of getting an IP from some data, such as an
// http request or network connection.
type Lookup interface {
	Address(...interface{}) (net.IP, error)
}

// NetConn implements the Lookup interface for net.Conn connections.
type NetConnLookup struct{}

// Address extracts an IP from the remote address in the net.Conn. A
// single net.Conn should be passed to Address.
func (lu NetConnLookup) Address(args ...interface{}) (net.IP, error) {
	if len(args) != 1 {
		return nil, errors.New("whitelist: lookup requires a net.Conn")
	}

	var conn net.Conn
	switch arg := args[0].(type) {
	case net.Conn:
		conn = arg
	default:
		return nil, errors.New("whitelist: lookup requires a net.Conn")
	}

	addr, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, errors.New("whitelist: no address found")
	}
	return ip, nil
}

// HTTPRequestLookup implements the Lookup interface for http.Requests.
type HTTPRequestLookup struct{}

// Address extracts an IP from the remote address in a *http.Request. A
// single *http.Request should be passed to Address.
func (lu HTTPRequestLookup) Address(args ...interface{}) (net.IP, error) {
	if len(args) != 1 {
		return nil, errors.New("whitelist: lookup requires a *http.Request")
	}

	var req *http.Request
	switch arg := args[0].(type) {
	case *http.Request:
		req = arg
	default:
		return nil, errors.New("whitelist: lookup requires a *http.Request")
	}

	addr, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, errors.New("whitelist: no address found")
	}
	return ip, nil

}
