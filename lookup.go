package whitelist

import (
	"errors"
	"log"
	"net"
	"net/http"
)

// A Lookup is a means of getting an IP from some data, such as an
// http request or network connection.
type Lookup interface {
	Address(...interface{}) (net.IP, error)
}

// NetConnLookup implements the Lookup interface for net.Conn connections.
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

	netAddr := conn.RemoteAddr()
	if netAddr == nil {
		return nil, errors.New("whitelist: no address returned")
	}

	addr, _, err := net.SplitHostPort(netAddr.String())
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(addr)
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
	return ip, nil

}

// Handler wraps an HTTP handler with IP whitelisting.
type Handler struct {
	allowHandler http.Handler
	denyHandler  http.Handler
	whitelist    Whitelist
	lookup       Lookup
}

// NewHandler returns a new whitelisting-wrapped HTTP handler. The
// allow handler should contain a handler that will be called if the
// request is whitelisted; the deny handler should contain a handler
// that will be called in the request is not whitelisted.
func NewHandler(allow, deny http.Handler, wl Whitelist) http.Handler {
	return &Handler{
		allowHandler: allow,
		denyHandler:  deny,
		whitelist:    wl,
		lookup:       HTTPRequestLookup{},
	}
}

// ServeHTTP wraps the request in a whitelist check.
func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ip, err := h.lookup.Address(req)
	if err != nil {
		log.Printf("failed to lookup request address: %v", err)
		status := http.StatusInternalServerError
		http.Error(w, http.StatusText(status), status)
		return
	}

	if h.whitelist.Permitted(ip) {
		h.allowHandler.ServeHTTP(w, req)
	} else {
		if h.denyHandler == nil {
			status := http.StatusUnauthorized
			http.Error(w, http.StatusText(status), status)
		} else {
			h.denyHandler.ServeHTTP(w, req)
		}
	}
}
