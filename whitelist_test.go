package whitelist

import (
	"errors"
	"net"
	"testing"
)

type StringLookup struct{}

func (lu StringLookup) Address(args ...interface{}) (net.IP, error) {
	if len(args) != 1 {
		return nil, errors.New("whitelist: lookup requires a string")
	}

	var s string
	switch arg := args[0].(type) {
	case string:
		s = arg
	default:
		return nil, errors.New("whitelist: lookup requires a string")
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return nil, errors.New("whitelist: no address found")
	}
	return ip, nil
}

var slu StringLookup

func checkIPString(wl Whitelist, addr string, t *testing.T) bool {
	ip, err := slu.Address(addr)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return wl.Permitted(ip)
}

func addIPString(wl Whitelist, addr string, t *testing.T) {
	ip, err := slu.Address(addr)
	if err != nil {
		t.Fatalf("%v", err)
	}

	wl.Add(ip)
}

func delIPString(wl Whitelist, addr string, t *testing.T) {
	ip, err := slu.Address(addr)
	if err != nil {
		t.Fatalf("%v", err)
	}

	wl.Remove(ip)
}

func TestBasicWhitelist(t *testing.T) {
	wl := NewBasic()

	if checkIPString(wl, "127.0.0.1", t) {
		t.Fatal("whitelist should have denied address")
	}

	addIPString(wl, "127.0.0.1", t)
	if !checkIPString(wl, "127.0.0.1", t) {
		t.Fatal("whitelist should have permitted address")
	}

	delIPString(wl, "127.0.0.1", t)
	if checkIPString(wl, "127.0.0.1", t) {
		t.Fatal("whitelist should have denied address")
	}
}
