package whitelist

import (
	"errors"
	"io/ioutil"
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

var nlu NetConnLookup
var shutdown = make(chan struct{}, 1)
var proceed = make(chan struct{}, 0)

func setupTestServer(t *testing.T, wl Whitelist) {
	ln, err := net.Listen("tcp", "127.0.0.1:4141")
	if err != nil {
		t.Fatalf("%v", err)
	}
	proceed <- struct{}{}
	for {
		select {
		case _, ok := <-shutdown:
			if !ok {
				return
			}
		default:
			conn, err := ln.Accept()
			if err != nil {
				t.Fatalf("%v", err)
			}
			go handleTestConnection(conn, wl, t)
		}
	}
}

func handleTestConnection(conn net.Conn, wl Whitelist, t *testing.T) {
	defer conn.Close()
	ip, err := nlu.Address(conn)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if wl.Permitted(ip) {
		conn.Write([]byte("OK"))
	} else {
		conn.Write([]byte("NO"))
	}
}

func TestNetConn(t *testing.T) {
	wl := NewBasic()
	defer close(shutdown)

	go setupTestServer(t, wl)
	<-proceed

	conn, err := net.Dial("tcp", "127.0.0.1:4141")
	if err != nil {
		t.Fatalf("%v", err)
	}
	body, err := ioutil.ReadAll(conn)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if string(body) != "NO" {
		t.Fatalf("Expected NO, but received %s", body)
	}
	conn.Close()

	addIPString(wl, "127.0.0.1", t)
	conn, err = net.Dial("tcp", "127.0.0.1:4141")
	if err != nil {
		t.Fatalf("%v", err)
	}
	body, err = ioutil.ReadAll(conn)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if string(body) != "OK" {
		t.Fatalf("Expected OK, but received %s", body)
	}
	conn.Close()

}
