## netallow

![Build Status](https://travis-ci.org/kisom/netallow.svg)

This is a simple network ACL package encompassing several common
patterns into a reusable package.

The basic type is the `ACL` type, which provides a single method on
a `net.IP` value:

* `Permitted` determines whether the IP address is permitted access. It
  should return true if the address is permitted.

Additionally, there are two other types that are built on the `ACL`
type; the `HostACL` stores individual hosts and the `NetACL` stores
networks. Each of these provides two functions that differ in the
types of their arguments.

* `Add` permits the IP address.
* `Remove` restrics a previously-permitted IP address.

The `HostACL` operates on `net.IP` values, while the `NetACL` operates
on `*net.IPNet`s.

There are currently four implementations of `ACL` provided in this
package; a basic implementation of the two types of ACLs and a stub
type for each:

* `Basic` is a simple host-based ACL that converts the IP addresses
  to strings; the ACL is implemented as a set of string addresses.
  The set is implemented as a `map[string]bool`, and uses a `sync.Mutex`
  to coordinate updates to the ACL.
* `BasicNet` is a simple network-based ACL that similarly uses
  a mutex and an array to store networks. This has a number of
  limitations: operations are /O(n)/, and subsets/supersets of
  existing networks isn't detected. That is, if 192.168.3.0/24 is
  removed from an ACL that has 192.168.0.0/16 permitted, **that subnet
  will not actually be removed**. Exact networks are required for
  `Add` and `Remove` at this time.
* `HostStub` and `NetStub` are stand-in ACLs that always permit addresses.
  They are vocal about logging warning messages noting that the ACL is
  stubbed. They are designed to be used in cases where ACLs are desired,
  but the mechanics of ACLs (i.e. administration) are not yet implemented,
  perhaps to keep ACLs in the system's flow.

Two convenience functions are provided here for extracting IP addresses:

* `NetConnLookup` accepts a `net.Conn` value, and returns the `net.IP`
  value from the connection.
* `HTTPRequestLookup` accepts a `*http.Request` and returns the
  `net.IP` value from the request.

There are also two functions for ACL'ing HTTP endpoints:

* `NewHandler` returns an `http.Handler`
* `NewHandlerFunc` returns an `http.HandlerFunc`

These endpoints will work with both `HostACL` and `NetACL`.

### Example `http.Handler`

This is a file server that uses a pair of ACLs. The admin ACL permits
modifications to the user ACL only by the localhost. The user ACL
controls which hosts have access to the file server.

```
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/kisom/netallow"
)

var acl = netallow.NewBasic()

func addIP(w http.ResponseWriter, r *http.Request) {
	addr := r.FormValue("ip")

	ip := net.ParseIP(addr)
	acl.Add(ip)
	log.Printf("request to add %s to the ACL", addr)
	w.Write([]byte(fmt.Sprintf("Added %s to ACL.\n", addr)))
}

func delIP(w http.ResponseWriter, r *http.Request) {
	addr := r.FormValue("ip")

	ip := net.ParseIP(addr)
	acl.Remove(ip)
	log.Printf("request to remove %s from the ACL", addr)
	w.Write([]byte(fmt.Sprintf("Removed %s from ACL.\n", ip)))
}

func dumpACL(w http.ResponseWriter, r *http.Request) {
	out, err := json.Marshal(acl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	} else {
		w.Write(out)
	}
}

func main() {
	root := flag.String("root", "files/", "file server root")
	flag.Parse()

	fileServer := http.StripPrefix("/files/",
		http.FileServer(http.Dir(*root)))
	acl.Add(net.IP{127, 0, 0, 1})

	adminACL := netallow.NewBasic()
	adminACL.Add(net.IP{127, 0, 0, 1})
	adminACL.Add(net.ParseIP("::1"))

	protFiles, err := netallow.NewHandler(fileServer, nil, acl)
	if err != nil {
		log.Fatalf("%v", err)
	}

	addHandler, err := netallow.NewHandlerFunc(addIP, nil, adminACL)
	if err != nil {
		log.Fatalf("%v", err)
	}

	delHandler, err := netallow.NewHandlerFunc(delIP, nil, adminACL)
	if err != nil {
		log.Fatalf("%v", err)
	}

	dumpHandler, err := netallow.NewHandlerFunc(dumpACL, nil, adminACL)
	if err != nil {
		log.Fatalf("%v", err)
	}

	http.Handle("/files/", protFiles)
	http.Handle("/add", addHandler)
	http.Handle("/del", delHandler)
	http.Handle("/dump", dumpHandler)

	log.Println("Serving files on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```
