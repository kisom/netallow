## whitelist

![Build Status](https://travis-ci.org/kisom/whitelist.svg)

This is a simple whitelisting package that encompasses several common
patterns into a reusable package.

The basic type of a whitelist is the `ACL` type, which provides
three methods on `net.IP` values:

* `Permitted` determines whether the IP address is whitelisted and
  therefore should be permitted access. It should return true if the
  address is whitelisted.
* `Add` whitelists the IP address.
* `Remove` drops the IP address from the whitelist.

There are currently two implementations of `ACL` provided in
this package:

* `Basic` converts the IP addresses to strings and contains a
  set of string addresses as the whitelist. The set is implemented
  as a `map[string]bool`, and uses a `sync.RWMutex` to coordinate
  updates to the whitelist.
* `Stub` is a stand-in whitelist that always permits addresses. It
  is vocal about logging warning messages noting that whitelisting is
  stubbed. It is designed to be used in cases where whitelisting is
  desired, but the mechanics of whitelisting (i.e. administration of
  the whitelist) is not yet implemented, perhaps to keep whitelists
  in the system's flow.

Two convenience functions are provided here for extracting IP addresses:

* `NetConnLookup` accepts a `net.Conn` value, and returns the `net.IP`
  value from the connection.
* `HTTPRequestLookup` accepts a `*http.Request` and returns the
  `net.IP` value from the request.

There is also an `http.Handler` implementation that wraps a pair of
handlers, one for the case where the IP is permitted, and one for the
case where the IP is denied, in a handler that will check incoming
requests against the whitelist.

### Example `http.Handler`

This is a file server that uses a pair of whitelists. The admin
whitelist permits modifications to the user whitelist only by the
localhost. The user whitelist controls which hosts have access to
the file server.

```
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/kisom/whitelist"
)

var wl = whitelist.NewBasic()

func addIP(w http.ResponseWriter, r *http.Request) {
	addr := r.FormValue("ip")

	ip := net.ParseIP(addr)
	wl.Add(ip)
	w.Write([]byte(fmt.Sprintf("Added %s to whitelist.\n", ip)))
}

func delIP(w http.ResponseWriter, r *http.Request) {
	addr := r.FormValue("ip")

	ip := net.ParseIP(addr)
	wl.Remove(ip)
	w.Write([]byte(fmt.Sprintf("Added %s to whitelist.\n", ip)))
}

func dumpWhitelist(w http.ResponseWriter, r *http.Request) {
	w.Write(whitelist.DumpBasic(wl))
}

type handler struct {
	h func(http.ResponseWriter, *http.Request)
}

func newHandler(h func(w http.ResponseWriter, r *http.Request)) http.Handler {
	return &handler{h: h}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.h(w, r)
}

func main() {
	root := flag.String("root", "files/", "file server root")
	flag.Parse()

	fileServer := http.StripPrefix("/files/",
		http.FileServer(http.Dir(*root)))
	wl.Add(net.IP{127, 0, 0, 1})

	adminWL := whitelist.NewBasic()
	adminWL.Add(net.IP{127, 0, 0, 1})
	adminWL.Add(net.ParseIP("::1"))

	protFiles := whitelist.NewHandler(fileServer, nil, wl)
	http.Handle("/files/", protFiles)
	http.Handle("/add", whitelist.NewHandler(newHandler(addIP),
		nil, adminWL))
	http.Handle("/del", whitelist.NewHandler(newHandler(delIP),
		nil, adminWL))
	http.Handle("/dump", whitelist.NewHandler(newHandler(dumpWhitelist),
		nil, adminWL))

	log.Fatal(http.ListenAndServe(":8080", nil))
}
```
