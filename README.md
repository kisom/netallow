## whitelist

![Build Status](https://travis-ci.org/kisom/whitelist.svg)

This is a simple whitelisting package that encompasses several common
patterns into a reusable package.

The basic type of a whitelist is the `Whitelist` type, which provides
three methods on `net.IP` values:

* `Permitted` determines whether the IP address is whitelisted and
  therefore should be permitted access. It should return true if the
  address is whitelisted.
* `Add` whitelists the IP address.
* `Remove` drops the IP address from the whitelist.

There are currently two implementations of `Whitelist` provided in
this package:

* `BasicWhitelist` converts the IP addresses to strings and contains a
  set of string addresses as the whitelist. The set is implemented as a
  `map[string]bool`, and uses a `sync.RWMutex` to coordinate updates to
  the whitelist.
* `StubWhitelist` is a stand-in whitelist that always permits
  addresses. It is vocal about logging warning messages noting
  that whitelisting is stubbed. It is designed to be used in cases
  where whitelisting is desired, but the mechanics of whitelisting
  (i.e. administration of the whitelist) is not yet implemented,
  perhaps to keep whitelists in the system's flow.

There is a second type provided here: the `Lookup`. A `Lookup`
is a mechanism for converting some arguments to a `net.IP` value;
most often, it's a convenience for performing a common set of
operations. Two implementations are provided here:

* `NetConnLookup` accepts a `net.Conn` value, and returns the `net.IP`
  value from the connection.
* `HTTPRequestLookup` accepts a `*http.Request` and returns the
  `net.IP` value from the request.

There is also an `http.Handler` implementation that wraps a pair of
handlers, one for the case where the IP is permitted, and one for the
case where the IP is denied, in a handler that will check incoming
requests against the whitelist.

### Example `http.Handler`


