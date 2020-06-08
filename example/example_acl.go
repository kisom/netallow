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
