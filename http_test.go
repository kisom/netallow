package netallow

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type testHandler struct {
	Message string
}

func newTestHandler(m string) http.Handler {
	return &testHandler{Message: m}
}

func (h *testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h.Message))
}

var testAllowHandler = newTestHandler("OK")
var testDenyHandler = newTestHandler("NO")

func testHTTPResponse(url string, t *testing.T) string {
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("%v", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%v", err)
	}
	resp.Body.Close()
	return string(body)
}

func testWorker(url string, t *testing.T, wg *sync.WaitGroup) {
	for i := 0; i < 100; i++ {
		response := testHTTPResponse(url, t)
		if response != "NO" {
			t.Fatalf("Expected NO, but got %s", response)
		}
	}
	wg.Done()
}

func TestHostStubHTTP(t *testing.T) {
	acl := NewHostStub()
	h, err := NewHandler(testAllowHandler, testDenyHandler, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	response := testHTTPResponse(srv.URL, t)
	if response != "OK" {
		t.Fatalf("Expected OK, but got %s", response)
	}

	addIPString(acl, "127.0.0.1", t)
	response = testHTTPResponse(srv.URL, t)
	if response != "OK" {
		t.Fatalf("Expected OK, but got %s", response)
	}

	delIPString(acl, "127.0.0.1", t)
	response = testHTTPResponse(srv.URL, t)
	if response != "OK" {
		t.Fatalf("Expected OK, but got %s", response)
	}
}

func TestNetStubHTTP(t *testing.T) {
	acl := NewNetStub()
	h, err := NewHandler(testAllowHandler, testDenyHandler, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	response := testHTTPResponse(srv.URL, t)
	if response != "OK" {
		t.Fatalf("Expected OK, but got %s", response)
	}

	testAddNet(acl, "127.0.0.1/32", t)
	response = testHTTPResponse(srv.URL, t)
	if response != "OK" {
		t.Fatalf("Expected OK, but got %s", response)
	}

	testDelNet(acl, "127.0.0.1/32", t)
	response = testHTTPResponse(srv.URL, t)
	if response != "OK" {
		t.Fatalf("Expected OK, but got %s", response)
	}
}

func TestBasicHTTP(t *testing.T) {
	acl := NewBasic()
	h, err := NewHandler(testAllowHandler, testDenyHandler, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	response := testHTTPResponse(srv.URL, t)
	if response != "NO" {
		t.Fatalf("Expected NO, but got %s", response)
	}

	addIPString(acl, "127.0.0.1", t)
	response = testHTTPResponse(srv.URL, t)
	if response != "OK" {
		t.Fatalf("Expected OK, but got %s", response)
	}

	delIPString(acl, "127.0.0.1", t)
	response = testHTTPResponse(srv.URL, t)
	if response != "NO" {
		t.Fatalf("Expected NO, but got %s", response)
	}
}

func TestBasicHTTPDefaultDeny(t *testing.T) {
	acl := NewBasic()
	h, err := NewHandler(testAllowHandler, nil, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	expected := "Unauthorized"
	response := strings.TrimSpace(testHTTPResponse(srv.URL, t))
	if response != expected {
		t.Fatalf("Expected %s, but got %s", expected, response)
	}
}

func TestBasicHTTPWorkers(t *testing.T) {
	acl := NewBasic()
	h, err := NewHandler(testAllowHandler, testDenyHandler, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}

	srv := httptest.NewServer(h)
	wg := new(sync.WaitGroup)
	defer srv.Close()

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go testWorker(srv.URL, t, wg)
	}

	wg.Wait()

}

func TestFailHTTP(t *testing.T) {
	acl := NewBasic()
	h, err := NewHandler(testAllowHandler, testDenyHandler, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}

	w := httptest.NewRecorder()
	req := new(http.Request)

	if h.ServeHTTP(w, req); w.Code != http.StatusInternalServerError {
		t.Fatalf("Expect HTTP 500, but got HTTP %d", w.Code)
	}
}

var testHandlerFunc *HandlerFunc

func newTestHandlerFunc(m string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(m))
	}
}

var testAllowHandlerFunc = newTestHandlerFunc("OK")
var testDenyHandlerFunc = newTestHandlerFunc("NO")

func TestSetupHandlerFuncFails(t *testing.T) {
	acl := NewBasic()
	_, err := NewHandlerFunc(nil, testDenyHandlerFunc, acl)
	if err == nil {
		t.Fatal("expected NewHandlerFunc to fail with nil allow handler")
	}

	_, err = NewHandlerFunc(testAllowHandlerFunc, testDenyHandlerFunc, nil)
	if err == nil {
		t.Fatal("expected NewHandlerFunc to fail with nil allowed")
	}

	_, err = NewHandlerFunc(testAllowHandlerFunc, nil, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestSetupHandlerFunc(t *testing.T) {
	acl := NewBasic()
	h, err := NewHandlerFunc(testAllowHandlerFunc, testDenyHandlerFunc, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	expected := "NO"
	response := strings.TrimSpace(testHTTPResponse(srv.URL, t))
	if response != expected {
		t.Fatalf("Expected %s, but got %s", expected, response)
	}

	h.deny = nil
	expected = "Unauthorized"
	response = strings.TrimSpace(testHTTPResponse(srv.URL, t))
	if response != expected {
		t.Fatalf("Expected %s, but got %s", expected, response)
	}

	addIPString(acl, "127.0.0.1", t)
	expected = "OK"
	response = strings.TrimSpace(testHTTPResponse(srv.URL, t))
	if response != expected {
		t.Fatalf("Expected %s, but got %s", expected, response)
	}
}

func TestFailHTTPFunc(t *testing.T) {
	acl := NewBasic()
	h, err := NewHandlerFunc(testAllowHandlerFunc, testDenyHandlerFunc, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}

	w := httptest.NewRecorder()
	req := new(http.Request)

	if h.ServeHTTP(w, req); w.Code != http.StatusInternalServerError {
		t.Fatalf("Expect HTTP 500, but got HTTP %d", w.Code)
	}
}

func TestBasicNetHTTP(t *testing.T) {
	acl := NewBasicNet()
	h, err := NewHandler(testAllowHandler, testDenyHandler, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	response := testHTTPResponse(srv.URL, t)
	if response != "NO" {
		t.Fatalf("Expected NO, but got %s", response)
	}

	testAddNet(acl, "127.0.0.1/32", t)
	response = testHTTPResponse(srv.URL, t)
	if response != "OK" {
		t.Fatalf("Expected OK, but got %s", response)
	}

	testDelNet(acl, "127.0.0.1/32", t)
	response = testHTTPResponse(srv.URL, t)
	if response != "NO" {
		t.Fatalf("Expected NO, but got %s", response)
	}
}

func TestBasicNetHTTPDefaultDeny(t *testing.T) {
	acl := NewBasicNet()
	h, err := NewHandler(testAllowHandler, nil, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	expected := "Unauthorized"
	response := strings.TrimSpace(testHTTPResponse(srv.URL, t))
	if response != expected {
		t.Fatalf("Expected %s, but got %s", expected, response)
	}
}

func TestBasicNetHTTPWorkers(t *testing.T) {
	acl := NewBasicNet()
	h, err := NewHandler(testAllowHandler, testDenyHandler, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}

	srv := httptest.NewServer(h)
	wg := new(sync.WaitGroup)
	defer srv.Close()

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go testWorker(srv.URL, t, wg)
	}

	wg.Wait()

}

func TestNetFailHTTP(t *testing.T) {
	acl := NewBasicNet()
	h, err := NewHandler(testAllowHandler, testDenyHandler, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}
	w := httptest.NewRecorder()
	req := new(http.Request)

	if h.ServeHTTP(w, req); w.Code != http.StatusInternalServerError {
		t.Fatalf("Expect HTTP 500, but got HTTP %d", w.Code)
	}
}

func TestSetupNetHandlerFuncFails(t *testing.T) {
	acl := NewBasicNet()
	_, err := NewHandlerFunc(nil, testDenyHandlerFunc, acl)
	if err == nil {
		t.Fatal("expected NewHandlerFunc to fail with nil allow handler")
	}

	_, err = NewHandlerFunc(testAllowHandlerFunc, testDenyHandlerFunc, nil)
	if err == nil {
		t.Fatal("expected NewHandlerFunc to fail with nil allowed")
	}

	_, err = NewHandlerFunc(testAllowHandlerFunc, nil, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestSetupNetHandlerFunc(t *testing.T) {
	acl := NewBasicNet()
	h, err := NewHandlerFunc(testAllowHandlerFunc, testDenyHandlerFunc, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	expected := "NO"
	response := strings.TrimSpace(testHTTPResponse(srv.URL, t))
	if response != expected {
		t.Fatalf("Expected %s, but got %s", expected, response)
	}

	h.deny = nil
	expected = "Unauthorized"
	response = strings.TrimSpace(testHTTPResponse(srv.URL, t))
	if response != expected {
		t.Fatalf("Expected %s, but got %s", expected, response)
	}

	testAddNet(acl, "127.0.0.1/32", t)
	expected = "OK"
	response = strings.TrimSpace(testHTTPResponse(srv.URL, t))
	if response != expected {
		t.Fatalf("Expected %s, but got %s", expected, response)
	}
}

func TestNetFailHTTPFunc(t *testing.T) {
	acl := NewBasicNet()
	h, err := NewHandlerFunc(testAllowHandlerFunc, testDenyHandlerFunc, acl)
	if err != nil {
		t.Fatalf("%v", err)
	}

	w := httptest.NewRecorder()
	req := new(http.Request)

	if h.ServeHTTP(w, req); w.Code != http.StatusInternalServerError {
		t.Fatalf("Expect HTTP 500, but got HTTP %d", w.Code)
	}
}

func TestHandlerFunc(t *testing.T) {
	var acl ACL
	_, err := NewHandler(testAllowHandler, testDenyHandler, nil)
	if err == nil || err.Error() != "netallow: ACL cannot be nil" {
		t.Fatal("Expected error with nil ACL.")
	}

	acl = NewBasic()
	_, err = NewHandler(nil, testDenyHandler, acl)
	if err == nil || err.Error() != "netallow: allow cannot be nil" {
		t.Fatal("Expected error with nil allow handler.")
	}
}
