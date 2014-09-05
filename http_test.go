package whitelist

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
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

func TestStubHTTP(t *testing.T) {
	wl := NewStub()
	h := NewHandler(testAllowHandler, testDenyHandler, wl)
	srv := httptest.NewServer(h)
	defer srv.Close()

	response := testHTTPResponse(srv.URL, t)
	if response != "OK" {
		t.Fatalf("Expected OK, but got %s", response)
	}

	addIPString(wl, "127.0.0.1", t)
	response = testHTTPResponse(srv.URL, t)
	if response != "OK" {
		t.Fatalf("Expected OK, but got %s", response)
	}

	delIPString(wl, "127.0.0.1", t)
	response = testHTTPResponse(srv.URL, t)
	if response != "OK" {
		t.Fatalf("Expected OK, but got %s", response)
	}
}

func TestBasicHTTP(t *testing.T) {
	wl := NewBasic()
	h := NewHandler(testAllowHandler, testDenyHandler, wl)
	srv := httptest.NewServer(h)
	defer srv.Close()

	response := testHTTPResponse(srv.URL, t)
	if response != "NO" {
		t.Fatalf("Expected NO, but got %s", response)
	}

	addIPString(wl, "127.0.0.1", t)
	response = testHTTPResponse(srv.URL, t)
	if response != "OK" {
		t.Fatalf("Expected OK, but got %s", response)
	}

	delIPString(wl, "127.0.0.1", t)
	response = testHTTPResponse(srv.URL, t)
	if response != "NO" {
		t.Fatalf("Expected NO, but got %s", response)
	}
}

func TestFailHTTP(t *testing.T) {
	wl := NewBasic()
	h := NewHandler(testAllowHandler, testDenyHandler, wl)
	w := httptest.NewRecorder()
	req := new(http.Request)

	if h.ServeHTTP(w, req); w.Code != http.StatusInternalServerError {
		t.Fatalf("Expect HTTP 500, but got HTTP %d", w.Code)
	}
}
