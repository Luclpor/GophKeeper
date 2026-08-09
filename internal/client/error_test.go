package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientDecodesAPIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"error":"short and stout"}`))
	}))
	defer server.Close()

	api, err := New(WithBaseURL(server.URL), WithToken("token"), WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	_, err = api.ListRecords(context.Background())
	if err == nil {
		t.Fatal("ListRecords returned nil error")
	}
	if !strings.Contains(err.Error(), "short and stout") {
		t.Fatalf("error = %v, want API error text", err)
	}
}
