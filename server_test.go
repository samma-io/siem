package main

import (
	"net/http/httptest"
	"testing"
)

func TestAuthenticatedSenderValidToken(t *testing.T) {
	tokens := map[string]string{"aaa": "fleet"}
	r := httptest.NewRequest("POST", "/ingest", nil)
	r.Header.Set("Authorization", "Bearer aaa")

	sender, ok := authenticatedSender(r, tokens)
	if !ok {
		t.Fatal("expected authenticated")
	}
	if sender != "fleet" {
		t.Errorf("got sender %q, want %q", sender, "fleet")
	}
}

func TestAuthenticatedSenderMissingHeader(t *testing.T) {
	tokens := map[string]string{"aaa": "fleet"}
	r := httptest.NewRequest("POST", "/ingest", nil)

	if _, ok := authenticatedSender(r, tokens); ok {
		t.Error("expected unauthenticated with missing Authorization header")
	}
}

func TestAuthenticatedSenderWrongToken(t *testing.T) {
	tokens := map[string]string{"aaa": "fleet"}
	r := httptest.NewRequest("POST", "/ingest", nil)
	r.Header.Set("Authorization", "Bearer wrong")

	if _, ok := authenticatedSender(r, tokens); ok {
		t.Error("expected unauthenticated with wrong token")
	}
}

func TestAuthenticatedSenderNonBearerScheme(t *testing.T) {
	tokens := map[string]string{"aaa": "fleet"}
	r := httptest.NewRequest("POST", "/ingest", nil)
	r.Header.Set("Authorization", "Basic aaa")

	if _, ok := authenticatedSender(r, tokens); ok {
		t.Error("expected unauthenticated with non-Bearer scheme")
	}
}
