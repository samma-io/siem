package main

import (
	"reflect"
	"testing"
)

func TestParseIngestTokens(t *testing.T) {
	t.Setenv("SIEM_INGEST_TOKENS", "fleet=aaa,ci=bbb")
	cfg := LoadConfig()
	want := map[string]string{"aaa": "fleet", "bbb": "ci"}
	if !reflect.DeepEqual(cfg.IngestTokens, want) {
		t.Errorf("got %v, want %v", cfg.IngestTokens, want)
	}
}

func TestParseIngestTokensSkipsMalformedPairs(t *testing.T) {
	t.Setenv("SIEM_INGEST_TOKENS", "nofintosh,ci=bbb")
	cfg := LoadConfig()
	want := map[string]string{"bbb": "ci"}
	if !reflect.DeepEqual(cfg.IngestTokens, want) {
		t.Errorf("got %v, want %v", cfg.IngestTokens, want)
	}
}

func TestParseIngestTokensUnsetYieldsEmptyMap(t *testing.T) {
	cfg := LoadConfig()
	if len(cfg.IngestTokens) != 0 {
		t.Errorf("expected empty map, got %v", cfg.IngestTokens)
	}
}
