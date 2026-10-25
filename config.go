package main

import (
	"os"
	"strings"
)

type Config struct {
	HTTPPort      string
	NATSUrl       string
	NATSUser      string
	NATSPassword  string
	NATSSubscribe []string
	RulesDir      string
	IngestTokens  map[string]string
}

func LoadConfig() Config {
	var subjects []string
	if s := os.Getenv("SIEM_NATS_SUBSCRIBE"); s != "" {
		for _, sub := range strings.Split(s, ",") {
			sub = strings.TrimSpace(sub)
			if sub != "" {
				subjects = append(subjects, sub)
			}
		}
	}

	return Config{
		HTTPPort:      getenv("SIEM_HTTP_PORT", "8080"),
		NATSUrl:       getenv("SIEM_NATS_URL", "nats://localhost:4222"),
		NATSUser:      os.Getenv("SIEM_NATS_USER"),
		NATSPassword:  os.Getenv("SIEM_NATS_PASSWORD"),
		NATSSubscribe: subjects,
		RulesDir:      getenv("SIEM_RULES_DIR", "./rules"),
		IngestTokens:  parseIngestTokens(os.Getenv("SIEM_INGEST_TOKENS")),
	}
}

func parseIngestTokens(raw string) map[string]string {
	tokens := make(map[string]string)
	if raw == "" {
		return tokens
	}
	for _, pair := range strings.Split(raw, ",") {
		name, token, found := strings.Cut(pair, "=")
		if !found {
			continue
		}
		tokens[strings.TrimSpace(token)] = strings.TrimSpace(name)
	}
	return tokens
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
