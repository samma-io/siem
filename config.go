package main

import (
	"os"
	"strings"
)

type Config struct {
	HTTPPort       string
	NATSUrl        string
	NATSSubscribe  []string
	RulesDir       string
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
		NATSSubscribe: subjects,
		RulesDir:      getenv("SIEM_RULES_DIR", "./rules"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
