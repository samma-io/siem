package main

import (
	"encoding/json"
	"log"
)

func main() {
	cfg := LoadConfig()

	if len(cfg.IngestTokens) == 0 {
		log.Fatal("no ingest tokens configured: set SIEM_INGEST_TOKENS (comma-separated name=token pairs); refusing to start with open /ingest")
	}

	rules, err := LoadRules(cfg.RulesDir)
	if err != nil {
		log.Fatalf("failed to load rules: %v", err)
	}
	log.Printf("loaded %d rules", len(rules))

	nc, err := NewNATSClient(cfg.NATSUrl, cfg.NATSUser, cfg.NATSPassword)
	if err != nil {
		log.Fatalf("failed to connect to NATS: %v", err)
	}
	defer nc.Close()

	if len(cfg.NATSSubscribe) > 0 {
		err := nc.Subscribe(cfg.NATSSubscribe, func(subject string, data []byte) {
			var event map[string]interface{}
			if err := json.Unmarshal(data, &event); err != nil {
				log.Printf("ERROR decoding NATS message: %v", err)
				return
			}
			processEvent(event, rules, nc, "nats:"+subject)
		})
		if err != nil {
			log.Fatalf("failed to subscribe: %v", err)
		}
	}

	StartServer(cfg, rules, nc)
}
