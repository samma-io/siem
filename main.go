package main

import (
	"encoding/json"
	"log"
)

func main() {
	cfg := LoadConfig()

	rules, err := LoadRules(cfg.RulesDir)
	if err != nil {
		log.Fatalf("failed to load rules: %v", err)
	}
	log.Printf("loaded %d rules", len(rules))

	nc, err := NewNATSClient(cfg.NATSUrl)
	if err != nil {
		log.Fatalf("failed to connect to NATS: %v", err)
	}
	defer nc.Close()

	if len(cfg.NATSSubscribe) > 0 {
		err := nc.Subscribe(cfg.NATSSubscribe, func(data []byte) {
			var event map[string]interface{}
			if err := json.Unmarshal(data, &event); err != nil {
				log.Printf("ERROR decoding NATS message: %v", err)
				return
			}
			processEvent(event, rules, nc)
		})
		if err != nil {
			log.Fatalf("failed to subscribe: %v", err)
		}
	}

	StartServer(cfg, rules, nc)
}
