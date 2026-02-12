package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type Alert struct {
	Rule  AlertRule              `json:"rule"`
	Event map[string]interface{} `json:"event"`
}

type AlertRule struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Severity    string     `json:"severity"`
	Compliance  Compliance `json:"compliance"`
}

func processEvent(event map[string]interface{}, rules []CompiledRule, nc *NATSClient) int {
	matched := 0
	for _, rule := range rules {
		if rule.Matcher(event) {
			matched++
			alert := Alert{
				Rule: AlertRule{
					Name:        rule.Name,
					Description: rule.Description,
					Severity:    rule.Severity,
					Compliance:  rule.Compliance,
				},
				Event: event,
			}
			data, err := json.Marshal(alert)
			if err != nil {
				log.Printf("ERROR marshaling alert: %v", err)
				continue
			}
			if err := nc.Publish(rule.NATSSubject, data); err != nil {
				log.Printf("ERROR publishing to %s: %v", rule.NATSSubject, err)
			} else {
				log.Printf("rule %q matched, published to %s", rule.Name, rule.NATSSubject)
			}
		}
	}
	return matched
}

func StartServer(cfg Config, rules []CompiledRule, nc *NATSClient) {
	http.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var event map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
			return
		}

		matched := processEvent(event, rules, nc)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "ok",
			"matched": matched,
		})
	})

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	addr := ":" + cfg.HTTPPort
	log.Printf("HTTP server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
