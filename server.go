package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

type Alert struct {
	Rule   AlertRule              `json:"rule"`
	Event  map[string]interface{} `json:"event"`
	Source string                 `json:"source"`
}

type AlertRule struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Severity    string     `json:"severity"`
	Compliance  Compliance `json:"compliance"`
}

func processEvent(event map[string]interface{}, rules []CompiledRule, nc *NATSClient, source string) int {
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
				Event:  event,
				Source: source,
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

func authenticatedSender(r *http.Request, tokens map[string]string) (string, bool) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return "", false
	}
	token := auth[len(prefix):]
	for tok, sender := range tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(tok)) == 1 {
			return sender, true
		}
	}
	return "", false
}

func StartServer(cfg Config, rules []CompiledRule, nc *NATSClient) {
	http.HandleFunc("/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		sender, ok := authenticatedSender(r, cfg.IngestTokens)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var event map[string]interface{}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
			return
		}

		matched := processEvent(event, rules, nc, sender)

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
	srv := &http.Server{
		Addr:              addr,
		Handler:           nil,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
