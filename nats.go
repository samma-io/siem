package main

import (
	"fmt"
	"log"

	"github.com/nats-io/nats.go"
)

type NATSClient struct {
	conn *nats.Conn
}

func NewNATSClient(url string) (*NATSClient, error) {
	nc, err := nats.Connect(url,
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to NATS at %s: %w", url, err)
	}
	log.Printf("connected to NATS at %s", url)
	return &NATSClient{conn: nc}, nil
}

func (c *NATSClient) Publish(subject string, data []byte) error {
	return c.conn.Publish(subject, data)
}

func (c *NATSClient) Subscribe(subjects []string, handler func([]byte)) error {
	for _, subject := range subjects {
		_, err := c.conn.Subscribe(subject, func(msg *nats.Msg) {
			handler(msg.Data)
		})
		if err != nil {
			return fmt.Errorf("subscribing to %s: %w", subject, err)
		}
		log.Printf("subscribed to NATS subject: %s", subject)
	}
	return nil
}

func (c *NATSClient) Close() {
	c.conn.Close()
}
