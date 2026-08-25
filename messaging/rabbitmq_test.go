package messaging

import "testing"

func TestNewRabbitMQ_MissingURL(t *testing.T) {
	t.Setenv("RABBITMQ_URL", "")

	if _, err := NewRabbitMQ(); err == nil {
		t.Fatal("expected an error when RABBITMQ_URL is unset")
	}
}
