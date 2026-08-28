package messaging

import (
	"encoding/json"
	"fmt"
	"os"

	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	PasswordResetEmailQueue = "password_reset_email"
	PasswordResetSMSQueue   = "password_reset_sms"
	AuditLogQueue           = "audit_logs"
)

type RabbitMQ struct {
	Conn *amqp.Connection
	Ch   *amqp.Channel
}

func NewRabbitMQ() (*RabbitMQ, error) {
	url := os.Getenv("RABBITMQ_URL")
	if url == "" {
		return nil, fmt.Errorf("RABBITMQ_URL is not set")
	}

	conn, err := amqp.Dial(url)
	if err != nil {
		return nil, err
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &RabbitMQ{
		Conn: conn,
		Ch:   ch,
	}, nil
}

func (r *RabbitMQ) Close() {
	r.Ch.Close()
	r.Conn.Close()
}

func (r *RabbitMQ) String() string {
	return "Rabbitmq connected"
}

func (r *RabbitMQ) PublishJSON(queueName string, payload any) error {
	if _, err := r.Ch.QueueDeclare(
		queueName,
		true,  // durable: survives a broker restart
		false, // autoDelete
		false, // exclusive
		false, // noWait
		nil,   // args
	); err != nil {
		return err
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	return r.Ch.Publish(
		"",        // default exchange
		queueName, // routing key = queue name
		false,     // mandatory
		false,     // immediate
		amqp.Publishing{
			ContentType:  "application/json",
			DeliveryMode: amqp.Persistent,
			Body:         body,
		},
	)
}
