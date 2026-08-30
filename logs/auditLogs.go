package logs

import (
	"encoding/json"
	"time"
)

type Status string

const (
	StatusSuccess Status = "success"
	StatusFailure Status = "failure"
	StatusDenied  Status = "denied"
)

func (s Status) Valid() bool {
	switch s {
	case StatusSuccess, StatusFailure, StatusDenied:
		return true
	default:
		return false
	}
}

type AuditLog struct {
	ID      int64  `db:"id"`
	EventID string `db:"event_id"` // UUID; blank => DB generates one

	// origin
	ServiceName string `db:"service_name"`
	Environment string `db:"environment"` // blank => DB default 'production'

	// actor
	ActorID        *string `db:"actor_id"` // UUID
	ActorType      string  `db:"actor_type"`
	ActorIP        *string `db:"actor_ip"` // INET, e.g. "10.0.0.4"
	ActorUserAgent *string `db:"actor_user_agent"`

	// action
	Action       string  `db:"action"`
	ResourceType string  `db:"resource_type"`
	ResourceID   *string `db:"resource_id"`

	// change data
	OldValues     json.RawMessage `db:"old_values"` // JSONB
	NewValues     json.RawMessage `db:"new_values"` // JSONB
	ChangedFields []string        `db:"changed_fields"`

	// outcome
	Status       Status  `db:"status"` // blank => DB default 'success'
	ErrorMessage *string `db:"error_message"`

	// tracing / correlation
	RequestID     *string `db:"request_id"`     // UUID
	CorrelationID *string `db:"correlation_id"` // UUID
	TraceID       *string `db:"trace_id"`

	// metadata
	Metadata json.RawMessage `db:"metadata"` // JSONB

	OccurredAt time.Time `db:"occurred_at"`
	CreatedAt  time.Time `db:"created_at"`
}
