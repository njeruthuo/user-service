package logs

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/njeruthuo/user-service/messaging"
	"github.com/njeruthuo/user-service/utils"
)

const serviceName = "user-service"

type Publisher interface {
	PublishJSON(queueName string, payload any) error
}

type routeAudit struct {
	action   string
	resource string
}

var routeAudits = map[string]routeAudit{
	"GET /health":                {"health.check", "health"},
	"POST /auth/login":           {"auth.login", "session"},
	"POST /auth/logout":          {"auth.logout", "session"},
	"POST /auth/register":        {"auth.register", "user"},
	"POST /auth/refresh":         {"auth.refresh", "session"},
	"POST /auth/forgot-password": {"auth.forgot_password", "password"},
	"POST /auth/reset-password":  {"auth.reset_password", "password"},
	"POST /auth/change-password": {"auth.change_password", "password"},
}

// Middleware records one audit entry per request, after the handler has run so
// the outcome is known. Publishing happens on its own goroutine: the audit
// trail must never be the reason a request is slow, or fails.
func Middleware(pub Publisher) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := uuid.NewString()
			w.Header().Set("X-Request-ID", requestID)

			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()

			next.ServeHTTP(rec, r)

			entry := buildEntry(r, rec, requestID, start)

			if pub == nil {
				return
			}

			go func() {
				if err := pub.PublishJSON(messaging.AuditLogQueue, entry); err != nil {
					log.Printf("audit: failed to publish log for %s: %v", requestID, err)
				}
			}()
		})
	}
}

func buildEntry(r *http.Request, rec *statusRecorder, requestID string, start time.Time) AuditLog {
	now := time.Now().UTC()

	route := routeKey(r)
	meta := routeAudits[route]
	if meta.action == "" {
		// An unmapped route (a 404, or one added without a matching entry
		// above) is still recorded, just with generic descriptors.
		meta = routeAudit{
			action:   strings.ToLower(r.Method) + " " + r.URL.Path,
			resource: "http",
		}
	}

	entry := AuditLog{
		ServiceName:  serviceName,
		ActorType:    "anonymous",
		Action:       meta.action,
		ResourceType: meta.resource,
		Status:       outcome(rec.status),
		RequestID:    &requestID,
		OccurredAt:   now,
		CreatedAt:    now,
	}

	if ip := clientIP(r); ip != "" {
		entry.ActorIP = &ip
	}

	if ua := r.UserAgent(); ua != "" {
		entry.ActorUserAgent = &ua
	}

	if id, ok := actorID(r); ok {
		entry.ActorID = &id
		entry.ActorType = "user"
	}

	entry.Metadata = requestMetadata(r, rec, start)

	return entry
}

func routeKey(r *http.Request) string {
	if route := mux.CurrentRoute(r); route != nil {
		if tmpl, err := route.GetPathTemplate(); err == nil {
			return r.Method + " " + tmpl
		}
	}

	return r.Method + " " + r.URL.Path
}

func outcome(status int) Status {
	switch {
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return StatusDenied
	case status >= 400:
		return StatusFailure
	default:
		return StatusSuccess
	}
}

func actorID(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")

	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}

	claims, err := utils.ParseToken(strings.TrimSpace(token))
	if err != nil || claims.Subject == "" {
		return "", false
	}

	return claims.Subject, true
}

func requestMetadata(r *http.Request, rec *statusRecorder, start time.Time) json.RawMessage {
	payload := map[string]any{
		"method":      r.Method,
		"path":        r.URL.Path,
		"status_code": rec.status,
		"duration_ms": time.Since(start).Milliseconds(),
		"bytes":       rec.written,
	}

	if q := r.URL.RawQuery; q != "" {
		payload["query"] = q
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil
	}

	return raw
}

// clientIP strips the port off RemoteAddr so the value fits an INET column.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// statusRecorder remembers the status code and body size written through it so
// the middleware can report the outcome after the handler returns.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int
	wrote   bool
}

func (rec *statusRecorder) WriteHeader(status int) {
	if !rec.wrote {
		rec.status = status
		rec.wrote = true
	}

	rec.ResponseWriter.WriteHeader(status)
}

func (rec *statusRecorder) Write(b []byte) (int, error) {
	if !rec.wrote {
		rec.wrote = true
	}

	n, err := rec.ResponseWriter.Write(b)
	rec.written += n

	return n, err
}
