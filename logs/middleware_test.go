package logs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// fakePublisher records what the middleware hands it. Publishing runs on its
// own goroutine, so access is guarded and tests wait on the channel.
type fakePublisher struct {
	mu      sync.Mutex
	entries []AuditLog
	got     chan struct{}
}

func newFakePublisher() *fakePublisher {
	return &fakePublisher{got: make(chan struct{}, 8)}
}

func (f *fakePublisher) PublishJSON(queueName string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	var entry AuditLog
	if err := json.Unmarshal(raw, &entry); err != nil {
		return err
	}

	f.mu.Lock()
	f.entries = append(f.entries, entry)
	f.mu.Unlock()

	f.got <- struct{}{}

	return nil
}

func (f *fakePublisher) waitForEntry(t *testing.T) AuditLog {
	t.Helper()

	select {
	case <-f.got:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for an audit entry")
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	return f.entries[len(f.entries)-1]
}

func newRouter(pub Publisher) *mux.Router {
	r := mux.NewRouter()
	r.Use(Middleware(pub))

	r.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)

	r.HandleFunc("/auth/login", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}).Methods(http.MethodPost)

	return r
}

func TestMiddleware_RecordsSuccessfulRequest(t *testing.T) {
	pub := newFakePublisher()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	req.Header.Set("User-Agent", "probe/1.0")

	w := httptest.NewRecorder()
	newRouter(pub).ServeHTTP(w, req)

	if got := w.Header().Get("X-Request-ID"); got == "" {
		t.Error("expected an X-Request-ID response header")
	}

	entry := pub.waitForEntry(t)

	if entry.Action != "health.check" {
		t.Errorf("action: got %q, want %q", entry.Action, "health.check")
	}

	if entry.Status != StatusSuccess {
		t.Errorf("status: got %q, want %q", entry.Status, StatusSuccess)
	}

	if entry.ActorType != "anonymous" {
		t.Errorf("actor type: got %q, want %q", entry.ActorType, "anonymous")
	}

	if entry.ActorIP == nil || *entry.ActorIP != "203.0.113.7" {
		t.Errorf("actor ip: got %v, want %q", entry.ActorIP, "203.0.113.7")
	}

	if entry.RequestID == nil || *entry.RequestID == "" {
		t.Error("expected a request id on the entry")
	}
}

func TestMiddleware_UnauthorizedIsRecordedAsDenied(t *testing.T) {
	pub := newFakePublisher()

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	w := httptest.NewRecorder()
	newRouter(pub).ServeHTTP(w, req)

	entry := pub.waitForEntry(t)

	if entry.Action != "auth.login" {
		t.Errorf("action: got %q, want %q", entry.Action, "auth.login")
	}

	if entry.Status != StatusDenied {
		t.Errorf("status: got %q, want %q", entry.Status, StatusDenied)
	}
}

func TestMiddleware_NilPublisherDoesNotPanic(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	newRouter(nil).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want %d", w.Code, http.StatusOK)
	}
}
