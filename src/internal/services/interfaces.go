// backend/internal/services/interfaces.go

package services

import (
	"context"
	"net/http"
	"time"

	"github.com/fullstack-pw/cks/backend/internal/models"
	"github.com/fullstack-pw/cks/backend/internal/validation"
)

// SessionService defines the interface for session-related operations
type SessionService interface {
	CreateSession(ctx context.Context, scenarioID string) (*models.Session, error)
	GetSession(sessionID string) (*models.Session, error)
	ListSessions() []*models.Session
	DeleteSession(ctx context.Context, sessionID string) error
	ExtendSession(sessionID string, duration time.Duration) error
	UpdateTaskStatus(sessionID, taskID string, status string) error
	ValidateTask(ctx context.Context, sessionID, taskID string) (*validation.ValidationResponse, error)
	CheckVMsStatus(ctx context.Context, session *models.Session) (string, error)
	UpdateSessionStatus(sessionID string, status models.SessionStatus, message string) error
	RegisterTerminalSession(sessionID, terminalID, target string) error
	UnregisterTerminalSession(sessionID, terminalID string) error
	GetOrCreateTerminalSession(sessionID, target string) (string, bool, error)
	StoreTerminalSession(sessionID, terminalID, target string) error
	MarkTerminalInactive(sessionID, terminalID string) error
}

// TerminalService defines the interface for terminal-related operations
type TerminalService interface {
	CreateSession(sessionID, namespace, target string) (string, error)
	HandleTerminal(w http.ResponseWriter, r *http.Request, terminalID string)
	ResizeTerminal(terminalID string, rows, cols uint16) error
	CloseSession(terminalID string) error
	CleanupSessionSSH(sessionID string) // Add this method
}

// ScenarioService defines the interface for scenario-related operations
type ScenarioService interface {
	GetScenario(id string) (*models.Scenario, error)
	ListScenarios(category, difficulty, searchQuery string) ([]*models.Scenario, error)
	GetCategories() (map[string]string, error)
	ReloadScenarios() error
}
