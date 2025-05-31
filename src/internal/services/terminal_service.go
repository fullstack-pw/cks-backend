// backend/internal/services/terminal_service.go

package services

import (
	"net/http"

	"github.com/fullstack-pw/cks/backend/internal/terminal"
)

// TerminalServiceImpl implements the TerminalService interface
type TerminalServiceImpl struct {
	terminalManager *terminal.Manager
}

// NewTerminalService creates a new terminal service
func NewTerminalService(terminalManager *terminal.Manager) TerminalService {
	return &TerminalServiceImpl{
		terminalManager: terminalManager,
	}
}

// CreateSession creates a new terminal session
func (t *TerminalServiceImpl) CreateSession(sessionID, namespace, target string) (string, error) {
	return t.terminalManager.CreateSession(sessionID, namespace, target)
}

// HandleTerminal handles a terminal connection
func (t *TerminalServiceImpl) HandleTerminal(w http.ResponseWriter, r *http.Request, terminalID string) {
	t.terminalManager.HandleTerminal(w, r, terminalID)
}

// ResizeTerminal resizes a terminal
func (t *TerminalServiceImpl) ResizeTerminal(terminalID string, rows, cols uint16) error {
	return t.terminalManager.ResizeTerminal(terminalID, rows, cols)
}

// CloseSession closes a terminal session
func (t *TerminalServiceImpl) CloseSession(terminalID string) error {
	return t.terminalManager.CloseSession(terminalID)
}

// CleanupSessionSSH cleans up persistent SSH connections for a session
func (t *TerminalServiceImpl) CleanupSessionSSH(sessionID string) {
	t.terminalManager.CleanupSessionSSH(sessionID)
}
