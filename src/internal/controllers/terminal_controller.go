// backend/internal/controllers/terminal_controller.go

package controllers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/fullstack-pw/cks/backend/internal/models"
	"github.com/fullstack-pw/cks/backend/internal/services"
)

// TerminalController handles HTTP requests related to terminal sessions
type TerminalController struct {
	terminalService services.TerminalService
	sessionService  services.SessionService
	logger          *logrus.Logger
}

// NewTerminalController creates a new terminal controller
func NewTerminalController(
	terminalService services.TerminalService,
	sessionService services.SessionService,
	logger *logrus.Logger,
) *TerminalController {
	return &TerminalController{
		terminalService: terminalService,
		sessionService:  sessionService,
		logger:          logger,
	}
}

// RegisterRoutes registers terminal-related routes
func (tc *TerminalController) RegisterRoutes(router *gin.Engine) {
	// Terminal routes
	router.POST("/api/v1/sessions/:id/terminals", tc.CreateTerminal)

	terminals := router.Group("/api/v1/terminals")
	{
		terminals.GET("/:id/attach", tc.AttachTerminal)
		terminals.POST("/:id/resize", tc.ResizeTerminal)
		terminals.DELETE("/:id", tc.CloseTerminal)
	}
}

// CreateTerminal creates a new terminal session or reuses existing one
func (tc *TerminalController) CreateTerminal(c *gin.Context) {
	sessionID := c.Param("id")

	var request models.CreateTerminalRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		tc.logger.WithError(err).Error("Invalid terminal creation request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	// Check if session exists
	session, err := tc.sessionService.GetSession(sessionID)
	if err != nil {
		tc.logger.WithError(err).WithField("sessionID", sessionID).Error("Session not found")
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Session not found: %v", err)})
		return
	}

	// Check if session is in running state
	if session.Status != models.SessionStatusRunning {
		tc.logger.WithFields(logrus.Fields{
			"sessionID": sessionID,
			"status":    session.Status,
		}).Warn("Attempted to create terminal for non-running session")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Session is not ready yet, current status: %s", session.Status),
		})
		return
	}

	// Validate target
	targetVM := ""
	switch request.Target {
	case "control-plane":
		targetVM = session.ControlPlaneVM
	case "worker-node":
		targetVM = session.WorkerNodeVM
	default:
		tc.logger.WithField("target", request.Target).Error("Invalid terminal target")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid terminal target"})
		return
	}

	// Always create or get terminal session
	terminalID, err := tc.terminalService.CreateSession(sessionID, session.Namespace, targetVM)
	if err != nil {
		tc.logger.WithError(err).Error("Failed to create terminal session")
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create terminal: %v", err)})
		return
	}

	// Store terminal info in session
	err = tc.sessionService.StoreTerminalSession(sessionID, terminalID, request.Target)
	if err != nil {
		tc.logger.WithError(err).Error("Failed to store terminal session info")
		// Continue anyway, don't fail the request
	}

	tc.logger.WithFields(logrus.Fields{
		"sessionID":  sessionID,
		"terminalID": terminalID,
		"target":     request.Target,
	}).Info("Terminal session created/retrieved")

	c.JSON(http.StatusOK, models.CreateTerminalResponse{
		TerminalID: terminalID,
	})
}

// AttachTerminal handles WebSocket connection to a terminal
func (tc *TerminalController) AttachTerminal(c *gin.Context) {
	terminalID := c.Param("id")

	tc.logger.WithField("terminalID", terminalID).Info("Attaching to terminal session")

	// Add CORS headers for WebSocket connections
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
	c.Header("Access-Control-Allow-Credentials", "true")

	// Handle WebSocket using the service
	tc.terminalService.HandleTerminal(c.Writer, c.Request, terminalID)
}

// ResizeTerminal handles terminal resize events
func (tc *TerminalController) ResizeTerminal(c *gin.Context) {
	terminalID := c.Param("id")

	var request models.ResizeTerminalRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		tc.logger.WithError(err).Error("Invalid resize request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid resize request"})
		return
	}

	// Validate dimensions
	if request.Rows == 0 || request.Cols == 0 {
		tc.logger.WithFields(logrus.Fields{
			"terminalID": terminalID,
			"rows":       request.Rows,
			"cols":       request.Cols,
		}).Error("Invalid terminal dimensions")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid terminal dimensions"})
		return
	}

	// Resize terminal using the service
	err := tc.terminalService.ResizeTerminal(terminalID, request.Rows, request.Cols)
	if err != nil {
		tc.logger.WithError(err).WithField("terminalID", terminalID).Error("Failed to resize terminal")
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to resize terminal: %v", err)})
		return
	}

	tc.logger.WithFields(logrus.Fields{
		"terminalID": terminalID,
		"rows":       request.Rows,
		"cols":       request.Cols,
	}).Debug("Terminal resized")

	c.JSON(http.StatusOK, gin.H{"message": "Terminal resized"})
}

// CloseTerminal closes a terminal session
func (tc *TerminalController) CloseTerminal(c *gin.Context) {
	terminalID := c.Param("id")

	// Close terminal session using the service
	err := tc.terminalService.CloseSession(terminalID)
	if err != nil {
		tc.logger.WithError(err).WithField("terminalID", terminalID).Error("Failed to close terminal")
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to close terminal: %v", err)})
		return
	}

	// Unregister terminal session from all sessions
	// This needs to be refactored to be more service-oriented
	sessions := tc.sessionService.ListSessions()
	for _, session := range sessions {
		for id := range session.TerminalSessions {
			if id == terminalID {
				unregErr := tc.sessionService.UnregisterTerminalSession(session.ID, terminalID)
				if unregErr != nil {
					tc.logger.WithError(unregErr).WithFields(logrus.Fields{
						"sessionID":  session.ID,
						"terminalID": terminalID,
					}).Warn("Failed to unregister terminal session, continuing anyway")
				}
				break
			}
		}
	}

	tc.logger.WithField("terminalID", terminalID).Info("Terminal session closed")
	c.JSON(http.StatusOK, gin.H{"message": "Terminal closed"})
}
