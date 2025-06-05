// backend/internal/middleware/middleware.go - Common middleware for the application

package middleware

import (
	"bytes"
	"io"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// RequestID adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := uuid.New().String()
		c.Set("RequestID", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

// Logger logs request details using logrus
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Start timer
		startTime := time.Now()
		path := c.Request.URL.Path

		// Get request ID
		requestID, exists := c.Get("RequestID")
		if !exists {
			requestID = "unknown"
		}

		// Process request
		c.Next()

		// Skip logging for WebSocket connections
		if c.IsWebsocket() {
			return
		}

		// Skip logging for health check endpoints
		if path == "/health" || path == "/metrics" {
			return
		}

		// End timer
		endTime := time.Now()
		latency := endTime.Sub(startTime)

		// Get client IP
		clientIP := c.ClientIP()

		// Get user agent
		userAgent := c.Request.UserAgent()

		// Get response status
		statusCode := c.Writer.Status()

		// Get response size
		responseSize := c.Writer.Size()

		// Log request details
		entry := logrus.WithFields(logrus.Fields{
			"requestID":    requestID,
			"method":       c.Request.Method,
			"path":         path,
			"status":       statusCode,
			"latency":      latency,
			"ip":           clientIP,
			"userAgent":    userAgent,
			"responseSize": responseSize,
		})

		if len(c.Errors) > 0 {
			// Log with context errors
			entry.Error(c.Errors.String())
		} else if statusCode >= 500 {
			entry.Error("Server error")
		} else if statusCode >= 400 {
			entry.Warn("Client error")
		} else {
			entry.Info("Request processed")
		}
	}
}

// LogRequestBody logs the request body for debug purposes
func LogRequestBody() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only log for debug level
		logger := logrus.StandardLogger()
		if logger.Level != logrus.DebugLevel {
			c.Next()
			return
		}

		// Skip WebSocket connections
		if c.IsWebsocket() {
			c.Next()
			return
		}

		// Read the request body
		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
		}

		// Restore the request body
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Log the request body if it's not too large
		if len(bodyBytes) > 0 && len(bodyBytes) < 10000 {
			// Get request ID
			requestID, exists := c.Get("RequestID")
			if !exists {
				requestID = "unknown"
			}

			logger.WithFields(logrus.Fields{
				"requestID": requestID,
				"method":    c.Request.Method,
				"path":      c.Request.URL.Path,
				"body":      string(bodyBytes),
			}).Debug("Request body")
		}

		c.Next()
	}
}

// ErrorHandler handles API errors
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Handle errors
		if len(c.Errors) > 0 {
			// Get last error
			err := c.Errors.Last()

			// Determine status code
			statusCode := c.Writer.Status()
			if statusCode == 200 {
				statusCode = 500 // Default to internal server error
			}

			// Send error response
			c.JSON(statusCode, gin.H{
				"error": err.Error(),
			})
		}
	}
}
