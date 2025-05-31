// backend/internal/scenarios/errors.go

package scenarios

import "fmt"

// Error types for scenario management
type ScenarioError struct {
	Type    string
	Message string
	Err     error
}

func (e *ScenarioError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *ScenarioError) Unwrap() error {
	return e.Err
}

// Common error types
const (
	ErrTypeNotFound       = "SCENARIO_NOT_FOUND"
	ErrTypeInvalid        = "SCENARIO_INVALID"
	ErrTypeValidation     = "VALIDATION_ERROR"
	ErrTypeInitialization = "INITIALIZATION_ERROR"
	ErrTypeIO             = "IO_ERROR"
)

// Error constructors
func NewScenarioNotFoundError(id string) *ScenarioError {
	return &ScenarioError{
		Type:    ErrTypeNotFound,
		Message: fmt.Sprintf("scenario not found: %s", id),
	}
}

func NewScenarioInvalidError(id string, reason string) *ScenarioError {
	return &ScenarioError{
		Type:    ErrTypeInvalid,
		Message: fmt.Sprintf("scenario %s is invalid: %s", id, reason),
	}
}

func NewValidationError(taskID string, err error) *ScenarioError {
	return &ScenarioError{
		Type:    ErrTypeValidation,
		Message: fmt.Sprintf("validation failed for task %s", taskID),
		Err:     err,
	}
}

func NewInitializationError(scenarioID string, err error) *ScenarioError {
	return &ScenarioError{
		Type:    ErrTypeInitialization,
		Message: fmt.Sprintf("failed to initialize scenario %s", scenarioID),
		Err:     err,
	}
}

func NewIOError(operation string, path string, err error) *ScenarioError {
	return &ScenarioError{
		Type:    ErrTypeIO,
		Message: fmt.Sprintf("IO error during %s on %s", operation, path),
		Err:     err,
	}
}

// Helper to check error types
func IsNotFoundError(err error) bool {
	if se, ok := err.(*ScenarioError); ok {
		return se.Type == ErrTypeNotFound
	}
	return false
}

func IsValidationError(err error) bool {
	if se, ok := err.(*ScenarioError); ok {
		return se.Type == ErrTypeValidation
	}
	return false
}

func IsInitializationError(err error) bool {
	if se, ok := err.(*ScenarioError); ok {
		return se.Type == ErrTypeInitialization
	}
	return false
}
