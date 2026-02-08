// backend/internal/sessions/session_manager.go - SessionManager implementation

package sessions

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/fullstack-pw/cks/backend/internal/clusterpool"
	"github.com/fullstack-pw/cks/backend/internal/config"
	"github.com/fullstack-pw/cks/backend/internal/kubevirt"
	"github.com/fullstack-pw/cks/backend/internal/models"
	"github.com/fullstack-pw/cks/backend/internal/scenarios"
	"github.com/fullstack-pw/cks/backend/internal/validation"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
)

type SessionManager struct {
	sessions            map[string]*models.Session
	lock                sync.RWMutex
	clientset           *kubernetes.Clientset
	kubevirtClient      *kubevirt.Client
	config              *config.Config
	unifiedValidator    *validation.UnifiedValidator
	logger              *logrus.Logger
	stopCh              chan struct{}
	scenarioManager     *scenarios.ScenarioManager
	clusterPool         *clusterpool.Manager
}

func NewSessionManager(
	cfg *config.Config,
	clientset *kubernetes.Clientset,
	kubevirtClient *kubevirt.Client,
	unifiedValidator *validation.UnifiedValidator,
	logger *logrus.Logger,
	scenarioManager *scenarios.ScenarioManager,
	clusterPool *clusterpool.Manager,
) (*SessionManager, error) {
	sm := &SessionManager{
		sessions:         make(map[string]*models.Session),
		clientset:        clientset,
		kubevirtClient:   kubevirtClient,
		config:           cfg,
		unifiedValidator: unifiedValidator,
		logger:           logger,
		stopCh:           make(chan struct{}),
		scenarioManager:  scenarioManager,
		clusterPool:      clusterPool, // Add this line
	}

	// Clean stale terminals after backend restart
	sm.cleanStaleTerminals()

	// Start session cleanup goroutine
	go sm.cleanupExpiredSessions()

	return sm, nil
}

// CreateSession creates a new session using cluster pool assignment
func (sm *SessionManager) CreateSession(ctx context.Context, scenarioID string) (*models.Session, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	// Check if maximum sessions exceeded
	if len(sm.sessions) >= sm.config.MaxConcurrentSessions {
		return nil, fmt.Errorf("maximum number of concurrent sessions reached")
	}

	// Generate session ID
	sessionID := uuid.New().String()[:8]

	// Assign cluster from pool
	assignedCluster, err := sm.clusterPool.AssignCluster(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to assign cluster: %w", err)
	}

	sm.logger.WithFields(logrus.Fields{
		"sessionID": sessionID,
		"clusterID": assignedCluster.ClusterID,
		"namespace": assignedCluster.Namespace,
	}).Info("Cluster assigned to session")

	// Initialize variables
	var tasks []models.TaskStatus
	var scenarioTitle string

	// Load scenario if specified
	if scenarioID != "" {
		scenario, err := sm.loadScenario(ctx, scenarioID)
		if err != nil {
			// Release cluster on error
			sm.clusterPool.ReleaseCluster(sessionID)
			return nil, fmt.Errorf("failed to load scenario: %w", err)
		}

		// Store scenario title for logging
		scenarioTitle = scenario.Title

		// Initialize task statuses from loaded scenario
		tasks = make([]models.TaskStatus, 0, len(scenario.Tasks))
		for _, task := range scenario.Tasks {
			tasks = append(tasks, models.TaskStatus{
				ID:     task.ID,
				Status: "pending",
			})
		}

		sm.logger.WithFields(logrus.Fields{
			"sessionID":     sessionID,
			"scenarioID":    scenarioID,
			"scenarioTitle": scenarioTitle,
			"taskCount":     len(tasks),
		}).Info("Initialized session with scenario tasks")
	}

	// Create session object using assigned cluster
	session := &models.Session{
		ID:               sessionID,
		Namespace:        assignedCluster.Namespace, // Use cluster namespace
		ScenarioID:       scenarioID,
		Status:           models.SessionStatusRunning, // Immediate running status
		StartTime:        time.Now(),
		ExpirationTime:   time.Now().Add(time.Duration(sm.config.SessionTimeoutMinutes) * time.Minute),
		ControlPlaneVM:   assignedCluster.ControlPlaneVM, // Use cluster VMs
		WorkerNodeVM:     assignedCluster.WorkerNodeVM,   // Use cluster VMs
		Tasks:            tasks,
		TerminalSessions: make(map[string]string),
		ActiveTerminals:  make(map[string]models.TerminalInfo),
		AssignedCluster:  assignedCluster.ClusterID, // Track assigned cluster
		ClusterLockTime:  assignedCluster.LockTime,  // Track lock time
	}

	// Store session
	sm.sessions[sessionID] = session

	sm.logger.WithFields(logrus.Fields{
		"sessionID":      sessionID,
		"clusterID":      assignedCluster.ClusterID,
		"namespace":      session.Namespace,
		"scenarioID":     scenarioID,
		"scenarioTitle":  scenarioTitle,
		"controlPlaneVM": session.ControlPlaneVM,
		"workerNodeVM":   session.WorkerNodeVM,
	}).Info("Session created with assigned cluster - ready immediately")

	// Initialize scenario in background if needed
	if scenarioID != "" {
		go func() {
			initCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			err := sm.initializeScenario(initCtx, session)
			if err != nil {
				sm.logger.WithError(err).WithField("sessionID", sessionID).Error("Failed to initialize scenario (session still usable)")
			}
		}()
	}

	return session, nil
}

// GetSession returns a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*models.Session, error) {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	return session, nil
}

// ListSessions returns all active sessions
func (sm *SessionManager) ListSessions() []*models.Session {
	sm.lock.RLock()
	defer sm.lock.RUnlock()

	sessions := make([]*models.Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}

	return sessions
}

// DeleteSession deletes a session and releases its cluster
func (sm *SessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	sm.lock.Lock()
	session, ok := sm.sessions[sessionID]
	if !ok {
		sm.lock.Unlock()
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Remove from session map immediately
	delete(sm.sessions, sessionID)
	sm.lock.Unlock()

	sm.logger.WithFields(logrus.Fields{
		"sessionID": sessionID,
		"clusterID": session.AssignedCluster,
	}).Info("Deleting session and releasing cluster")

	// Release cluster back to pool
	if session.AssignedCluster != "" {
		err := sm.clusterPool.ReleaseCluster(sessionID)
		if err != nil {
			sm.logger.WithError(err).WithFields(logrus.Fields{
				"sessionID": sessionID,
				"clusterID": session.AssignedCluster,
			}).Error("Failed to release cluster")
		}
	}
	return nil
}

// ExtendSession extends the expiration time of a session
func (sm *SessionManager) ExtendSession(sessionID string, duration time.Duration) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Extend expiration time
	session.ExpirationTime = time.Now().Add(duration)

	sm.logger.WithFields(logrus.Fields{
		"sessionID":      sessionID,
		"expirationTime": session.ExpirationTime,
	}).Info("Session extended")

	return nil
}

// UpdateTaskStatus updates the status of a task in a session
func (sm *SessionManager) UpdateTaskStatus(sessionID, taskID string, status string) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Find task and update status
	found := false
	for i, task := range session.Tasks {
		if task.ID == taskID {
			session.Tasks[i].Status = status
			session.Tasks[i].ValidationTime = time.Now()
			found = true
			break
		}
	}

	// Task not found, add it
	if !found {
		session.Tasks = append(session.Tasks, models.TaskStatus{
			ID:             taskID,
			Status:         status,
			ValidationTime: time.Now(),
		})
	}

	sm.logger.WithFields(logrus.Fields{
		"sessionID": sessionID,
		"taskID":    taskID,
		"status":    status,
	}).Info("Task status updated")

	return nil
}

// Update ValidateTask method
func (sm *SessionManager) ValidateTask(ctx context.Context, sessionID, taskID string) (*validation.ValidationResponse, error) {
	// Get session
	session, err := sm.GetSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	// Check if session has a scenario
	if session.ScenarioID == "" {
		return nil, fmt.Errorf("session has no associated scenario")
	}

	sm.logger.WithFields(logrus.Fields{
		"sessionID":  sessionID,
		"taskID":     taskID,
		"scenarioID": session.ScenarioID,
	}).Debug("Starting task validation")

	// Load scenario to get task validation rules
	scenario, err := sm.loadScenario(ctx, session.ScenarioID)
	if err != nil {
		return nil, fmt.Errorf("failed to load scenario: %w", err)
	}

	sm.logger.WithFields(logrus.Fields{
		"scenarioID": scenario.ID,
		"taskCount":  len(scenario.Tasks),
		"tasks": func() []map[string]interface{} {
			taskInfo := make([]map[string]interface{}, len(scenario.Tasks))
			for i, t := range scenario.Tasks {
				taskInfo[i] = map[string]interface{}{
					"id":              t.ID,
					"title":           t.Title,
					"validationCount": len(t.Validation),
				}
			}
			return taskInfo
		}(),
	}).Debug("Loaded scenario for validation with task details")

	// Find task in scenario
	var taskToValidate *models.Task
	for i, task := range scenario.Tasks {
		sm.logger.WithFields(logrus.Fields{
			"checkingTaskID":  task.ID,
			"targetTaskID":    taskID,
			"taskTitle":       task.Title,
			"validationCount": len(task.Validation),
			"match":           task.ID == taskID,
		}).Debug("Checking task match")

		if task.ID == taskID {
			taskToValidate = &scenario.Tasks[i]
			sm.logger.WithFields(logrus.Fields{
				"taskID":    taskID,
				"foundTask": true,
				"validationRules": func() []map[string]interface{} {
					rules := make([]map[string]interface{}, len(task.Validation))
					for j, rule := range task.Validation {
						rules[j] = map[string]interface{}{
							"id":   rule.ID,
							"type": rule.Type,
						}
					}
					return rules
				}(),
			}).Debug("Found task with validation rules")
			break
		}
	}

	if taskToValidate == nil {
		sm.logger.WithFields(logrus.Fields{
			"sessionID":  sessionID,
			"taskID":     taskID,
			"scenarioID": session.ScenarioID,
			"availableTasks": func() []string {
				ids := make([]string, len(scenario.Tasks))
				for i, t := range scenario.Tasks {
					ids[i] = t.ID
				}
				return ids
			}(),
		}).Error("Task not found in scenario")

		return nil, fmt.Errorf("task %s not found in scenario %s", taskID, session.ScenarioID)
	}

	sm.logger.WithFields(logrus.Fields{
		"taskID":          taskID,
		"taskTitle":       taskToValidate.Title,
		"validationRules": len(taskToValidate.Validation),
	}).Info("Found task for validation")

	// Check if task has validation rules
	if len(taskToValidate.Validation) == 0 {
		sm.logger.WithFields(logrus.Fields{
			"sessionID":  sessionID,
			"taskID":     taskID,
			"scenarioID": session.ScenarioID,
		}).Warn("Task has no validation rules")

		// Return success if no validation rules
		return &validation.ValidationResponse{
			Success:   true,
			Message:   "No validation rules defined for this task",
			Results:   []validation.ValidationResult{},
			Timestamp: time.Now(),
		}, nil
	}

	// Log each validation rule
	for i, rule := range taskToValidate.Validation {
		sm.logger.WithFields(logrus.Fields{
			"taskID":    taskID,
			"ruleIndex": i,
			"ruleID":    rule.ID,
			"ruleType":  rule.Type,
		}).Debug("Validating rule")
	}

	// Validate task using the unified validator
	result, err := sm.unifiedValidator.ValidateTask(ctx, session, taskToValidate.Validation)
	if err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Update task status based on validation result
	status := "failed"
	if result.Success {
		status = "completed"
	}

	// Store validation result in session - NEW FUNCTIONALITY
	err = sm.UpdateTaskValidationResult(sessionID, taskID, status, result)
	if err != nil {
		sm.logger.WithError(err).WithFields(logrus.Fields{
			"sessionID": sessionID,
			"taskID":    taskID,
			"status":    status,
		}).Error("Failed to update task validation result")
		// Continue despite error - validation result is more important
	}

	sm.logger.WithFields(logrus.Fields{
		"sessionID": sessionID,
		"taskID":    taskID,
		"success":   result.Success,
		"status":    status,
		"details":   len(result.Results),
	}).Info("Task validation completed")

	return result, nil
}

func (sm *SessionManager) UpdateTaskValidationResult(sessionID, taskID string, status string, validationResult *validation.ValidationResponse) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Find task and update status and validation result
	found := false
	for i, task := range session.Tasks {
		if task.ID == taskID {
			session.Tasks[i].Status = status
			session.Tasks[i].ValidationTime = time.Now()
			session.Tasks[i].ValidationResult = &models.ValidationResponseRef{
				Success:   validationResult.Success,
				Message:   validationResult.Message,
				Timestamp: time.Now(),
			}
			found = true
			break
		}
	}

	// Task not found, add it
	if !found {
		session.Tasks = append(session.Tasks, models.TaskStatus{
			ID:             taskID,
			Status:         status,
			ValidationTime: time.Now(),
			ValidationResult: &models.ValidationResponseRef{
				Success:   validationResult.Success,
				Message:   validationResult.Message,
				Timestamp: time.Now(),
			},
		})
	}

	sm.logger.WithFields(logrus.Fields{
		"sessionID": sessionID,
		"taskID":    taskID,
		"status":    status,
		"success":   validationResult.Success,
	}).Info("Task validation result stored in session")

	return nil
}

// RegisterTerminalSession registers a terminal session for a VM
func (sm *SessionManager) RegisterTerminalSession(sessionID, terminalID, target string) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Initialize map if nil
	if session.TerminalSessions == nil {
		session.TerminalSessions = make(map[string]string)
	}

	session.TerminalSessions[terminalID] = target

	sm.logger.WithFields(logrus.Fields{
		"sessionID":  sessionID,
		"terminalID": terminalID,
		"target":     target,
	}).Debug("Terminal session registered")

	return nil
}

// UnregisterTerminalSession removes a terminal session
func (sm *SessionManager) UnregisterTerminalSession(sessionID, terminalID string) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Check if TerminalSessions map exists
	if session.TerminalSessions == nil {
		return nil // Nothing to unregister
	}

	delete(session.TerminalSessions, terminalID)

	sm.logger.WithFields(logrus.Fields{
		"sessionID":  sessionID,
		"terminalID": terminalID,
	}).Debug("Terminal session unregistered")

	return nil
}

// createNamespace creates a new namespace for the session
func (sm *SessionManager) createNamespace(ctx context.Context, namespace string) error {
	sm.logger.WithField("namespace", namespace).Info("Creating namespace")

	// Check if namespace already exists
	_, err := sm.clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{})
	if err == nil {
		// Namespace already exists, that's fine
		sm.logger.WithField("namespace", namespace).Info("Namespace already exists, continuing")
		return nil
	}

	// If error is NOT "not found", return the error
	if !errors.IsNotFound(err) {
		return fmt.Errorf("failed to check existing namespace: %w", err)
	}

	// Create namespace with labels
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
			Labels: map[string]string{
				"cks.io/session": "true",
			},
		},
	}

	_, err = sm.clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		// Double-check if it's an "already exists" error
		if errors.IsAlreadyExists(err) {
			sm.logger.WithField("namespace", namespace).Info("Namespace created by another process, continuing")
			return nil
		}
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	sm.logger.WithField("namespace", namespace).Info("Namespace created successfully")
	return nil
}

func (sm *SessionManager) setupResourceQuotas(ctx context.Context, namespace string) error {
	sm.logger.WithField("namespace", namespace).Info("Setting up resource quotas")

	// Create a resource quota with HIGHER limits for cluster pool
	quota := &corev1.ResourceQuota{
		ObjectMeta: metav1.ObjectMeta{
			Name: "session-quota",
		},
		Spec: corev1.ResourceQuotaSpec{
			Hard: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("16"),   // Increased from 4
				corev1.ResourceMemory: resource.MustParse("16Gi"), // Increased from 8Gi
				corev1.ResourcePods:   resource.MustParse("20"),   // Increased from 10
			},
		},
	}

	// Check if quota already exists
	existingQuota, err := sm.clientset.CoreV1().ResourceQuotas(namespace).Get(ctx, "session-quota", metav1.GetOptions{})
	if err == nil {
		// Update existing quota
		existingQuota.Spec = quota.Spec
		_, err = sm.clientset.CoreV1().ResourceQuotas(namespace).Update(ctx, existingQuota, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update resource quota: %w", err)
		}
		sm.logger.WithField("namespace", namespace).Info("Resource quota updated")
		return nil
	}

	// Create new quota if it doesn't exist
	if errors.IsNotFound(err) {
		_, err = sm.clientset.CoreV1().ResourceQuotas(namespace).Create(ctx, quota, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create resource quota: %w", err)
		}
		sm.logger.WithField("namespace", namespace).Info("Resource quota created")
		return nil
	}

	return fmt.Errorf("failed to check existing quota: %w", err)
}

// loadScenario loads a scenario by ID
func (sm *SessionManager) loadScenario(ctx context.Context, scenarioID string) (*models.Scenario, error) {
	return sm.scenarioManager.GetScenario(scenarioID)
}

// Update initializeScenario method
func (sm *SessionManager) initializeScenario(ctx context.Context, session *models.Session) error {
	if session.ScenarioID == "" {
		return fmt.Errorf("session has no scenario ID")
	}

	// Load scenario
	scenario, err := sm.scenarioManager.GetScenario(session.ScenarioID)
	if err != nil {
		return fmt.Errorf("failed to load scenario: %w", err)
	}

	sm.logger.WithFields(logrus.Fields{
		"sessionID":     session.ID,
		"scenarioID":    scenario.ID,
		"scenarioTitle": scenario.Title,
		"setupSteps":    len(scenario.SetupSteps),
	}).Info("Initializing scenario for session")

	// Check if scenario has setup steps
	if len(scenario.SetupSteps) == 0 {
		sm.logger.WithField("scenarioID", scenario.ID).Debug("No setup steps for scenario")
		return nil
	}

	// Create scenario initializer
	initializer := scenarios.NewScenarioInitializer(sm.clientset, sm.kubevirtClient, sm.logger)

	// Run initialization with timeout
	initCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	err = initializer.InitializeScenario(initCtx, session, scenario)
	if err != nil {
		return fmt.Errorf("scenario initialization failed: %w", err)
	}

	sm.logger.WithFields(logrus.Fields{
		"sessionID":  session.ID,
		"scenarioID": scenario.ID,
	}).Info("Scenario initialization completed")

	return nil
}

func (sm *SessionManager) GetSessionWithScenario(ctx context.Context, sessionID string) (*models.Session, *models.Scenario, error) {
	session, err := sm.GetSession(sessionID)
	if err != nil {
		return nil, nil, err
	}

	if session.ScenarioID == "" {
		return session, nil, nil
	}

	scenario, err := sm.loadScenario(ctx, session.ScenarioID)
	if err != nil {
		sm.logger.WithError(err).WithField("scenarioID", session.ScenarioID).Warn("Failed to load scenario for session")
		return session, nil, nil // Return session even if scenario fails to load
	}

	return session, scenario, nil
}

// cleanupExpiredSessions periodically checks and cleans up expired sessions
func (sm *SessionManager) cleanupExpiredSessions() {
	ticker := time.NewTicker(time.Duration(sm.config.CleanupIntervalMinutes) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.logger.Debug("Running session cleanup")

			// Use a context with timeout for cleanup operations
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

			// Find expired sessions
			expiredSessions := make([]string, 0)

			func() {
				sm.lock.Lock()
				defer sm.lock.Unlock()

				now := time.Now()

				// Find expired sessions
				for id, session := range sm.sessions {
					if now.After(session.ExpirationTime) &&
						session.Status != models.SessionStatusFailed {
						expiredSessions = append(expiredSessions, id)

						// Mark as failed to prevent race conditions
						session.Status = models.SessionStatusFailed
						session.StatusMessage = "Session expired"
					}
				}
			}()

			// Clean up marked sessions outside the lock
			for _, id := range expiredSessions {
				sm.logger.WithField("sessionID", id).Info("Cleaning up expired session")

				// Get session with lock
				var session *models.Session
				func() {
					sm.lock.RLock()
					defer sm.lock.RUnlock()
					session = sm.sessions[id]
				}()

				if session != nil {
					// Clean up resources
					err := sm.DeleteSession(ctx, id)
					if err != nil {
						sm.logger.WithError(err).WithField("sessionID", id).Error("Error cleaning up expired session environment")
					}

					// Now remove from sessions map with proper locking
					sm.lock.Lock()
					delete(sm.sessions, id)
					sm.lock.Unlock()

					sm.logger.WithField("sessionID", id).Info("Expired session removed")
				}
			}

			// Always cancel the context when done
			cancel()

		case <-sm.stopCh:
			return
		}
	}
}

// Stop stops the session manager and releases resources
func (sm *SessionManager) Stop() {
	close(sm.stopCh)
	sm.logger.Info("Session manager stopped")
}

// CheckVMsStatus checks the status of VMs in a session including SSH readiness
func (sm *SessionManager) CheckVMsStatus(ctx context.Context, session *models.Session) (string, error) {
	controlPlaneStatus, err := sm.kubevirtClient.GetVMStatus(ctx, session.Namespace, session.ControlPlaneVM)
	if err != nil {
		return "", fmt.Errorf("failed to get control plane VM status: %w", err)
	}

	workerNodeStatus, err := sm.kubevirtClient.GetVMStatus(ctx, session.Namespace, session.WorkerNodeVM)
	if err != nil {
		return "", fmt.Errorf("failed to get worker node VM status: %w", err)
	}

	sm.logger.WithFields(logrus.Fields{
		"sessionID":          session.ID,
		"controlPlaneStatus": controlPlaneStatus,
		"workerNodeStatus":   workerNodeStatus,
	}).Debug("VM status check")

	// Only return "Running" if both VMs are running
	if controlPlaneStatus == "Running" && workerNodeStatus == "Running" {
		// For cluster pool sessions, also check SSH readiness
		if session.AssignedCluster != "" {
			sm.logger.WithField("sessionID", session.ID).Debug("Checking SSH readiness for cluster pool VMs")

			// Check SSH readiness with timeout
			sshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			cpSSHReady, _ := sm.kubevirtClient.IsVMSSHReady(sshCtx, session.Namespace, session.ControlPlaneVM)
			workerSSHReady, _ := sm.kubevirtClient.IsVMSSHReady(sshCtx, session.Namespace, session.WorkerNodeVM)

			sm.logger.WithFields(logrus.Fields{
				"sessionID":      session.ID,
				"cpSSHReady":     cpSSHReady,
				"workerSSHReady": workerSSHReady,
			}).Debug("SSH readiness check completed")

			// If SSH is ready for both, return "Running"
			if cpSSHReady && workerSSHReady {
				return "Running", nil
			}

			// If VMs are running but SSH not ready, return "Starting"
			return "Starting", nil
		}

		return "Running", nil
	}

	// Return the status of the control plane since it's more critical
	return controlPlaneStatus, nil
}

// UpdateSessionStatus updates the status of a session
func (sm *SessionManager) UpdateSessionStatus(sessionID string, status models.SessionStatus, message string) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Update status
	session.Status = status
	session.StatusMessage = message

	sm.logger.WithFields(logrus.Fields{
		"sessionID": sessionID,
		"status":    status,
		"message":   message,
	}).Info("Session status updated")

	return nil
}

func (sm *SessionManager) GetOrCreateTerminalSession(sessionID, target string) (string, bool, error) {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return "", false, fmt.Errorf("session not found: %s", sessionID)
	}

	// Generate deterministic terminal ID (matching TerminalManager logic)
	expectedTerminalID := fmt.Sprintf("%s-%s", sessionID, target)

	// Initialize ActiveTerminals if nil
	if session.ActiveTerminals == nil {
		session.ActiveTerminals = make(map[string]models.TerminalInfo)
	}

	// Check if terminal already exists with the expected ID
	if terminalInfo, exists := session.ActiveTerminals[expectedTerminalID]; exists {
		if terminalInfo.Status == "active" {
			// Update last used time
			terminalInfo.LastUsedAt = time.Now()
			session.ActiveTerminals[expectedTerminalID] = terminalInfo

			sm.logger.WithFields(logrus.Fields{
				"sessionID":  sessionID,
				"terminalID": expectedTerminalID,
				"target":     target,
			}).Info("Reusing existing terminal session with deterministic ID")

			return expectedTerminalID, true, nil // true = existing terminal
		}
	}

	// No existing active terminal found, will need to create new one
	// Return the deterministic ID that should be created
	return expectedTerminalID, false, nil // false = needs new terminal
}

// StoreTerminalSession stores terminal info in session
func (sm *SessionManager) StoreTerminalSession(sessionID, terminalID, target string) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Verify that the terminalID matches our deterministic pattern
	expectedTerminalID := fmt.Sprintf("%s-%s", sessionID, target)
	if terminalID != expectedTerminalID {
		sm.logger.WithFields(logrus.Fields{
			"sessionID":          sessionID,
			"providedTerminalID": terminalID,
			"expectedTerminalID": expectedTerminalID,
			"target":             target,
		}).Warn("Terminal ID mismatch - using expected deterministic ID")
		terminalID = expectedTerminalID
	}

	// Initialize ActiveTerminals if nil
	if session.ActiveTerminals == nil {
		session.ActiveTerminals = make(map[string]models.TerminalInfo)
	}

	// Store or update terminal info
	session.ActiveTerminals[terminalID] = models.TerminalInfo{
		ID:         terminalID,
		Target:     target,
		Status:     "active",
		CreatedAt:  time.Now(),
		LastUsedAt: time.Now(),
	}

	// Also maintain existing TerminalSessions map for backward compatibility
	if session.TerminalSessions == nil {
		session.TerminalSessions = make(map[string]string)
	}
	session.TerminalSessions[terminalID] = target

	sm.logger.WithFields(logrus.Fields{
		"sessionID":  sessionID,
		"terminalID": terminalID,
		"target":     target,
	}).Info("Stored terminal session info with deterministic ID")

	return nil
}

// MarkTerminalInactive marks a terminal as inactive
func (sm *SessionManager) MarkTerminalInactive(sessionID, terminalID string) error {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	if session.ActiveTerminals != nil {
		if terminalInfo, exists := session.ActiveTerminals[terminalID]; exists {
			terminalInfo.Status = "disconnected"
			terminalInfo.LastUsedAt = time.Now()
			session.ActiveTerminals[terminalID] = terminalInfo
		}
	}

	return nil
}

// CLUSTER POOL

// BootstrapClusterPool creates 3 baseline clusters in static namespaces
func (sm *SessionManager) BootstrapClusterPool(ctx context.Context) error {
	clusterIDs := []string{"cluster1", "cluster2", "cluster3"}

	sm.logger.Info("Starting cluster pool bootstrap")

	// Bootstrap clusters SEQUENTIALLY to avoid resource conflicts
	for _, clusterID := range clusterIDs {
		sm.logger.WithField("clusterID", clusterID).Info("Starting bootstrap for cluster")

		err := sm.bootstrapClusterInNamespace(ctx, clusterID)
		if err != nil {
			return fmt.Errorf("failed to bootstrap cluster %s: %w", clusterID, err)
		}

		sm.logger.WithField("clusterID", clusterID).Info("Cluster bootstrap completed")

		// Add delay between cluster bootstraps to avoid resource conflicts
		time.Sleep(30 * time.Second)
	}

	sm.logger.Info("All clusters bootstrapped successfully")
	return nil
}

// bootstrapClusterInNamespace bootstraps one cluster using existing proven logic
func (sm *SessionManager) bootstrapClusterInNamespace(ctx context.Context, clusterID string) error {
	namespace := clusterID // namespace matches clusterID

	sm.logger.WithField("clusterID", clusterID).Info("Bootstrapping cluster")

	// Use EXISTING VM naming pattern to avoid breaking join command logic
	controlPlaneVM := fmt.Sprintf("cp-%s", clusterID)
	workerNodeVM := fmt.Sprintf("wk-%s", clusterID)

	// Create session object to use with existing provisionFromBootstrap
	session := &models.Session{
		ID:             clusterID, // Use clusterID as session ID
		Namespace:      namespace, // Use static cluster namespace
		Status:         models.SessionStatusProvisioning,
		ControlPlaneVM: controlPlaneVM, // Keep existing naming pattern
		WorkerNodeVM:   workerNodeVM,   // Keep existing naming pattern
		StartTime:      time.Now(),
		ExpirationTime: time.Now().Add(240 * time.Hour), // Long expiration for pool clusters
	}

	// Clean up existing resources if they exist
	err := sm.cleanupExistingCluster(ctx, session)
	if err != nil {
		sm.logger.WithError(err).WithField("clusterID", clusterID).Warn("Failed to cleanup existing cluster, continuing...")
	}

	// Use existing proven provisionFromBootstrap method with bootstrap flag
	err = sm.provisionFromBootstrapForClusterPool(ctx, session)
	if err != nil {
		return fmt.Errorf("failed to bootstrap cluster %s: %w", clusterID, err)
	}

	sm.logger.WithField("clusterID", clusterID).Info("Cluster bootstrap completed")

	// ADD THIS LINE - Mark cluster as available in the pool
	err = sm.clusterPool.MarkClusterAvailable(clusterID)
	if err != nil {
		sm.logger.WithError(err).WithField("clusterID", clusterID).Error("Failed to mark cluster as available")
		return fmt.Errorf("failed to mark cluster available: %w", err)
	}

	return nil
}

// cleanupExistingCluster removes existing VMs and resources before bootstrap
func (sm *SessionManager) cleanupExistingCluster(ctx context.Context, session *models.Session) error {
	sm.logger.WithField("namespace", session.Namespace).Info("Cleaning up existing cluster resources")

	// Delete existing VMs if they exist
	err := sm.kubevirtClient.DeleteVMs(ctx, session.Namespace, session.ControlPlaneVM, session.WorkerNodeVM)
	if err != nil {
		sm.logger.WithError(err).Warn("Failed to delete existing VMs")
	}

	// Wait a bit for cleanup to complete
	time.Sleep(10 * time.Second)

	return nil
}

// provisionFromBootstrapForClusterPool provisions a cluster for the pool (no session status updates)
func (sm *SessionManager) provisionFromBootstrapForClusterPool(ctx context.Context, session *models.Session) error {
	sm.logger.WithField("clusterID", session.ID).Info("Provisioning cluster for pool using bootstrap method")

	// Verify KubeVirt is available
	err := sm.kubevirtClient.VerifyKubeVirtAvailable(ctx)
	if err != nil {
		sm.logger.WithError(err).Error("Failed to verify KubeVirt availability")
		return fmt.Errorf("failed to verify KubeVirt availability: %w", err)
	}

	// Create namespace
	namespaceCtx, cancelNamespace := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelNamespace()
	err = sm.createNamespace(namespaceCtx, session.Namespace)
	if err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}

	// Add a short delay to ensure the namespace is fully created
	time.Sleep(2 * time.Second)

	// Set up resource quotas
	quotaCtx, cancelQuota := context.WithTimeout(ctx, 2*time.Minute)
	defer cancelQuota()
	sm.logger.WithField("namespace", session.Namespace).Info("Setting up resource quotas")
	err = sm.setupResourceQuotas(quotaCtx, session.Namespace)
	if err != nil {
		return fmt.Errorf("failed to set up resource quotas: %w", err)
	}

	// Add a short delay to ensure resource quotas are applied
	time.Sleep(2 * time.Second)

	// Create KubeVirt VMs
	vmCtx, cancelVM := context.WithTimeout(ctx, 10*time.Minute)
	defer cancelVM()
	sm.logger.WithField("clusterID", session.ID).Info("Creating KubeVirt VMs")
	err = sm.kubevirtClient.CreateCluster(vmCtx, session.Namespace, session.ControlPlaneVM, session.WorkerNodeVM)
	if err != nil {
		return fmt.Errorf("failed to create VMs: %w", err)
	}

	// Wait for VMs to be ready
	waitCtx, cancelWait := context.WithTimeout(ctx, 15*time.Minute)
	defer cancelWait()
	sm.logger.WithField("clusterID", session.ID).Info("Waiting for VMs to be ready")
	err = sm.kubevirtClient.WaitForVMsReady(waitCtx, session.Namespace, session.ControlPlaneVM, session.WorkerNodeVM)
	if err != nil {
		return fmt.Errorf("failed waiting for VMs: %w", err)
	}

	// NO scenario initialization needed for cluster pool
	// NO session status updates needed for cluster pool

	sm.logger.WithField("clusterID", session.ID).Info("Cluster pool bootstrap completed successfully")
	return nil
}

// cleanStaleTerminals removes terminal sessions that don't exist in TerminalManager
func (sm *SessionManager) cleanStaleTerminals() {
	sm.lock.Lock()
	defer sm.lock.Unlock()

	sm.logger.Info("Checking for stale terminals on startup")

	// Don't clear terminals on restart - let them reconnect
	// Only clear if explicitly marked as disconnected for too long
	for sessionID, session := range sm.sessions {
		if session.ActiveTerminals != nil {
			for terminalID, terminalInfo := range session.ActiveTerminals {
				// Only clear if disconnected for more than 5 minutes
				if terminalInfo.Status == "disconnected" &&
					time.Since(terminalInfo.LastUsedAt) > 5*time.Minute {
					delete(session.ActiveTerminals, terminalID)
					sm.logger.WithFields(logrus.Fields{
						"sessionID":  sessionID,
						"terminalID": terminalID,
					}).Info("Removed stale disconnected terminal")
				}
			}
		}
	}
}

// GetClusterPool returns the cluster pool manager for admin operations
func (sm *SessionManager) GetClusterPool() *clusterpool.Manager {
	return sm.clusterPool
}
