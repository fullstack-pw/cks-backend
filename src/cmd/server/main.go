// backend/cmd/server/main.go

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/fullstack-pw/cks/backend/internal/clusterpool"
	"github.com/fullstack-pw/cks/backend/internal/config"
	"github.com/fullstack-pw/cks/backend/internal/controllers"
	"github.com/fullstack-pw/cks/backend/internal/kubevirt"
	"github.com/fullstack-pw/cks/backend/internal/middleware"
	"github.com/fullstack-pw/cks/backend/internal/scenarios"
	"github.com/fullstack-pw/cks/backend/internal/services"
	"github.com/fullstack-pw/cks/backend/internal/sessions"
	"github.com/fullstack-pw/cks/backend/internal/terminal"
	"github.com/fullstack-pw/cks/backend/internal/validation"
)

func main() {
	logger := logrus.New()
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
	}

	// Configure formatter based on config
	switch cfg.LogFormat {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
			DisableColors: false, // Enable colors for development
		})
	default:
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
			DisableColors: false,
		})
	}

	// Set log level based on configuration
	logLevel, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logger.WithError(err).Warn("Invalid log level, using info")
	}
	logger.SetLevel(logLevel)

	// Set up Gin
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Configure middleware
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{cfg.CorsAllowOrigin},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger())

	// Health check and metrics
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Create Kubernetes client configuration
	var k8sConfig *rest.Config
	if os.Getenv("KUBECONFIG") != "" {
		k8sConfig, err = clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
		if err != nil {
			logger.WithError(err).Fatal("Failed to build kubeconfig")
		}
	} else {
		// Use in-cluster configuration
		k8sConfig, err = rest.InClusterConfig()
		if err != nil {
			logger.WithError(err).Fatal("Failed to create in-cluster config")
		}
	}

	// Create Kubernetes client
	kubeClient, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create kubernetes client")
	}

	// Create KubeVirt client
	kubevirtClient, err := kubevirt.NewClient(k8sConfig, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create kubevirt client")
	}

	// Create unified validator (ADD THIS)
	unifiedValidator := validation.NewUnifiedValidator(kubevirtClient, logger)

	// Create terminal manager (existing)
	terminalManager := terminal.NewManager(kubeClient, kubevirtClient, k8sConfig, logger)

	// Create scenario manager first
	scenarioManager, err := scenarios.NewScenarioManager(cfg.ScenariosPath, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create scenario manager")
	}

	// Create cluster pool manager
	clusterPoolManager, err := clusterpool.NewManager(cfg, kubeClient, kubevirtClient, logger)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create cluster pool manager")
	}

	// Update session manager creation with cluster pool
	sessionManager, err := sessions.NewSessionManager(cfg, kubeClient, kubevirtClient, unifiedValidator, logger, scenarioManager, clusterPoolManager)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create session manager")
	}

	// Create service layer implementations
	sessionService := services.NewSessionService(sessionManager)
	terminalService := services.NewTerminalService(terminalManager)
	scenarioService := services.NewScenarioService(scenarioManager)
	sessionManager.SetTerminalCleanupFunc(terminalService.CleanupSessionSSH)

	// Create and register controllers
	sessionController := controllers.NewSessionController(sessionService, scenarioService, logger, unifiedValidator)
	sessionController.RegisterRoutes(router)

	terminalController := controllers.NewTerminalController(terminalService, sessionService, logger)
	terminalController.RegisterRoutes(router)

	scenarioController := controllers.NewScenarioController(scenarioService)
	scenarioController.RegisterRoutes(router)

	adminController := controllers.NewAdminController(sessionManager, kubevirtClient, logger)
	adminController.RegisterRoutes(router)

	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.ServerHost, cfg.ServerPort),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 300 * time.Second, // Longer timeout for WebSockets
		IdleTimeout:  60 * time.Second,
	}

	// Run server in a goroutine
	go func() {
		logger.WithFields(logrus.Fields{
			"host": cfg.ServerHost,
			"port": cfg.ServerPort,
		}).Info("Starting server")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Failed to start server")
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down server...")

	// Create context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Stop cluster pool manager
	clusterPoolManager.Stop()

	// Shutdown server
	if err := server.Shutdown(ctx); err != nil {
		logger.WithError(err).Fatal("Server forced to shutdown")
	}

	logger.Info("Server exited properly")
}
