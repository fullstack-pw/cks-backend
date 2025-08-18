// internal/config/config.go - Add Kubernetes context configuration

package config

// Config contains application configuration
type Config struct {
	// Server settings
	ServerHost      string
	ServerPort      int
	Environment     string
	LogLevel        string
	CorsAllowOrigin string
	LogFormat       string

	// Kubernetes settings
	KubernetesContext string
	KubeconfigPath    string

	// Session settings
	SessionTimeoutMinutes  int
	MaxConcurrentSessions  int
	CleanupIntervalMinutes int

	// VM settings
	TemplatePath         string
	KubernetesVersion    string
	VMCPUCores           string
	VMMemory             string
	VMStorageSize        string
	VMStorageClass       string
	VMImageURL           string
	PodCIDR              string
	GoldenImageName      string // Name of the golden image PVC
	GoldenImageNamespace string // Namespace where golden images are stored
	ValidateGoldenImage  bool   // Whether to validate image exists before VM creation

	// Scenario settings
	ScenariosPath string
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	config := &Config{
		// Server defaults
		ServerHost:      getEnv("SERVER_HOST", "0.0.0.0"),
		ServerPort:      getEnvAsInt("SERVER_PORT", 8080),
		Environment:     getEnv("ENVIRONMENT", "dev"),
		LogLevel:        getEnv("LOG_LEVEL", "info"),
		CorsAllowOrigin: getEnv("CORS_ALLOW_ORIGIN", "*"),
		LogFormat:       getEnv("LOG_FORMAT", "text"),

		// Kubernetes defaults
		KubernetesContext: getEnv("KUBERNETES_CONTEXT", "sandboxy"),
		KubeconfigPath:    getEnv("KUBECONFIG", ""),

		// Session defaults
		SessionTimeoutMinutes:  getEnvAsInt("SESSION_TIMEOUT_MINUTES", 60),
		MaxConcurrentSessions:  getEnvAsInt("MAX_CONCURRENT_SESSIONS", 10),
		CleanupIntervalMinutes: getEnvAsInt("CLEANUP_INTERVAL_MINUTES", 5),

		// VM defaults
		TemplatePath:         getEnv("TEMPLATE_PATH", "templates"),
		KubernetesVersion:    getEnv("KUBERNETES_VERSION", "1.33.0"),
		VMCPUCores:           getEnv("VM_CPU_CORES", "2"),
		VMMemory:             getEnv("VM_MEMORY", "2Gi"),
		VMStorageSize:        getEnv("VM_STORAGE_SIZE", "10Gi"),
		VMStorageClass:       getEnv("VM_STORAGE_CLASS", "longhorn"),
		VMImageURL:           getEnv("VM_IMAGE_URL", "https://cloud-images.ubuntu.com/releases/22.04/release/ubuntu-22.04-server-cloudimg-amd64.img"),
		PodCIDR:              getEnv("POD_CIDR", "10.0.0.0/8"),
		GoldenImageName:      getEnv("GOLDEN_IMAGE_NAME", "new-golden-image-1-33-0"),
		GoldenImageNamespace: getEnv("GOLDEN_IMAGE_NAMESPACE", "vm-templates"),
		ValidateGoldenImage:  getEnvAsBool("VALIDATE_GOLDEN_IMAGE", true),

		// Scenario defaults
		ScenariosPath: getEnv("SCENARIOS_PATH", "scenarios"),
	}

	return config, nil
}
