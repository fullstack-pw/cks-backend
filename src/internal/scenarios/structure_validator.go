package scenarios

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

type StructureValidator struct {
	scenarioPath string
}

func NewStructureValidator(scenarioPath string) *StructureValidator {
	return &StructureValidator{
		scenarioPath: scenarioPath,
	}
}

func (sv *StructureValidator) Validate() error {
	// Check metadata.yaml exists
	metadataPath := filepath.Join(sv.scenarioPath, "metadata.yaml")
	if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
		return fmt.Errorf("missing metadata.yaml in %s", sv.scenarioPath)
	}

	// Check tasks directory
	tasksDir := filepath.Join(sv.scenarioPath, "tasks")
	if _, err := os.Stat(tasksDir); os.IsNotExist(err) {
		return fmt.Errorf("missing tasks directory in %s", sv.scenarioPath)
	}

	// Check validation directory
	validationDir := filepath.Join(sv.scenarioPath, "validation")
	if _, err := os.Stat(validationDir); os.IsNotExist(err) {
		return fmt.Errorf("missing validation directory in %s", sv.scenarioPath)
	}

	// Validate task files
	taskFiles, err := os.ReadDir(tasksDir)
	if err != nil {
		return fmt.Errorf("failed to read tasks directory: %w", err)
	}

	taskPattern := regexp.MustCompile(`^(\d+)-task\.md$`)
	validationPattern := regexp.MustCompile(`^(\d+)-validation\.yaml$`)

	taskIDs := make(map[string]bool)
	for _, file := range taskFiles {
		if !file.IsDir() && taskPattern.MatchString(file.Name()) {
			matches := taskPattern.FindStringSubmatch(file.Name())
			taskIDs[matches[1]] = true
		}
	}

	// Check corresponding validation files
	validationFiles, err := os.ReadDir(validationDir)
	if err != nil {
		return fmt.Errorf("failed to read validation directory: %w", err)
	}

	for _, file := range validationFiles {
		if !file.IsDir() && validationPattern.MatchString(file.Name()) {
			matches := validationPattern.FindStringSubmatch(file.Name())
			taskID := matches[1]
			if !taskIDs[taskID] {
				return fmt.Errorf("validation file %s has no corresponding task file", file.Name())
			}
		}
	}

	// Check that all tasks have validation files (optional warning)
	for taskID := range taskIDs {
		validationFile := fmt.Sprintf("%s-validation.yaml", taskID)
		validationPath := filepath.Join(validationDir, validationFile)
		if _, err := os.Stat(validationPath); os.IsNotExist(err) {
			// This could be a warning instead of an error
			fmt.Printf("Warning: task %s has no validation file\n", taskID)
		}
	}

	return nil
}
