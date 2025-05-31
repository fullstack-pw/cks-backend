package scenarios

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	MetadataTemplate = `id: %s
title: "%s"
description: "%s"
version: "1.0.0"
difficulty: beginner
timeEstimate: "30m"
topics:
  - pod-security
requirements:
  k8sVersion: "1.33.0"
  resources:
    cpu: 2
    memory: 2Gi
`

	TaskTemplate = `# Task %d: %s

## Description

%s

## Background

Provide background information about the concepts involved in this task.

## Objectives

1. First objective
2. Second objective
3. Third objective

## Step-by-Step Guide

1. First step:

` + "```yaml" + `
# Example YAML
` + "```" + `

2. Second step:

` + "```bash" + `
# Example command
` + "```" + `

## Hints

<details>
<summary>Hint 1: First Hint</summary>
Helpful hint text here.
</details>

<details>
<summary>Hint 2: Second Hint</summary>
Another helpful hint.
</details>

## Validation Criteria

- First validation criterion
- Second validation criterion
`

	ValidationTemplate = `validation:
  - id: task-%s-check-1
    type: resource_exists
    resource:
      kind: Pod
      name: example-pod
      namespace: default
    errorMessage: "Pod 'example-pod' does not exist"

  - id: task-%s-check-2
    type: resource_property
    resource:
      kind: Pod
      name: example-pod
      namespace: default
    property: .spec.containers[0].image
    condition: equals
    value: "nginx:1.20"
    errorMessage: "Pod is not using the correct image"
`

	SetupTemplate = `steps:
  - id: setup-namespace
    type: command
    target: control-plane
    description: "Create test namespace"
    command: "kubectl create namespace test-namespace"
    timeout: 30s
    retryCount: 3
`
)

// ScenarioGenerator creates new scenario structures
type ScenarioGenerator struct {
	basePath string
}

func NewScenarioGenerator(basePath string) *ScenarioGenerator {
	return &ScenarioGenerator{
		basePath: basePath,
	}
}

func (sg *ScenarioGenerator) CreateScenario(id, title, description string) error {
	scenarioPath := filepath.Join(sg.basePath, id)

	// Create directory structure
	dirs := []string{
		scenarioPath,
		filepath.Join(scenarioPath, "tasks"),
		filepath.Join(scenarioPath, "validation"),
		filepath.Join(scenarioPath, "setup"),
		filepath.Join(scenarioPath, "resources"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Create metadata.yaml
	metadataContent := fmt.Sprintf(MetadataTemplate, id, title, description)
	metadataPath := filepath.Join(scenarioPath, "metadata.yaml")
	if err := os.WriteFile(metadataPath, []byte(metadataContent), 0644); err != nil {
		return fmt.Errorf("failed to create metadata.yaml: %w", err)
	}

	// Create first task
	taskContent := fmt.Sprintf(TaskTemplate, 1, "Your First Task", "Task description here")
	taskPath := filepath.Join(scenarioPath, "tasks", "01-task.md")
	if err := os.WriteFile(taskPath, []byte(taskContent), 0644); err != nil {
		return fmt.Errorf("failed to create task file: %w", err)
	}

	// Create corresponding validation
	validationContent := fmt.Sprintf(ValidationTemplate, "01", "01")
	validationPath := filepath.Join(scenarioPath, "validation", "01-validation.yaml")
	if err := os.WriteFile(validationPath, []byte(validationContent), 0644); err != nil {
		return fmt.Errorf("failed to create validation file: %w", err)
	}

	// Create setup template (optional)
	setupPath := filepath.Join(scenarioPath, "setup", "init.yaml")
	if err := os.WriteFile(setupPath, []byte(SetupTemplate), 0644); err != nil {
		return fmt.Errorf("failed to create setup file: %w", err)
	}

	return nil
}
