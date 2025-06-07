# Task 1: Verify Falco Installation and Custom Rules

## Description

In this task, you will verify that Falco has been installed on the worker node and examine the custom security rules that have been configured to detect suspicious activities.

## Background

Falco is a runtime security monitoring tool for Kubernetes that uses system calls to detect abnormal behavior in applications. It can detect:

- Unauthorized file access
- Network connections to unexpected destinations
- Process execution anomalies
- Privilege escalations
- Package management activities

Custom rules allow you to define specific security policies for your environment.

## Objectives

1. Verify Falco is running on the worker node
2. Examine the custom Falco rules configuration
3. Understand the rule structure and detection patterns
4. Check that Falco is actively monitoring system calls

## Step-by-Step Guide

1. **Connect to the worker node and verify Falco service:**

```bash
# Check Falco service status
sudo systemctl status falco

# Verify Falco is actively running
sudo systemctl is-active falco
```

2. **Examine the custom Falco rules:**

```bash
# View the custom rules file
sudo cat /etc/falco/rules.d/falco_custom.yaml

# List all loaded Falco rules
sudo falco --list | grep -E "(Detect passwd file modification|Package management process launched)"
```

3. **Check Falco logs to see if it's monitoring:**

```bash
# View recent Falco logs
sudo journalctl -u falco -f --since "5 minutes ago"
```

4. **Verify test deployments are running:**

```bash
# Check the suspicious pods are running
kubectl get pods -n falco-test

# Verify pods are scheduled on worker node
kubectl get pods -n falco-test -o wide
```

## Hints

<details>
<summary>Hint 1: Understanding Falco Rules</summary>
Falco rules consist of:
- `rule`: Name of the rule
- `desc`: Description of what the rule detects
- `condition`: Logic that triggers the rule
- `output`: Format of the alert message
- `priority`: Severity level (INFO, WARNING, ERROR, CRITICAL)
</details>

<details>
<summary>Hint 2: Troubleshooting Falco</summary>
If Falco isn't running:
```bash
sudo systemctl restart falco
sudo journalctl -u falco -n 50
```
</details>

## Validation Criteria

- Falco service is running on the worker node
- Custom rules file exists at `/etc/falco/rules.d/falco_custom.yaml`
- Both custom rules are loaded and active
- Test deployments are running in the `falco-test` namespace